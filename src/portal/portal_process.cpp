#include "portal/portal_process.h"
#include "portal/portal_protocol.h"
#include "core/constants.h"
#include <QSslError>
#include <QHostAddress>
#include <QHostInfo>
#include <QRandomGenerator>

// ============================================================================
// 构造 / 析构
// ============================================================================

PortalProcess::PortalProcess(QObject* parent)
    : QObject(parent)
{
    // QNetworkAccessManager / QTimer 惰性创建（首次 start() 时，此时本对象已在
    // Portal 工作线程）：网络栈与定时器的 thread affinity 必须与使用线程一致
}

PortalProcess::~PortalProcess()
{
    // 非常规退出路径（进程结束）兜底：中止在飞请求，避免 NAM 析构时回调悬空
    if (m_activeReply)
        m_activeReply->abort();
}

void PortalProcess::setConfig(const AuthConfig& config)
{
    // 与 EapProcess 相同的调用契约：start() 的排队事件处理前由调用线程同步
    // 直调（QueuedConnection 提供 happens-before），工作线程处理 start 槽时
    // 必然已持有最新配置；本类无共享临界区（纯异步事件驱动），无需加锁
    m_config = config;
}

// ============================================================================
// 会话控制
// ============================================================================

void PortalProcess::start()
{
    // 惰性创建（见构造函数注释）
    if (!m_nam) {
        m_nam = new QNetworkAccessManager(this);
        m_keepaliveTimer = new QTimer(this);
        m_keepaliveTimer->setInterval(PORTAL_KEEPALIVE_INTERVAL);
        connect(m_keepaliveTimer, &QTimer::timeout,
                this, &PortalProcess::onKeepaliveTimeout);
    }

    // 新会话：代数递增使旧会话在飞回复作废；停掉旧保活（若有）
    ++m_generation;
    if (m_activeReply) {
        m_activeReply->abort();   // finished 延续因代数不匹配被丢弃
        m_activeReply = nullptr;
    }
    m_keepaliveTimer->stop();
    m_wasOnline = false;
    m_lastUserIp.clear();

    setCurrentState(AuthState::SendingStart);
    emit stateChanged(AuthState::SendingStart,
                      QStringLiteral("正在查询 Portal 在线状态..."));

    m_keepaliveCheck = false;
    sendRequest(PortalProtocol::buildChkstatusUrl(
                    m_config.host, QRandomGenerator::global()->bounded(100000, 999999)),
                &PortalProcess::onChkstatusFinished);
}

void PortalProcess::stop()
{
    ++m_generation;
    if (m_activeReply) {
        m_activeReply->abort();
        m_activeReply = nullptr;
    }
    if (m_keepaliveTimer)
        m_keepaliveTimer->stop();

    const bool wasOnline = m_wasOnline;
    m_wasOnline = false;
    setCurrentState(AuthState::Stopped);

    if (wasOnline) {
        // 注销尽力而为：结果只记日志，不改变状态机（logout 请求不携带会话
        // 代数属性，其迟到回复不被代数守卫拦截）
        emit logMessage(QStringLiteral("正在注销 Portal 会话..."), 0);
        sendRequest(PortalProtocol::buildLogoutUrl(
                        m_config.host, QRandomGenerator::global()->bounded(100000, 999999)),
                    &PortalProcess::onLogoutFinished);
    }

    emit stateChanged(AuthState::Stopped, QString());
}

// ============================================================================
// 请求发送（GET + 浏览器伪装头 + 自签证书忽略）
// ============================================================================

void PortalProcess::sendRequest(const QUrl& url,
                                void (PortalProcess::*onFinished)(QNetworkReply*))
{
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, QLatin1String(PORTAL_USER_AGENT));
    req.setRawHeader("Referer",
                     QStringLiteral("https://%1/").arg(m_config.host).toUtf8());
    req.setTransferTimeout(PORTAL_REQUEST_TIMEOUT);
    // 会话代数随请求下发（logout 不设置，默认 -1，回调不做代数拦截）
    req.setAttribute(QNetworkRequest::User, m_generation);

    QNetworkReply* reply = m_nam->get(req);
    m_activeReply = reply;

    // 服务器使用自签名/非常规证书（尤其 :801 eportal 端口），证书错误一律忽略
    connect(reply, &QNetworkReply::sslErrors, this,
            [this, reply](const QList<QSslError>& errors) {
        if (!m_sslWarned && !errors.isEmpty()) {
            m_sslWarned = true;
            emit logMessage(QStringLiteral("Portal 服务器证书异常（%1），已忽略校验")
                                .arg(errors.first().errorString()), 1);
        }
        reply->ignoreSslErrors();
    });

    // finished 延续：统一回收 m_activeReply / 延迟销毁，再分发到具体处理函数
    connect(reply, &QNetworkReply::finished, this, [this, onFinished, reply]() {
        if (reply == m_activeReply)
            m_activeReply = nullptr;
        reply->deleteLater();
        (this->*onFinished)(reply);
    });
}

// ============================================================================
// ① chkstatus：在线状态查询
// ============================================================================

void PortalProcess::onChkstatusFinished(QNetworkReply* reply)
{
    // 旧会话迟到回复（stop/新 start 已切换代数）→ 丢弃
    if (reply->request().attribute(QNetworkRequest::User, -1).toInt() != m_generation)
        return;

    // 网络错误：登录路径回退本机 IP 继续登录；保活路径静默忽略（下次再查）
    if (reply->error() != QNetworkReply::NoError) {
        if (!m_keepaliveCheck) {
            emit logMessage(QStringLiteral("在线状态查询失败（%1），尝试直接登录...")
                                .arg(reply->errorString()), 1);
            m_lastUserIp = localIpFallback();
            beginLogin();
        }
        return;
    }

    const PortalProtocol::PortalResponse resp =
        PortalProtocol::parseJsonp(reply->readAll(), QStringLiteral("dr1002"));

    if (!resp.valid) {
        if (!m_keepaliveCheck) {
            emit logMessage(QStringLiteral("无法解析在线状态响应，尝试直接登录..."), 1);
            m_lastUserIp = localIpFallback();
            beginLogin();
        }
        return;
    }

    if (resp.result == 1) {
        // 已在线：登录路径直接成功；保活路径无事（顺带刷新缓存 IP）
        m_lastUserIp = resp.v46ip;
        if (!m_keepaliveCheck)
            finishSuccess(QStringLiteral("账号已在线"));
        return;
    }

    // 未在线：登录路径直接登录；保活路径为掉线 → 自动重新登录
    if (m_keepaliveCheck)
        emit logMessage(QStringLiteral("检测到 Portal 会话掉线，自动重新登录..."), 1);
    m_lastUserIp = resp.v46ip.isEmpty() ? localIpFallback() : resp.v46ip;
    beginLogin();
}

// ============================================================================
// ② login：Portal 登录
// ============================================================================

void PortalProcess::beginLogin()
{
    if (m_lastUserIp.isEmpty())
        m_lastUserIp = localIpFallback();

    setCurrentState(AuthState::SendingIdentity);
    emit stateChanged(AuthState::SendingIdentity,
                      QStringLiteral("正在登录 Portal（%1）...").arg(m_lastUserIp));

    sendRequest(PortalProtocol::buildLoginUrl(
                    m_config.host, m_config.username, m_config.password, m_lastUserIp,
                    QRandomGenerator::global()->bounded(100000, 999999)),
                &PortalProcess::onLoginFinished);
}

void PortalProcess::onLoginFinished(QNetworkReply* reply)
{
    if (reply->request().attribute(QNetworkRequest::User, -1).toInt() != m_generation)
        return;

    if (reply->error() != QNetworkReply::NoError) {
        finishFailure(QStringLiteral("Portal 认证请求失败: %1").arg(reply->errorString()),
                      /*retryable=*/true);
        return;
    }

    const PortalProtocol::PortalResponse resp =
        PortalProtocol::parseJsonp(reply->readAll(), QStringLiteral("dr1003"));

    if (!resp.valid) {
        finishFailure(QStringLiteral("无法解析认证服务器响应"), /*retryable=*/true);
        return;
    }

    if (resp.result == 1) {
        finishSuccess(resp.msg.isEmpty() ? QStringLiteral("Portal 认证成功")
                                         : resp.msg);
        return;
    }

    // result == 0 的三类分支：已在线（掉线重登竞态）/ 永久性错误 / 暂时性错误
    if (PortalProtocol::isAlreadyOnline(resp.msg)) {
        finishSuccess(QStringLiteral("账号已在线"));
        return;
    }
    if (PortalProtocol::isPermanentFailure(resp.msg)) {
        finishFailure(resp.msg, /*retryable=*/false);
        return;
    }
    finishFailure(resp.msg.isEmpty() ? QStringLiteral("认证失败（未知原因）")
                                     : resp.msg,
                  /*retryable=*/true);
}

// ============================================================================
// 终点：成功 / 失败
// ============================================================================

void PortalProcess::finishSuccess(const QString& reason)
{
    m_wasOnline = true;
    setCurrentState(AuthState::Authenticated);
    m_keepaliveTimer->start();
    emit stateChanged(AuthState::Authenticated, reason);
    emit portalSuccess();
}

void PortalProcess::finishFailure(const QString& msg, bool retryable)
{
    m_keepaliveTimer->stop();
    m_wasOnline = false;
    setCurrentState(AuthState::Failed);
    emit stateChanged(AuthState::Failed,
                      retryable ? QStringLiteral("Portal 认证失败: %1").arg(msg) : msg,
                      retryable);
}

// ============================================================================
// ③ 在线保活：周期 chkstatus，掉线自动重登
// ============================================================================

void PortalProcess::onKeepaliveTimeout()
{
    m_keepaliveCheck = true;
    sendRequest(PortalProtocol::buildChkstatusUrl(
                    m_config.host, QRandomGenerator::global()->bounded(100000, 999999)),
                &PortalProcess::onChkstatusFinished);
}

// ============================================================================
// ④ logout 结果（尽力而为，仅记日志）
// ============================================================================

void PortalProcess::onLogoutFinished(QNetworkReply* reply)
{
    if (reply->error() != QNetworkReply::NoError) {
        emit logMessage(QStringLiteral("Portal 注销请求失败（已忽略）: %1")
                            .arg(reply->errorString()), 1);
        return;
    }

    const PortalProtocol::PortalResponse resp =
        PortalProtocol::parseJsonp(reply->readAll(), QStringLiteral("dr1006"));
    const bool ok = resp.valid && resp.result == 1;
    emit logMessage(ok ? QStringLiteral("Portal 会话已注销")
                       : QStringLiteral("Portal 注销响应异常（已忽略）"),
                    ok ? 0 : 1);
}

// ============================================================================
// 本机 IPv4 回退（chkstatus 不可用时取 wlan_user_ip 参数）
// ============================================================================

QString PortalProcess::localIpFallback() const
{
    // 与参考实现（socket.gethostbyname(hostname)）等价：解析本机主机名取
    // 第一个非回环 IPv4。认证前校园网 DNS 若未劫持此解析，通常走本地解析成功
    const QHostInfo info = QHostInfo::fromName(QHostInfo::localHostName());
    for (const QHostAddress& addr : info.addresses()) {
        if (addr.protocol() == QAbstractSocket::IPv4Protocol && !addr.isLoopback())
            return addr.toString();
    }
    return QString();
}
