#include "portal/portal_process.h"
#include "portal/portal_protocol.h"
#include "core/constants.h"
#include <QSslError>
#include <QHostAddress>
#include <QNetworkInterface>
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
    // 非常规退出路径（进程结束）兜底：先断开 reply 的已连接信号再 abort，
    // 避免 abort() 触发的 finished/sslErrors 在对象析构后派发（悬垂 this）。
    // NAM 析构会清理在飞 reply，此处无需手动 delete。
    if (m_activeReply) {
        m_activeReply->disconnect(this);
        m_activeReply->abort();
        m_activeReply = nullptr;
    }
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
        m_sessionTimer = new QTimer(this);
        m_sessionTimer->setSingleShot(true);
        m_sessionTimer->setInterval(sessionTimeoutMs());
        connect(m_sessionTimer, &QTimer::timeout,
                this, &PortalProcess::onSessionTimeout);
    }

    // 新会话：代数递增使旧会话在飞回复作废；停掉旧保活/会话超时（若有）
    ++m_generation;
    if (m_activeReply) {
        m_activeReply->disconnect(this);
        m_activeReply->abort();
        m_activeReply = nullptr;
    }
    m_keepaliveTimer->stop();
    m_sessionTimer->stop();
    m_keepaliveIntervalMs = PORTAL_KEEPALIVE_INTERVAL;   // 新会话复位保活周期
    m_wasOnline = false;
    m_lastUserIp.clear();

    setCurrentState(AuthState::SendingStart);
    emit stateChanged(AuthState::SendingStart,
                      QStringLiteral("正在查询 Portal 在线状态..."));

    // 会话整体超时：chkstatus+login 整条登录链路的兜底（30s），
    // 网络卡死时按暂时性失败进入既有自动重连排程，避免无限等待
    m_sessionTimer->start();

    m_keepaliveCheck = false;
    sendRequest(makeChkstatusUrl(), &PortalProcess::onChkstatusFinished);
}

void PortalProcess::stop()
{
    ++m_generation;
    if (m_activeReply) {
        m_activeReply->disconnect(this);
        m_activeReply->abort();
        m_activeReply = nullptr;
    }
    if (m_keepaliveTimer)
        m_keepaliveTimer->stop();
    if (m_sessionTimer)
        m_sessionTimer->stop();

    const bool wasOnline = m_wasOnline;
    m_wasOnline = false;
    setCurrentState(AuthState::Stopped);

    if (wasOnline) {
        // 注销尽力而为：结果只记日志，不改变状态机（logout 请求不携带会话
        // 代数属性，其迟到回复不被代数守卫拦截）
        emit logMessage(QStringLiteral("正在注销 Portal 会话..."), 0);
        sendRequest(makeLogoutUrl(), &PortalProcess::onLogoutFinished);
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

    // 在飞请求去重：并发（如保活检测尚未完成又触发下一轮）时先中止旧请求并
    // 断开其信号，避免旧 finished 延续以相同代数通过守卫、造成重复登录/重复处理。
    if (m_activeReply) {
        m_activeReply->disconnect(this);
        m_activeReply->abort();
        m_activeReply = nullptr;
    }

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

    // 网络错误：登录路径回退本机 IP 继续登录；保活路径按指数退避重排，避免
    // 服务器短暂不可达时每 60s 打一个无效请求
    if (reply->error() != QNetworkReply::NoError) {
        if (m_keepaliveCheck) {
            backoffKeepalive();
        } else {
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
        if (m_keepaliveCheck) {
            backoffKeepalive();
        } else {
            emit logMessage(QStringLiteral("无法解析在线状态响应，尝试直接登录..."), 1);
            m_lastUserIp = localIpFallback();
            beginLogin();
        }
        return;
    }

    if (resp.result == 1) {
        // 已在线：登录路径直接成功；保活路径复位周期并刷新缓存 IP
        m_lastUserIp = resp.v46ip;
        if (!m_keepaliveCheck) {
            finishSuccess(QStringLiteral("账号已在线"));
        } else {
            resetKeepalive();
        }
        return;
    }

    // 未在线：登录路径直接登录；保活路径为掉线 → 自动重新登录
    if (m_keepaliveCheck)
        emit logMessage(QStringLiteral("检测到 Portal 会话掉线，自动重新登录..."), 1);
    m_lastUserIp = resp.v46ip.isEmpty() ? localIpFallback() : resp.v46ip;
    beginLogin();
}

// 保活失败退避：当前周期翻倍（封顶 PORTAL_KEEPALIVE_MAX_INTERVAL）并重排下一轮
void PortalProcess::backoffKeepalive()
{
    m_keepaliveIntervalMs = qMin(m_keepaliveIntervalMs * 2, PORTAL_KEEPALIVE_MAX_INTERVAL);
    if (m_keepaliveTimer)
        m_keepaliveTimer->start(m_keepaliveIntervalMs);
}

// 保活成功复位：恢复正常周期
void PortalProcess::resetKeepalive()
{
    m_keepaliveIntervalMs = PORTAL_KEEPALIVE_INTERVAL;
    if (m_keepaliveTimer)
        m_keepaliveTimer->start(m_keepaliveIntervalMs);
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

    // 登录也有独立时限：重置会话超时（覆盖掉线重登的登录链）
    if (m_sessionTimer)
        m_sessionTimer->start();

    sendRequest(makeLoginUrl(), &PortalProcess::onLoginFinished);
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
    if (m_sessionTimer)
        m_sessionTimer->stop();   // 已成功：停止登录链路超时
    m_wasOnline = true;
    setCurrentState(AuthState::Authenticated);
    // 成功：复位保活周期并启动在线检测
    m_keepaliveIntervalMs = PORTAL_KEEPALIVE_INTERVAL;
    m_keepaliveTimer->start(m_keepaliveIntervalMs);
    emit stateChanged(AuthState::Authenticated, reason);
    emit portalSuccess();
}

void PortalProcess::finishFailure(const QString& msg, bool retryable)
{
    if (m_sessionTimer)
        m_sessionTimer->stop();   // 已失败：停止登录链路超时
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
    // 先按当前周期排下一轮（失败时由 backoffKeepalive 覆盖为退避间隔）
    if (m_keepaliveTimer)
        m_keepaliveTimer->start(m_keepaliveIntervalMs);
    sendRequest(makeChkstatusUrl(), &PortalProcess::onChkstatusFinished);
}

void PortalProcess::onSessionTimeout()
{
    // 登录链路整体超时（chkstatus/login 在 PORTAL_SESSION_TIMEOUT 内无结果）。
    // 按暂时性失败处理（retryable=true），交由上层既有自动重连排程。
    if (m_currentState == AuthState::Authenticated)
        return;   // 已在超时前成功
    finishFailure(QStringLiteral("认证超时（%1 秒无响应）")
                      .arg(PORTAL_SESSION_TIMEOUT / 1000),
                  /*retryable=*/true);
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
// 端点构造（默认实现：真实 eportal URL；测试子类覆写指向本地 mock）
// ============================================================================

QUrl PortalProcess::makeChkstatusUrl() const
{
    return PortalProtocol::buildChkstatusUrl(
        m_config.host, QRandomGenerator::global()->bounded(100000, 999999));
}

QUrl PortalProcess::makeLoginUrl() const
{
    return PortalProtocol::buildLoginUrl(
        m_config.host, m_config.username, m_config.password, m_lastUserIp,
        QRandomGenerator::global()->bounded(100000, 999999));
}

QUrl PortalProcess::makeLogoutUrl() const
{
    return PortalProtocol::buildLogoutUrl(
        m_config.host, QRandomGenerator::global()->bounded(100000, 999999));
}

int PortalProcess::sessionTimeoutMs() const
{
    return PORTAL_SESSION_TIMEOUT;
}

// ============================================================================
// 本机 IPv4 回退（chkstatus 不可用时取 wlan_user_ip 参数）
// ============================================================================

QString PortalProcess::localIpFallback() const
{
    // 非阻塞：直接枚举本机接口（不调用阻塞式主机名 DNS 解析，避免卡住工作线程）。
    // 无线 Portal 场景优先 Wi-Fi 接口，并排除常见虚拟网卡，避免 VPN/虚拟机
    // 适配器的 IP 被误当作 wlan_user_ip 导致登录失败。chkstatus 正常时 v46ip
    // 已是可靠来源，本函数仅在 chkstatus 不可用时兜底。
    QString best;
    int bestScore = -1;
    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
        const QNetworkInterface::InterfaceFlags flags = iface.flags();
        if (!(flags & QNetworkInterface::IsUp) || (flags & QNetworkInterface::IsLoopBack))
            continue;

        QString ipv4;
        bool hasNetmask = false;
        for (const QNetworkAddressEntry& entry : iface.addressEntries()) {
            if (entry.ip().protocol() != QAbstractSocket::IPv4Protocol
                || entry.ip().isLoopback())
                continue;
            if (ipv4.isEmpty())
                ipv4 = entry.ip().toString();
            if (!entry.netmask().isNull() && entry.netmask().toIPv4Address() != 0)
                hasNetmask = true;   // 已配置子网 = 实际活动的网络接口
        }
        if (ipv4.isEmpty())
            continue;

        const QString label = iface.name() + QLatin1Char(' ') + iface.humanReadableName();
        int score = 0;
        // 无线 Portal 场景：优先 Wi-Fi / WLAN 接口
        if (label.contains(QStringLiteral("Wi-Fi"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("WLAN"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("Wireless"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("802.11"), Qt::CaseInsensitive))
            score += 30;
        if (hasNetmask)
            score += 20;
        // 排除常见虚拟/隧道网卡
        if (label.contains(QStringLiteral("Virtual"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("VMware"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("VirtualBox"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("TAP"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("TUN"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("VPN"), Qt::CaseInsensitive))
            score -= 40;

        if (score > bestScore) {
            bestScore = score;
            best = ipv4;
        }
    }
    return best;
}
