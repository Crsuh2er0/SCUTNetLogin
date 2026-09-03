#include "portal/portal_process.h"
#include "portal/portal_protocol.h"
#include "core/constants.h"
#include <QSslError>
#include <QHostAddress>
#include <QNetworkInterface>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
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
    m_lastUserMac = localMacFallback();   // mac/unbind 注销解绑需要真实网卡 MAC
    m_logoutVerifyAttempt = 0;

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

// 脱敏 URL：user_password / user_account 打码，其余参数原样（调试日志使用）
static QString redactUrlForDebug(const QUrl& url)
{
    QStringList parts;
    const QList<QPair<QString, QString>> items =
        QUrlQuery(url).queryItems(QUrl::FullyEncoded);
    for (const auto& kv : items) {
        if (kv.first == QLatin1String("user_password")
            || kv.first == QLatin1String("user_account"))
            parts << kv.first + QLatin1String("=***");
        else
            parts << kv.first + QLatin1Char('=') + kv.second;
    }
    return QStringLiteral("%1://%2:%3%4?%5")
        .arg(url.scheme(), url.host())
        .arg(url.port())
        .arg(url.path(), parts.join(QLatin1Char('&')));
}

void PortalProcess::debugLog(const QString& detail)
{
    if (m_config.debug)
        emit logMessage(QStringLiteral("[调试] %1").arg(detail), 1);
}

void PortalProcess::sendRequest(const QUrl& url,
                                void (PortalProcess::*onFinished)(QNetworkReply*))
{
    debugLog(QStringLiteral("GET %1").arg(redactUrlForDebug(url)));
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, QLatin1String(PORTAL_USER_AGENT));
    // eportal 会校验 Referer 来源：登录/注销走 https://host:802（门户页本身即
    // https 来源），Referer 必须匹配 https；chkstatus 走 https 443，按请求
    // scheme 推导即可让各端点来源保持一致。
    req.setRawHeader("Referer",
                     QStringLiteral("%1://%2/").arg(url.scheme())
                                                .arg(m_config.host).toUtf8());
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

    // 802/443 为受信 TLS；仅当证书链异常时兜底忽略（防御性），正常不触发
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

    // 登录失败后的在线回查（ret_code=2 = 「终端IP已经在线」，见门户页 a40.js
    // 错误表）→ 服务器已明确账号在线，仅当 chkstatus 明确返回离线才判失败；
    // chkstatus 网络错误/无法解析时不能推翻"IP 已在线"的判定，按已在线收尾
    if (m_verifyAfterFailure) {
        m_verifyAfterFailure = false;
        const QString reason = m_pendingFailureReason;
        m_pendingFailureReason.clear();
        if (reply->error() == QNetworkReply::NoError) {
            const QByteArray raw = reply->readAll();
            debugLog(QStringLiteral("回查响应: %1").arg(QString::fromUtf8(raw.left(200)).trimmed()));
            const PortalProtocol::PortalResponse r =
                PortalProtocol::parseJsonp(raw, QStringLiteral("dr1002"));
            if (r.valid && r.result == 0) {
                finishFailure(reason, /*retryable=*/true);
                return;
            }
            if (r.valid && r.result == 1)
                m_lastUserIp = r.v46ip.isEmpty() ? m_lastUserIp : r.v46ip;
        }
        finishSuccess(QStringLiteral("账号已在线（服务器判定 IP 已在线）"));
        return;
    }

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

    const QByteArray raw = reply->readAll();
    debugLog(QStringLiteral("chkstatus 响应: %1").arg(QString::fromUtf8(raw.left(200)).trimmed()));
    const PortalProtocol::PortalResponse resp =
        PortalProtocol::parseJsonp(raw, QStringLiteral("dr1002"));

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

    // program_index/page_index 是 login 必带参数（浏览器实测）。首次登录前先从
    // loadConfig 动态获取（按区域下发），失败回退出厂默认值，保证 login 恒带全
    if (m_programIndex.isEmpty()) {
        sendRequest(makeLoadConfigUrl(), &PortalProcess::onLoadConfigFinished);
        return;
    }

    sendRequest(makeLoginUrl(), &PortalProcess::onLoginFinished);
}

void PortalProcess::onLoadConfigFinished(QNetworkReply* reply)
{
    // 旧会话迟到回复丢弃（新会话已在 beginLogin 重新发起 loadConfig）
    if (reply->request().attribute(QNetworkRequest::User, -1).toInt() != m_generation)
        return;

    // loadConfig 失败不阻塞登录：回退出厂默认值（与在线下发的值一致）
    bool gotConfig = false;
    if (reply->error() == QNetworkReply::NoError) {
        // JSONP 壳 dr1004({...}) 中 data.program_index / data.page_index
        const QByteArray fullBody = reply->readAll();
        debugLog(QStringLiteral("loadConfig 响应: %1")
                     .arg(QString::fromUtf8(fullBody.left(150)).trimmed()));
        QByteArray body = fullBody.trimmed();
        const QByteArray prefix = "dr1004(";
        if (body.startsWith(prefix)) {
            body = body.mid(prefix.size());
            while (!body.isEmpty() && (body.endsWith(')') || body.endsWith(';')))
                body.chop(1);
            const QJsonObject obj = QJsonDocument::fromJson(body).object();
            const QJsonObject data = obj.value("data").toObject();
            const QString pi = data.value("program_index").toString();
            const QString pa = data.value("page_index").toString();
            if (!pi.isEmpty() && !pa.isEmpty()) {
                m_programIndex = pi;
                m_pageIndex = pa;
                gotConfig = true;
            }
        }
    }
    if (!gotConfig) {
        m_programIndex = QString::fromLatin1(PORTAL_DEFAULT_PROGRAM_INDEX);
        m_pageIndex    = QString::fromLatin1(PORTAL_DEFAULT_PAGE_INDEX);
        emit logMessage(QStringLiteral("加载页面参数失败，使用默认值（%1/%2）")
                            .arg(m_programIndex, m_pageIndex), 1);
    } else {
        emit logMessage(QStringLiteral("已获取页面参数 program_index=%1 page_index=%2")
                            .arg(m_programIndex, m_pageIndex), 0);
    }

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

    const QByteArray raw = reply->readAll();
    debugLog(QStringLiteral("登录响应: %1").arg(QString::fromUtf8(raw.left(150)).trimmed()));
    const PortalProtocol::PortalResponse resp =
        PortalProtocol::parseJsonp(raw, QStringLiteral("dr1003"));

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

    // 一般性失败：优先展示真实错误码。SCUT 部署对任意登录失败 msg 恒为无含义
    // 的 "512"，ret_code 才是真实原因（如凭证错误），必须透传给用户/日志。
    QString reason;
    if (resp.retCode != 0) {
        if (resp.msg.isEmpty() || resp.msg == QStringLiteral("512"))
            reason = QStringLiteral("认证失败（服务器错误码 %1）").arg(resp.retCode);
        else
            reason = QStringLiteral("%1（服务器错误码 %2）").arg(resp.msg).arg(resp.retCode);
    } else {
        reason = resp.msg.isEmpty() ? QStringLiteral("认证失败（未知原因）")
                                    : resp.msg;
    }

    // SCUT 实测：登录被拒为 ret_code=2 时，账号往往已被 AC 无感知认证置为在线
    // （chkstatus 可查到 result=1）——按已在线处理，避免周期重试空转
    if (resp.retCode == 2) {
        verifyOnlineAfterFailure(reason);
        return;
    }
    finishFailure(reason, /*retryable=*/true);
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

// 登录失败后回查 chkstatus：账号可能已被 AC 无感知认证置为在线（登录被拒
// ret_code=2）。回查不打断会话超时；在线 → 成功，离线 → 按原失败收尾。
void PortalProcess::verifyOnlineAfterFailure(const QString& reason)
{
    m_verifyAfterFailure = true;
    m_pendingFailureReason = reason;
    emit logMessage(QStringLiteral("登录被拒（服务器错误码 2），回查在线状态确认会话..."), 1);
    sendRequest(makeChkstatusUrl(), &PortalProcess::onChkstatusFinished);
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
    // 若正处于失败回查中，先清标记，防止迟到回查继续走到收尾分支再发一次状态
    m_verifyAfterFailure = false;
    m_pendingFailureReason.clear();
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
    // 注销回执【不作为结论】：服务端 result=1 只说明请求被受理，不等于 AC 上的
    // 会话已拆除（802 的 portal logout 就是回 result=1 却不生效）。最终结论一律
    // 由随后的 chkstatus 回查给出；此处仅在协议/网络层异常时提示。
    if (reply->error() != QNetworkReply::NoError) {
        emit logMessage(QStringLiteral("Portal 注销请求失败（%1），正在回查在线状态...")
                            .arg(reply->errorString()), 1);
    } else {
        const QByteArray raw = reply->readAll();
        debugLog(QStringLiteral("注销响应: %1").arg(QString::fromUtf8(raw.left(150)).trimmed()));
        const PortalProtocol::PortalResponse resp =
            PortalProtocol::parseJsonp(raw, QStringLiteral("dr1006"));
        if (!(resp.valid && resp.result == 1)) {
            const QString detail = (resp.valid && !resp.msg.isEmpty())
                                       ? resp.msg
                                       : QStringLiteral("响应无法解析");
            emit logMessage(QStringLiteral("Portal 注销未被服务器确认（%1），正在回查在线状态...")
                                .arg(detail), 1);
        }
    }

    m_logoutVerifyAttempt = 0;
    emit logMessage(QStringLiteral("正在确认注销结果..."), 0);
    sendRequest(makeChkstatusUrl(), &PortalProcess::onLogoutVerifyFinished);
}

void PortalProcess::onLogoutVerifyFinished(QNetworkReply* reply)
{
    // 旧会话迟到回复丢弃：注销后用户可能立刻重新连接，此时本回查的结论已无意义
    // （且会误报"仍在线"）。代数由 sendRequest 随请求下发。
    if (reply->request().attribute(QNetworkRequest::User, -1).toInt() != m_generation)
        return;

    // 唯一事实来源：chkstatus 的真实在线状态。不改变状态机（stop 后不再触发
    // 重登/成功信号），只如实告知用户。
    if (reply->error() != QNetworkReply::NoError) {
        emit logMessage(QStringLiteral("无法确认注销结果（%1）；请打开 https://%2 查看在线状态")
                            .arg(reply->errorString(), m_config.host), 1);
        return;
    }

    const QByteArray raw = reply->readAll();
    debugLog(QStringLiteral("注销回查#%1: %2")
                 .arg(m_logoutVerifyAttempt + 1)
                 .arg(QString::fromUtf8(raw.left(150)).trimmed()));
    const PortalProtocol::PortalResponse resp =
        PortalProtocol::parseJsonp(raw, QStringLiteral("dr1002"));

    if (resp.valid && resp.result == 1) {
        // AC 拆除会话存在秒级延迟，解绑成功但首查仍在线是常见时序（而非真故障）。
        // 间隔 1s 重查，最多 5 次；期间用户可能手动重新连接（新 start 已复位
        // m_logoutVerifyAttempt=0，本回查因代数不符被丢弃）。
        if (m_logoutVerifyAttempt < 5) {
            ++m_logoutVerifyAttempt;
            QTimer::singleShot(1000, this, [this]() {
                sendRequest(makeChkstatusUrl(), &PortalProcess::onLogoutVerifyFinished);
            });
            return;
        }
        emit logMessage(QStringLiteral(
            "注销未生效：门户仍显示本机在线（%1）。请打开 https://%2 点击页面上的"
            "「注销(Logout)」，或到校园网自助服务查询在线终端")
                            .arg(resp.v46ip.isEmpty() ? QStringLiteral("本机")
                                                       : resp.v46ip,
                                 m_config.host), 2);
        return;
    }

    emit logMessage(QStringLiteral("Portal 会话已注销，本机已离线"), 0);
}

// ============================================================================
// 端点构造（默认实现：真实 eportal URL；测试子类覆写指向本地 mock）
// ============================================================================

QUrl PortalProcess::makeChkstatusUrl() const
{
    return PortalProtocol::buildChkstatusUrl(
        m_config.host, QRandomGenerator::global()->bounded(100000, 999999));
}

QUrl PortalProcess::makeLoadConfigUrl() const
{
    // 与浏览器端 page/loadConfig 同形：program_index 兜底为空，由服务器按区域下发
    QUrl url;
    url.setScheme(QStringLiteral("https"));
    url.setHost(m_config.host);
    url.setPort(PORTAL_LOGIN_PORT);
    url.setPath(QStringLiteral("/eportal/portal/page/loadConfig"));
    url.setQuery(QStringLiteral("callback=dr1004&program_index=")
                 + QStringLiteral("&wlan_vlan_id=&wlan_user_ip=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(m_lastUserIp))
                 + QStringLiteral("&wlan_user_ipv6=&wlan_user_ssid=&wlan_user_areaid=")
                 + QStringLiteral("&wlan_ac_ip=&wlan_ap_mac=&gw_id=&v=%1")
                     .arg(QRandomGenerator::global()->bounded(100000, 999999)));
    return url;
}

QUrl PortalProcess::makeLoginUrl() const
{
    return PortalProtocol::buildLoginUrl(
        m_config.host, m_config.username, m_config.password, m_lastUserIp,
        m_programIndex, m_pageIndex,
        QRandomGenerator::global()->bounded(100000, 999999));
}

QUrl PortalProcess::makeLogoutUrl() const
{
    // mac/unbind 需要 ip（32 位整数）与真实 MAC；未 start 过（无缓存）时即时回退
    const QString ip =
        m_lastUserIp.isEmpty() ? localIpFallback() : m_lastUserIp;
    const QString mac =
        m_lastUserMac.isEmpty() ? localMacFallback() : m_lastUserMac;
    return PortalProtocol::buildLogoutUrl(
        m_config.host, m_config.username, ip, mac,
        QRandomGenerator::global()->bounded(100000, 999999));
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

QString PortalProcess::localMacFallback() const
{
    // 与 localIpFallback 相同评分口径，保证取到「同一块」带校园网 IP 的无线网卡，
    // 其 MAC 即 AC 记录的终端真实 MAC（mac/unbind 注销解绑必须携带）。
    // 返回 12 位十六进制（buildLogoutUrl 内再转大写）；无匹配网卡返回空串。
    QString best;
    int bestScore = -1;
    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
        const QNetworkInterface::InterfaceFlags flags = iface.flags();
        if (!(flags & QNetworkInterface::IsUp) || (flags & QNetworkInterface::IsLoopBack))
            continue;

        const QString mac = iface.hardwareAddress().toLower().remove(QLatin1Char(':'));
        if (mac.isEmpty() || mac == QStringLiteral("000000000000"))
            continue;

        bool hasIp = false;
        for (const QNetworkAddressEntry& entry : iface.addressEntries()) {
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol
                && !entry.ip().isLoopback()) {
                hasIp = true;
                break;
            }
        }
        if (!hasIp)
            continue;

        const QString label = iface.name() + QLatin1Char(' ') + iface.humanReadableName();
        int score = 0;
        // 无线 Portal 场景：优先 Wi-Fi / WLAN 接口
        if (label.contains(QStringLiteral("Wi-Fi"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("WLAN"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("Wireless"), Qt::CaseInsensitive)
            || label.contains(QStringLiteral("802.11"), Qt::CaseInsensitive))
            score += 30;
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
            best = mac;
        }
    }
    return best;
}
