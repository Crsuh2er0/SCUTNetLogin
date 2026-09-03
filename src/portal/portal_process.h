#ifndef PORTAL_PROCESS_H
#define PORTAL_PROCESS_H

#include <QObject>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include "core/protocol.h"
#include "core/log_level.h"

// ============================================================================
// 无线 Portal 认证处理器 — 在独立线程中运行（线程生命周期由 SessionManager 管理）
//
// 认证流程（DrCOM eportal，全部为 GET + JSONP 响应）：
//   ① chkstatus：查询在线状态（HTTPS 443）；已在线 → 直接成功；未在线 → 取
//      v46ip 作为本机 IP（查询失败不阻塞流程，回退本机主机名解析取 IP 后登录）
//   ② loadConfig：获取 login 必带的 program_index/page_index（HTTPS 802，
//      失败回退出厂默认值，不阻塞登录）
//   ③ login：GET eportal 登录（HTTPS 802；user_account 纯学号、wlan_user_mac
//      固定 000000000000、wlan_ac_ip 区域 AC、mac_type=0 + program_index/page_index，
//      形态实测自浏览器成功登录）
//   ④ 成功后启动在线保活：周期 chkstatus 检测会话，掉线自动重新登录
//      （Portal 会话由服务器维护，无需客户端心跳；SCUT 策略为 15 分钟无流量下线）
//   ⑤ stop：GET /drcom/logout 注销（443 内核接口，与门户页「注销」按钮一致），
//      随后回查一次 chkstatus 如实上报结果
//
// 802 为受信 TLS（证书链有效），无需忽略校验。
//
// 注销结果【只以 chkstatus 回查为准】：/eportal/portal/logout（802）会返回
// result=1 "Radius注销成功！" 却并不拆除 AC 会话，只信服务端回执就会谎报
// "已注销"。详见 portal_protocol.cpp 文件头。
//
// start() 幂等开启新会话（代数递增，旧会话在飞回复作废），自动重连路径
// 直接重复调用 start() 即可，无 stop→start 顺序契约（对比 EapProcess::restart）。
// ============================================================================

class PortalProcess : public QObject {
    Q_OBJECT

public:
    explicit PortalProcess(QObject* parent = nullptr);
    ~PortalProcess() override;

    // 认证配置（同 EapProcess 模式：start() 排队事件处理前由调用线程同步直调，
    // 保证工作线程处理 start 槽时已持有最新配置）
    void setConfig(const AuthConfig& config);

protected:
    // ---- 端点构造 seam（可测性）：默认按 portal_protocol 构造真实 eportal URL。
    //      测试子类可覆写指向本地 mock 服务器、缩短超时，从而在不接触真实网络的
    //      前提下驱动整个异步状态机（见 tests/tst_packets.cpp 的 Portal 集成用例）----
    virtual QUrl makeChkstatusUrl() const;
    virtual QUrl makeLoadConfigUrl() const;
    virtual QUrl makeLoginUrl() const;
    virtual QUrl makeLogoutUrl() const;
    virtual int  sessionTimeoutMs() const;   // 登录链路超时（测试可缩短）

public slots:
    void start();    // 查询在线状态 → 已在线直接成功 / 未在线登录
    void stop();     // 注销并停止保活，发射 Stopped

signals:
    // retryable=false 表示永久性错误（凭证/账户状态），上层不应自动重试
    void stateChanged(AuthState state, const QString& message, bool retryable = true);
    void logMessage(const QString& message, int level);
    void portalSuccess();   // 已在线 / 登录成功（对比 EapProcess::eapSuccess）

private:
    // 各 HTTP 请求完成处理（reply 由 sendRequest 的 finished 延续传入）
    void onChkstatusFinished(QNetworkReply* reply);
    void onLoadConfigFinished(QNetworkReply* reply);
    void onLoginFinished(QNetworkReply* reply);
    void onLogoutFinished(QNetworkReply* reply);
    void onLogoutVerifyFinished(QNetworkReply* reply);   // 注销后回查真实在线状态
    void onKeepaliveTimeout();
    void onSessionTimeout();   // 登录链路整体超时（chkstatus+login 兜底）

    // 发起 GET 并连接完成延续；sslErrors 一律忽略（服务器自签证书）
    void sendRequest(const QUrl& url, void (PortalProcess::*onFinished)(QNetworkReply*));
    // 调试日志（m_config.debug 开启时输出，密码/账号脱敏）
    void debugLog(const QString& detail);
    void beginLogin();                              // chkstatus 完成后进入登录
    void finishSuccess(const QString& reason);      // 成功终点（启动保活）
    void finishFailure(const QString& msg, bool retryable);
    // 登录返回"已在在线/重复登录"类失败（SCUT 实测 ret_code=2，伴随 AC 无感知
    // 认证使账号先于登录响应上线）→ 回查 chkstatus 确认实际在线状态，
    // 已在线则按成功处理，避免周期重试空转
    void verifyOnlineAfterFailure(const QString& reason);
    void backoffKeepalive();                        // 保活检测失败：周期翻倍退避
    void resetKeepalive();                          // 保活检测成功：复位正常周期
    QString localIpFallback() const;                // 本机 IPv4 回退（非阻塞枚举）
    // 本机无线网卡真实 MAC（mac/unbind 注销解绑必备，登录不使用）。
    // 与 localIpFallback 同一评分口径选出同一块网卡，返回 12 位十六进制
    QString localMacFallback() const;
    void setCurrentState(AuthState state) { m_currentState = state; }

    AuthConfig m_config;
    QNetworkAccessManager* m_nam = nullptr;   // 惰性创建（首次 start 时，见构造函数注释）
    QTimer* m_keepaliveTimer = nullptr;       // 同上
    QTimer* m_sessionTimer   = nullptr;       // 登录链路整体超时（同上）

    // start/stop 代数：每次会话切换递增，所有异步延续（网络回复）捕获发起时
    // 代数，回调时发现代数不匹配即丢弃——防止旧会话的迟到回复污染新会话状态机
    int m_generation = 0;

    // 本次 chkstatus 的用途：false = 登录前置查询 / true = 保活周期检测
    // （两者对 result 的处理不同：已在线时登录路径视为成功，保活路径无事）
    bool m_keepaliveCheck = false;
    // 保活当前周期 (ms)：检测失败指数退避（60s→…→10min），成功复位到正常周期
    int m_keepaliveIntervalMs = 0;

    AuthState m_currentState = AuthState::Idle;
    QString   m_lastUserIp;          // chkstatus 获取的本机 IP（login 参数）
    QString   m_lastUserMac;         // 本机无线网卡真实 MAC（mac/unbind 注销用）
    QString   m_programIndex;        // loadConfig 下发（login 必带）
    QString   m_pageIndex;           // loadConfig 下发（login 必带）
    bool      m_wasOnline = false;   // 曾认证成功（stop 时才发 logout）
    bool      m_sslWarned = false;   // 自签证书告警只记一次
    // 登录失败后回查在线状态：true = 当前 chkstatus 为该回查（勿再触发重登）
    bool      m_verifyAfterFailure = false;
    QString   m_pendingFailureReason;
    // 注销结果回查的重试计数（AC 拆除会话存在秒级延迟，首查仍在线时再查数次）
    int       m_logoutVerifyAttempt = 0;
    QNetworkReply* m_activeReply = nullptr;   // 当前在飞请求（stop 时 abort）
};

#endif // PORTAL_PROCESS_H
