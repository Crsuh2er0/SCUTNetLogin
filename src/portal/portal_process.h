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
// 认证流程（DrCOM eportal，全部为 HTTPS GET + JSONP 响应）：
//   ① chkstatus：查询在线状态；已在线 → 直接成功；未在线 → 取 v46ip 作为本机 IP
//      （查询失败不阻塞流程，回退本机主机名解析取 IP 后直接登录，
//        若账号实际已在线，login 会返回"已经在线"类提示，同样按成功处理）
//   ② login：GET eportal 接口（user_account 带 ",0," 前缀，明文密码走 TLS）
//   ③ 成功后启动在线保活：周期 chkstatus 检测会话，掉线自动重新登录
//      （Portal 会话由服务器维护，无需客户端心跳；SCUT 策略为 15 分钟无流量下线）
//   ④ stop：GET logout 注销（尽力而为）
//
// 服务器使用自签名证书（801 端口），通过 sslErrors 信号忽略校验。
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
    void onLoginFinished(QNetworkReply* reply);
    void onLogoutFinished(QNetworkReply* reply);
    void onKeepaliveTimeout();
    void onSessionTimeout();   // 登录链路整体超时（chkstatus+login 兜底）

    // 发起 GET 并连接完成延续；sslErrors 一律忽略（服务器自签证书）
    void sendRequest(const QUrl& url, void (PortalProcess::*onFinished)(QNetworkReply*));
    void beginLogin();                              // chkstatus 完成后进入登录
    void finishSuccess(const QString& reason);      // 成功终点（启动保活）
    void finishFailure(const QString& msg, bool retryable);
    void backoffKeepalive();                        // 保活检测失败：周期翻倍退避
    void resetKeepalive();                          // 保活检测成功：复位正常周期
    QString localIpFallback() const;                // 本机 IPv4 回退（非阻塞枚举）
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
    bool      m_wasOnline = false;   // 曾认证成功（stop 时才发 logout）
    bool      m_sslWarned = false;   // 自签证书告警只记一次
    QNetworkReply* m_activeReply = nullptr;   // 当前在飞请求（stop 时 abort）
};

#endif // PORTAL_PROCESS_H
