#ifndef PORTAL_PROTOCOL_H
#define PORTAL_PROTOCOL_H

#include <QString>
#include <QByteArray>
#include <QUrl>

// ============================================================================
// 无线 Portal（DrCOM eportal）协议纯函数 — URL 构造 / JSONP 解析 / 响应分类
//
// 协议逆向自 SCUT 无线认证门户（s.scut.edu.cn，DrCOM eportal 部署）：
//   登录门户页 https://s.scut.edu.cn/ 的 JS 配置（a41.js / 内联配置）给出：
//     authloginpath='/eportal/?c=ACSetting&a=Login'  authloginport=801 （纯 HTTP）
//     authlogoutpath='/eportal/?c=ACSetting&a=Logout&ver=1.0'           （纯 HTTP 801）
//   在线状态则走 443：
//     chkstatus : GET https://<host>/drcom/chkstatus?callback=dr1002   在线状态 + 本机 IP
//   响应均为 JSONP：callback({"result":1,"msg":"...","v46ip":"..."})。
//
// 注意：不能把 login 放在 443 —— eportal 的 login/logout 只监听 801，且是
// 纯 HTTP（非 TLS）；实测 801 上用 TLS 握手会被服务器拒绝（SEC_E_INVALID_TOKEN）。
// 443 只服务 / 首页、/drcom/chkstatus 与 /drcom/logout。
//
// 本模块只做纯数据变换（无 QNetworkAccessManager / 线程依赖），
// 与 eapol_packet / drcom_packet 同定位，可被单元测试直接编译。
// ============================================================================

namespace PortalProtocol {

// JSONP 响应解析结果
struct PortalResponse {
    bool valid = false;    // JSONP 结构合法且内层 JSON 可解析
    int  result = 0;       // 1 = 成功 / 已在线；0 = 失败 / 未在线
    QString msg;           // 服务器消息（登录成功提示或失败原因）
    QString v46ip;         // chkstatus 返回的本机 IPv4（login 的 wlan_user_ip 参数）
};

// --- URL 构造（v 为缓存破坏随机数，仅用于避免中间缓存） ---

// 在线状态查询（HTTPS 443）
QUrl buildChkstatusUrl(const QString& host, int v);

// Portal 登录（HTTP 801，user_account 自动拼接 ",0," 前缀 = PC 设备类型标记）
// 路径：/eportal/?c=Portal&a=login（门户配置 authloginpath 为 ACSetting&a=Login，
// 但门户页 JS 实际会跳转到 c=Portal&a=login 接口，两者等价且后者为移动端/PC 通用）
QUrl buildLoginUrl(const QString& host, const QString& username,
                   const QString& password, const QString& userIp, int v);

// Portal 注销（HTTP 801，门户配置 authlogoutpath）
QUrl buildLogoutUrl(const QString& host, int v);

// --- 响应解析 / 分类 ---

// 解析 JSONP 响应体（形如 dr1003({...})），callback 为请求中携带的回调名
PortalResponse parseJsonp(const QByteArray& body, const QString& callback);

// login 响应 result==0 时：msg 为"已在线"类提示 — 账号实际已通过认证，视为登录成功
bool isAlreadyOnline(const QString& msg);

// login 响应 result==0 时：msg 为凭证/账户状态类错误 — 自动重试无法恢复，停止重试
bool isPermanentFailure(const QString& msg);

} // namespace PortalProtocol

#endif // PORTAL_PROTOCOL_H