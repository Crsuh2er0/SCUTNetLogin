#ifndef PORTAL_PROTOCOL_H
#define PORTAL_PROTOCOL_H

#include <QString>
#include <QByteArray>
#include <QUrl>

// ============================================================================
// 无线 Portal（DrCOM eportal）协议纯函数 — URL 构造 / JSONP 解析 / 响应分类
//
// 协议逆向自 SCUT 无线认证门户（s.scut.edu.cn，DrCOM eportal 部署）：
//   在线状态走 443：
//     chkstatus : GET https://<host>/drcom/chkstatus?callback=dr1002   在线状态 + 本机 IP
//   认证 API 走 HTTPS 802（loadConfig 下发 enable_https=1 + ep_https_port=802）：
//     loadConfig: https://<host>:802/eportal/portal/page/loadConfig   program_index/page_index
//     login     : https://<host>:802/eportal/portal/login
// 注销走 802 的 mac/unbind 接口（注销并解绑本机 MAC，唯一能真正下线且不被
// 自动恢复的方式）：
//     logout    : https://<host>:802/eportal/portal/mac/unbind
// 802 证书为受信链（无需忽略校验）；801 纯 HTTP 为旧部署形态，新门户 login
// 一律返回失败（实测 result=0/msg=512），浏览器始终走 802。
// 注销端点的选型（实测结论，勿改回）：
//   - 443 /drcom/logout            → "Logout Error(no webmode)"，不生效
//   - 802 /eportal/portal/logout   → 假报 "Radius注销成功！"（result=1），
//                                     AC 会话仍保留，账号随后被重新注册
//   - 802 /eportal/portal/mac/unbind → "解绑终端MAC成功！"（result=1），
//                                     会话拆除且白名单解除，chkstatus 归 0
// 详见 portal_protocol.cpp（依据门户页 a40.js 注销按钮 wc() → user.unbind_mac）。
// 响应均为 JSONP：callback({"result":1,"msg":"...","v46ip":"..."})。
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
    int  retCode = 0;      // 服务器返回的详细错误码（仅 login 有效，0 表示无）
    QString v46ip;         // chkstatus 返回的本机 IPv4（login 的 wlan_user_ip 参数）
};

// --- URL 构造（v 为缓存破坏随机数，仅用于避免中间缓存） ---

// 在线状态查询（HTTPS 443）
QUrl buildChkstatusUrl(const QString& host, int v);

// Portal 登录（HTTPS 802，参数形态实测自浏览器成功登录请求）：
//   - user_account 为纯学号（无 ",0," 设备前缀、无 "@wifi" 后缀）
//   - wlan_user_mac 恒为 000000000000（不携带终端真实 MAC）
//   - wlan_ac_ip 为区域 AC 地址（PORTAL_WLAN_AC_IP）
//   - 必带 mac_type=0 与 loadConfig 下发的 program_index/page_index
QUrl buildLoginUrl(const QString& host, const QString& username,
                   const QString& password, const QString& userIp,
                   const QString& programIndex, const QString& pageIndex, int v);

// Portal 注销（HTTPS 802，/eportal/portal/mac/unbind —— 注销并解绑本机 MAC）。
// 实测：443 /drcom/logout 报 "Logout Error(no webmode)"；802 /eportal/portal/logout
// 仅 Radius 注销（AC 会话仍在，账号被重新注册）；只有 mac/unbind 能真正下线且
// 不被自动恢复。username 带 @wifi 完整后缀；userMac 为本机真实 MAC（大写）；
// userIp 转为 32 位整数（与门户页 util.ipToParseInt 一致）。
QUrl buildLogoutUrl(const QString& host, const QString& username,
                    const QString& userIp, const QString& userMac, int v);

// --- 响应解析 / 分类 ---

// 解析 JSONP 响应体（形如 dr1003({...})），callback 为请求中携带的回调名
PortalResponse parseJsonp(const QByteArray& body, const QString& callback);

// login 响应 result==0 时：msg 为"已在线"类提示 — 账号实际已通过认证，视为登录成功
bool isAlreadyOnline(const QString& msg);

// login 响应 result==0 时：msg 为凭证/账户状态类错误 — 自动重试无法恢复，停止重试
bool isPermanentFailure(const QString& msg);

} // namespace PortalProtocol

#endif // PORTAL_PROTOCOL_H