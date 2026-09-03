#include "portal/portal_protocol.h"
#include "core/constants.h"
#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>

namespace PortalProtocol {

// ---------------------------------------------------------------------------
// URL 构造
//
// 端口/scheme（实测自 s.scut.edu.cn + 浏览器成功登录抓包）：
//   - chkstatus : HTTPS 443  /drcom/chkstatus
//   - loadConfig: HTTPS 802  /eportal/portal/page/loadConfig（获取 program_index
//                 /page_index；enable_https=1 + ep_https_port=802）
//   - login     : HTTPS 802  /eportal/portal/login
//   - logout    : HTTPS 802  /eportal/portal/mac/unbind（注销并解绑本机 MAC）
// 802 为受信 TLS（证书链有效，无需忽略校验）；801 纯 HTTP 为旧部署形态，新门户
// 下 login 一律返回失败（实测 result=0/msg=512），浏览器始终走 802。
//
// 【注销必须用 802 的 mac/unbind，前两个候选均已实测否定】
// 门户页「注销(Logout)」按钮（a40.js wc()）：un_bind_mac=1 且 register_mode∈{1,4}
// → user.unbind_mac("","",1) → url = page.portal_api + 'mac/unbind'（unbind_type=1，
// 注销并解绑当前终端 MAC）。实测三种注销行为：
//   - 443  /drcom/logout          → "Logout Error(no webmode)"，不生效
//   - 802  /eportal/portal/logout → 返回 result=1 "Radius注销成功！"，但 AC 会话
//                                   未拆除，chkstatus 随后仍显示在线（假成功）
//   - 802  /eportal/portal/mac/unbind → "解绑终端MAC成功！"，chkstatus 归 0 且
//                                   稳定离线、不再被自动重新注册（唯一正确路径）
// 参数：user_account 带 @wifi 完整后缀（isp_unbind_suffix=0 保留后缀）；
// wlan_user_mac 为本机真实 MAC 大写；wlan_user_ip 为 32 位整数（0x0AC3AD85
// 型，等价门户页 util.ipToParseInt）；unbind_type=1。
// query 中非安全字符一律 QUrl::toPercentEncoding 编码（与浏览器 encodeURIComponent
// 一致）；次序按门户页抓包原样保留。
// ---------------------------------------------------------------------------

QUrl buildChkstatusUrl(const QString& host, int v)
{
    QUrl url;
    url.setScheme(QStringLiteral("https"));
    url.setHost(host);
    url.setPath(QStringLiteral("/drcom/chkstatus"));
    url.setQuery(QStringLiteral("callback=dr1002&v=%1").arg(v));
    return url;
}

QUrl buildLoginUrl(const QString& host, const QString& username,
                   const QString& password, const QString& userIp,
                   const QString& programIndex, const QString& pageIndex, int v)
{
    QUrl url;
    url.setScheme(QStringLiteral("https"));   // 802 为受信 TLS（见注释）
    url.setHost(host);
    url.setPort(PORTAL_LOGIN_PORT);
    url.setPath(QStringLiteral("/eportal/portal/login"));
    url.setQuery(QStringLiteral("callback=dr1003&login_method=1")
                 + QStringLiteral("&user_account=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(username))
                 + QStringLiteral("&user_password=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(password))
                 + QStringLiteral("&wlan_user_ip=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(userIp))
                 + QStringLiteral("&wlan_user_ipv6=&wlan_user_mac=")
                 + QLatin1String(PORTAL_WLAN_USER_MAC)
                 + QStringLiteral("&wlan_ac_ip=")
                 + QLatin1String(PORTAL_WLAN_AC_IP)
                 + QStringLiteral("&wlan_ac_name=&jsVersion=")
                 + QLatin1String(PORTAL_JS_VERSION)
                 + QStringLiteral("&terminal_type=1&lang=zh-cn&mac_type=0")
                 + QStringLiteral("&program_index=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(programIndex))
                 + QStringLiteral("&page_index=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(pageIndex))
                 + QStringLiteral("&v=%1&lang=zh").arg(v));
    return url;
}

QUrl buildLogoutUrl(const QString& host, const QString& username,
                    const QString& userIp, const QString& userMac, int v)
{
    // 注销（解绑 MAC）账号需带 @wifi 完整后缀（登录用纯学号，二者不同）
    const QString account = username.endsWith(QLatin1String(PORTAL_ACCOUNT_SUFFIX))
                                ? username
                                : username + QLatin1String(PORTAL_ACCOUNT_SUFFIX);

    // wlan_user_ip：点分 → 32 位大端整数（与门户页 util.ipToParseInt 一致）
    QString ipInt = QStringLiteral("0");
    {
        QHostAddress addr(userIp);
        if (addr.protocol() == QAbstractSocket::IPv4Protocol)
            ipInt = QString::number(addr.toIPv4Address());
    }

    QUrl url;
    url.setScheme(QStringLiteral("https"));   // 802 为受信 TLS（见注释）
    url.setHost(host);
    url.setPort(PORTAL_LOGIN_PORT);
    url.setPath(QStringLiteral("/eportal/portal/mac/unbind"));
    url.setQuery(QStringLiteral("callback=dr1006&user_account=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(account))
                 + QStringLiteral("&wlan_user_mac=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(userMac.toUpper()))
                 + QStringLiteral("&wlan_user_ip=")
                 + ipInt
                 + QStringLiteral("&unbind_type=1&jsVersion=")
                 + QLatin1String(PORTAL_JS_VERSION)
                 + QStringLiteral("&lang=zh&v=%1").arg(v));
    return url;
}

// ---------------------------------------------------------------------------
// JSONP 解析：callback({JSON}) → 剥壳后 JSON 解析
// ---------------------------------------------------------------------------

PortalResponse parseJsonp(const QByteArray& body, const QString& callback)
{
    PortalResponse r;

    // 剥 JSONP 壳：必须以 "callback(" 开头（允许尾随 ")" / ";" / 空白）
    const QByteArray prefix = callback.toUtf8() + '(';
    QByteArray json = body.trimmed();
    if (!json.startsWith(prefix))
        return r;
    json = json.mid(prefix.size());
    while (!json.isEmpty() && (json.endsWith(';') || json.endsWith(')')
                                || json.endsWith('\n') || json.endsWith('\r')
                                || json.endsWith(' ') || json.endsWith('\t')))
        json.chop(1);
    if (json.isEmpty() || !json.startsWith('{'))
        return r;

    QJsonDocument doc = QJsonDocument::fromJson(json);
    if (!doc.isObject()) {
        // 门户响应头声明 charset=gbk，字段值可能含非 UTF-8 字节（如 chkstatus 的
        // NID），Qt 的 fromJson 严格按 UTF-8 校验会整体解析失败。按 Latin-1 重新
        // 解释后再转 UTF-8：ASCII 结构（键名/引号/括号）逐字节不变，仅受影响
        // 字段的值字节被重映射，result/ret_code/v46ip 等 ASCII 字段不受影响。
        doc = QJsonDocument::fromJson(QString::fromLatin1(json).toUtf8());
    }
    if (!doc.isObject())
        return r;

    const QJsonObject obj = doc.object();
    // result 兼容数字与字符串两种部署形态（"result":1 / "result":"1"）
    const QJsonValue resultVal = obj.value(QStringLiteral("result"));
    r.result = resultVal.isString() ? resultVal.toString().toInt()
                                    : static_cast<int>(resultVal.toDouble());
    r.msg   = obj.value(QStringLiteral("msg")).toString();
    // 详细错误码（仅 login 失败响应携带）：SCUT 部署对任意登录失败 msg 恒为
    // 无含义的 "512"，真实原因在 ret_code —— 必须保留并上抛，否则无法区分
    // 凭证错误与暂时性错误
    const QJsonValue retVal = obj.value(QStringLiteral("ret_code"));
    r.retCode = retVal.isString() ? retVal.toString().toInt()
                                  : static_cast<int>(retVal.toDouble());
    r.v46ip = obj.value(QStringLiteral("v46ip")).toString();
    r.valid = true;
    return r;
}

// ---------------------------------------------------------------------------
// login 失败消息分类
// ---------------------------------------------------------------------------

bool isAlreadyOnline(const QString& msg)
{
    // DrCOM eportal 对重复登录返回 result=0 + "…已经在线…" 类提示，
    // 账号实际已通过认证（常见于掉线重登竞态），按成功处理。
    // 例外："已在其他设备/终端在线"为设备数超限冲突，本机并未通过认证，
    // 不能视为成功（否则状态误报已连接且保活循环空转）
    if (msg.contains(QStringLiteral("其他设备")) || msg.contains(QStringLiteral("其他终端")))
        return false;
    return msg.contains(QStringLiteral("已经在线"))
        || msg.contains(QStringLiteral("已在线"));
}

bool isPermanentFailure(const QString& msg)
{
    // 凭证 / 账户状态类关键字：重试无法自愈，应停止自动重连（与有线侧
    // NotificationParser 的 permanent 语义对齐）。
    // 同时覆盖中英文两种部署形态，避免英文提示（如 "incorrect password"）
    // 被误判为可重试而无限重试。
    static const char* kPermanentKeywords[] = {
        // 中文
        "密码",     // 密码错误
        "账号不存在",
        "用户名",   // 用户名错误 / 用户名不存在
        "停用",
        "过期",
        "欠费",
        "余额",
        "流量",     // 流量已用尽
        "时长",     // 上网时长已用尽
        // 英文（精确短语，避免误伤 "timeout" 等暂时性错误）
        "password",       // incorrect/wrong password
        "user name or password",
        "not exist",      // account/user not exist
        "disabled",
        "expired",
        "arrears",
        "balance",        // insufficient balance
        "traffic",        // traffic/flow used up
        "quota",
        "usage",          // usage/时长用尽
    };
    const QString lower = msg.toLower();
    for (const char* kw : kPermanentKeywords) {
        // 关键字含 UTF-8 中文，必须 fromUtf8 解码（fromLatin1 会把中文字节
        // 按 Latin-1 解释成错误字符导致永远匹配不上）；ASCII 英文两者等价
        if (lower.contains(QString::fromUtf8(kw)))
            return true;
    }
    return false;
}

} // namespace PortalProtocol
