#include "portal/portal_protocol.h"
#include "core/constants.h"
#include <QJsonDocument>
#include <QJsonObject>

namespace PortalProtocol {

// ---------------------------------------------------------------------------
// URL 构造
//
// query 中各参数显式用 QUrl::toPercentEncoding 编码（逗号 / & / = / @ 等
// 在密码中常见），保证与浏览器端 eportal JS 的 encodeURIComponent 行为一致；
// 固定参数（c=Portal 等）均为安全字符，直接拼接。
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
                   const QString& password, const QString& userIp, int v)
{
    // DrCOM eportal 用户账号格式：",0,<学号>"。前缀 ",0," 为设备类型标记
    //（0 = PC），缺失会被服务器拒绝（逆向自门户页 JS 的 fixed_account 逻辑）。
    const QString userAccount = QStringLiteral(",0,") + username;

    QUrl url;
    url.setScheme(QStringLiteral("https"));
    url.setHost(host);
    url.setPort(PORTAL_LOGIN_PORT);
    url.setPath(QStringLiteral("/eportal/"));
    url.setQuery(QStringLiteral(
                     "c=Portal&a=login&callback=dr1003&login_method=1")
                 + QStringLiteral("&user_account=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(userAccount))
                 + QStringLiteral("&user_password=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(password))
                 + QStringLiteral("&wlan_user_ip=")
                 + QString::fromUtf8(QUrl::toPercentEncoding(userIp))
                 + QStringLiteral("&wlan_user_ipv6=&wlan_user_mac=")
                 + QLatin1String(PORTAL_WLAN_USER_MAC)
                 + QStringLiteral("&wlan_ac_ip=&wlan_ac_name=&jsVersion=")
                 + QLatin1String(PORTAL_JS_VERSION)
                 + QStringLiteral("&v=%1").arg(v));
    return url;
}

QUrl buildLogoutUrl(const QString& host, int v)
{
    QUrl url;
    url.setScheme(QStringLiteral("https"));
    url.setHost(host);
    url.setPath(QStringLiteral("/drcom/logout"));
    url.setQuery(QStringLiteral("callback=dr1006&jsVersion=%1&v=%2&lang=zh")
                     .arg(QLatin1String(PORTAL_JS_VERSION)).arg(v));
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

    const QJsonDocument doc = QJsonDocument::fromJson(json);
    if (!doc.isObject())
        return r;

    const QJsonObject obj = doc.object();
    // result 兼容数字与字符串两种部署形态（"result":1 / "result":"1"）
    const QJsonValue resultVal = obj.value(QStringLiteral("result"));
    r.result = resultVal.isString() ? resultVal.toString().toInt()
                                    : static_cast<int>(resultVal.toDouble());
    r.msg   = obj.value(QStringLiteral("msg")).toString();
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
