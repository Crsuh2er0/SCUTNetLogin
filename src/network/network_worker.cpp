#include "network/network_worker.h"
#include "network/network.h"
#include "core/constants.h"
#include <QProcess>
#include <QCoreApplication>
#include <QDir>
#include <QThread>
#include <windows.h>

// ============================================================================
// 构造 / 析构
// ============================================================================

NetworkWorker::NetworkWorker(QObject* parent)
    : QObject(parent) {}

NetworkWorker::~NetworkWorker() = default;

// ============================================================================
// 静态 IP 设置 / DHCP 恢复
// ============================================================================

void NetworkWorker::doSetStaticIp(const QString& adapter, const QString& ip,
                                   const QString& mask, const QString& gw,
                                   const QString& dns1, const QString& dns2)
{
    QString error;
    bool ok = Network::setStaticIp(adapter, ip, mask, gw, dns1, dns2, &error);
    QThread::msleep(IP_SETTLE_WAIT);
    if (ok)
        emit staticIpDone();
    else
        emit staticIpFailed(error);
}

void NetworkWorker::doSetDhcp(const QString& adapter)
{
    Network::setDhcp(adapter);
}

// ============================================================================
// 开机自启 (Task Scheduler)
// ============================================================================

void NetworkWorker::doSetAutoStart(bool enable)
{
    QString taskName = QStringLiteral("SCUTNetLogin_AutoStart");
    QString appPath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());

    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
        cpa->flags |= CREATE_NO_WINDOW;
    });

    // 重要：schtasks 的 /tr 值含路径 + "--silent"，若走 QProcess::start(program, QStringList)，
    // Qt 会自动对含空格的参数加引号并转义内部引号，导致 schtasks 收到双反斜杠转义的引号，
    // 无法解析路径 → /create 失败 → 任务从不创建 → 之后 /delete 报"系统找不到指定的文件"。
    //
    // 因此全部改用 setNativeArguments 手工拼接命令行。schtasks 官方文档对含空格的 /tr 路径
    // 要求【两套引号】：外层双引号给 CMD.EXE，内层单引号 '...' 给 schtasks.exe 解析路径，
    // 即：/tr "'C:\path\exe.exe' --silent"。单引号在 Windows 命令行是字面字符，
    // 不与双引号争夺语义，彻底避免 "\\\"C:\\...\\exe\\\"" 这类反斜杠转义地狱。
    // /rl highest 需管理员权限创建（本程序以管理员运行），确保成功。
    if (enable) {
        const QString native =
            QStringLiteral("/create /tn \"%1\" /tr \"'%2' --silent\" /sc onlogon /rl highest /f")
                .arg(taskName, appPath);
        proc.setProgram(QStringLiteral("schtasks"));
        proc.setNativeArguments(native);
        qWarning().noquote() << "[AutoStart] create:" << native;
    } else {
        const QString native =
            QStringLiteral("/delete /tn \"%1\" /f").arg(taskName);
        proc.setProgram(QStringLiteral("schtasks"));
        proc.setNativeArguments(native);
        qWarning().noquote() << "[AutoStart] delete:" << native;
    }
    proc.start();
    if (!proc.waitForFinished(NETSH_TIMEOUT)) {
        // 显式终止挂起的 schtasks，并报告超时（原实现忽略返回值，
        // 直接读 exitCode() 语义未定义）
        proc.kill();
        proc.waitForFinished(2000);
        emit autoStartDone(false, QStringLiteral("schtasks 命令超时"));
        return;
    }

    if (proc.exitCode() != 0) {
        QString err = QString::fromLocal8Bit(proc.readAllStandardError()).trimmed();
        if (err.isEmpty())
            err = QString::fromLocal8Bit(proc.readAllStandardOutput()).trimmed();
        emit autoStartDone(false, err.isEmpty() ? QStringLiteral("schtasks 执行失败") : err);
    } else {
        emit autoStartDone(true, QString());
    }
}
