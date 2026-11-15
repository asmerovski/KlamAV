#include "systemdscheduler.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QSaveFile>
#include <QStandardPaths>

namespace {

bool runSystemctl(const QStringList &arguments, QString *error)
{
    const QString systemctl = QStandardPaths::findExecutable(QStringLiteral("systemctl"));
    if (systemctl.isEmpty()) {
        if (error)
            *error = QStringLiteral("systemctl is not installed.");
        return false;
    }

    QProcess process;
    process.start(systemctl, QStringList{QStringLiteral("--user")} + arguments);
    if (!process.waitForStarted(3000)) {
        if (error)
            *error = process.errorString();
        return false;
    }
    if (!process.waitForFinished(10000)) {
        process.kill();
        process.waitForFinished();
        if (error)
            *error = QStringLiteral("systemctl --user timed out.");
        return false;
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        if (error) {
            const QString output = QString::fromLocal8Bit(
                process.readAllStandardError() + process.readAllStandardOutput()).trimmed();
            *error = output.isEmpty()
                ? QStringLiteral("systemctl --user exited with code %1.").arg(process.exitCode())
                : output;
        }
        return false;
    }
    return true;
}

bool writeUnit(const QString &path, const QByteArray &contents, QString *error)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(contents) != contents.size() || !file.commit()) {
        if (error)
            *error = QStringLiteral("Could not write %1.").arg(path);
        return false;
    }
    return true;
}

QString escapeUnitArgument(QString argument)
{
    argument.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    argument.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    argument.replace(QLatin1Char('%'), QStringLiteral("%%"));
    return argument;
}

} // namespace

bool SystemdScheduler::configure(int schedule, const QString &executable, QString *error)
{
    const QString unitDirectory = QDir(QStandardPaths::writableLocation(QStandardPaths::ConfigLocation))
                                      .filePath(QStringLiteral("systemd/user"));
    const QString servicePath = QDir(unitDirectory).filePath(QStringLiteral("klamav-scan.service"));
    const QString timerPath = QDir(unitDirectory).filePath(QStringLiteral("klamav-scan.timer"));
    const bool hasUnits = QFileInfo::exists(servicePath) || QFileInfo::exists(timerPath);
    if (schedule == 0) {
        if (!hasUnits)
            return true;
        if (!runSystemctl({QStringLiteral("disable"), QStringLiteral("--now"),
                           QStringLiteral("klamav-scan.timer")}, error))
            return false;
        if ((QFileInfo::exists(servicePath) && !QFile::remove(servicePath))
            || (QFileInfo::exists(timerPath) && !QFile::remove(timerPath))) {
            if (error)
                *error = QStringLiteral("Could not remove the KlamAV timer unit files.");
            return false;
        }
        return runSystemctl({QStringLiteral("daemon-reload")}, error);
    }

    if (schedule != 1 && schedule != 2) {
        if (error)
            *error = QStringLiteral("Unsupported scan schedule.");
        return false;
    }
    if (!QDir().mkpath(unitDirectory)) {
        if (error)
            *error = QStringLiteral("Could not create the user systemd unit directory.");
        return false;
    }

    const QString command = QStringLiteral("ExecStart=\"%1\" --scheduled-scan\n")
                                .arg(escapeUnitArgument(executable));
    const QByteArray service = (QStringLiteral(
        "[Unit]\nDescription=KlamAV scheduled ClamAV scan\n\n"
        "[Service]\nType=oneshot\n") + command).toUtf8();
    const QString calendar = schedule == 1 ? QStringLiteral("daily") : QStringLiteral("weekly");
    const QByteArray timer = (QStringLiteral(
        "[Unit]\nDescription=Run KlamAV scheduled scan\n\n"
        "[Timer]\nOnCalendar=") + calendar
        + QStringLiteral("\nPersistent=true\nRandomizedDelaySec=15m\n\n"
                         "[Install]\nWantedBy=timers.target\n")).toUtf8();
    if (!writeUnit(servicePath, service, error) || !writeUnit(timerPath, timer, error))
        return false;
    if (!runSystemctl({QStringLiteral("daemon-reload")}, error))
        return false;
    return runSystemctl({QStringLiteral("enable"), QStringLiteral("--now"),
                         QStringLiteral("klamav-scan.timer")}, error);
}
