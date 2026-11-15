#include "scanengine.h"

#include <QDir>
#include <QDirIterator>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QProcess>
#include <QSet>
#include <QThreadPool>
#include <QFuture>
#include <QtConcurrent/QtConcurrentMap>
#include <utility>

namespace {

const QStringList &archiveExtensions()
{
    static const QStringList extensions{
        QStringLiteral("zip"), QStringLiteral("7z"), QStringLiteral("rar"),
        QStringLiteral("tar"), QStringLiteral("gz"), QStringLiteral("bz2"),
        QStringLiteral("xz"), QStringLiteral("cab"), QStringLiteral("iso"),
        QStringLiteral("arj"), QStringLiteral("zst")
    };
    return extensions;
}
bool isArchive(const QFileInfo &info)
{
    return archiveExtensions().contains(info.suffix().toLower());
}

QString canonicalOrAbsolute(const QFileInfo &info)
{
    const QString canonical = info.canonicalFilePath();
    return canonical.isEmpty() ? info.absoluteFilePath() : canonical;
}

bool containsPath(const QString &root, const QString &path)
{
    return path == root || path.startsWith(root + QLatin1Char('/'));
}

QVector<FileResult> scanBatch(const QStringList &files, const ScanOptions &options,
                              const std::atomic_bool &cancelled, int &scanned,
                              int &infected, int &errors, int &skippedUnreadable,
                              const ScanEngine::ProgressCallback &progress,
                              int discovered, int skippedLarge, int skippedArchives,
                              int excluded)
{
    QThreadPool pool;
    pool.setMaxThreadCount(qMax(1, options.workers));
    std::atomic_int completed{0};
    std::atomic_int foundThreats{0};
    std::atomic_int foundErrors{0};
    std::atomic_int unreadable{0};
    const int baseScanned = scanned;
    QFuture<FileResult> results = QtConcurrent::mapped(&pool, files,
        [&options, &cancelled, &completed, &foundThreats, &foundErrors,
         &unreadable, &progress, baseScanned, discovered, skippedLarge,
         skippedArchives, excluded]
        (const QString &path) {
            FileResult file;
            file.path = path;
            if (cancelled.load()) {
                file.status = QStringLiteral("Cancelled");
                return file;
            }

            QProcess process;
            process.start(QStringLiteral("clamdscan"),
                          {QStringLiteral("--no-summary"), QStringLiteral("--infected"),
                           QStringLiteral("--fdpass"), path});
            if (!process.waitForStarted(5000)) {
                file.status = QStringLiteral("Error");
                file.detail = process.errorString();
            } else {
                QElapsedTimer timer;
                timer.start();
                while (process.state() != QProcess::NotRunning) {
                    if (cancelled.load()) {
                        process.kill();
                        process.waitForFinished();
                        file.status = QStringLiteral("Cancelled");
                        break;
                    }
                    const int remaining = options.processTimeoutMs - static_cast<int>(timer.elapsed());
                    if (remaining <= 0) {
                        process.kill();
                        process.waitForFinished();
                        file.status = QStringLiteral("Error");
                        file.detail = QStringLiteral("clamdscan timed out after %1 seconds")
                                          .arg(options.processTimeoutMs / 1000);
                        break;
                    }
                    process.waitForFinished(qMin(200, remaining));
                }
                if (process.state() == QProcess::NotRunning
                    && file.status.isEmpty()) {
                    const QString output = QString::fromLocal8Bit(
                        process.readAllStandardOutput() + process.readAllStandardError()).trimmed();
                    const int exitCode = process.exitStatus() == QProcess::NormalExit
                        ? process.exitCode() : -1;
                    file = ScanEngine::interpretResult(path, exitCode, output,
                                                       process.errorString());
                }
            }

            if (file.infected)
                ++foundThreats;
            else if (file.status == QStringLiteral("Error"))
                ++foundErrors;
            else if (file.status == QStringLiteral("Unreadable"))
                ++unreadable;
            const int done = ++completed;
            if (progress && (done % 10 == 0 || file.infected
                             || file.status == QStringLiteral("Error"))) {
                ScanProgress update;
                update.discovered = discovered;
                update.scanned = baseScanned + done;
                update.skippedLarge = skippedLarge;
                update.skippedArchives = skippedArchives;
                update.skippedUnreadable = unreadable.load();
                update.excluded = excluded;
                if (file.infected || file.status == QStringLiteral("Error"))
                    update.notableResults.push_back(file);
                progress(update);
            }
            return file;
        });
    results.waitForFinished();

    QVector<FileResult> notable;
    for (int i = 0; i < results.resultCount(); ++i) {
        const FileResult result = results.resultAt(i);
        if (result.infected || result.status == QStringLiteral("Error"))
            notable.push_back(result);
    }
    scanned += completed.load();
    infected += foundThreats.load();
    errors += foundErrors.load();
    skippedUnreadable += unreadable.load();
    return notable;
}

} // namespace

FileResult ScanEngine::interpretResult(const QString &path, int exitCode,
                                       const QString &output, const QString &processError)
{
    FileResult result;
    result.path = path;
    result.detail = output;
    result.infected = exitCode == 1 || output.contains(QStringLiteral("FOUND"), Qt::CaseInsensitive);
    if (result.infected) {
        result.status = QStringLiteral("Threat detected");
    } else if (exitCode == 0) {
        result.status = QStringLiteral("Clean");
    } else {
        result.status = QStringLiteral("Error");
        if (result.detail.isEmpty())
            result.detail = processError.isEmpty()
                ? QStringLiteral("clamdscan exited with code %1").arg(exitCode)
                : processError;
    }
    return result;
}

bool ScanEngine::isExcludedPath(const QString &path)
{
    static const QStringList exclusions{
        QStringLiteral("/proc"), QStringLiteral("/sys"), QStringLiteral("/dev"),
        QStringLiteral("/run"), QStringLiteral("/var/lib/clamav")
    };
    const QString absolute = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    for (const QString &root : exclusions) {
        if (containsPath(root, absolute))
            return true;
    }
    return false;
}

ScanSummary ScanEngine::run(const ScanOptions &options, const std::atomic_bool &cancelled,
                            const ProgressCallback &progress)
{
    ScanSummary summary;
    summary.target = options.targets.join(QStringLiteral(", "));
    QStringList directories;
    QStringList batch;
    QSet<QString> seenDirectories;
    QSet<QString> explicitFiles;
    QSet<QString> batchFiles;
    int inspectedEntries = 0;
    auto reportEnumeration = [&] {
        if (!progress)
            return;
        ScanProgress update;
        update.discovered = summary.discovered;
        update.scanned = summary.scanned;
        update.skippedLarge = summary.skippedLarge;
        update.skippedArchives = summary.skippedArchives;
        update.skippedUnreadable = summary.skippedUnreadable;
        update.excluded = summary.excluded;
        progress(update);
    };

    auto publish = [&] {
        if (batch.isEmpty() || cancelled.load())
            return;
        reportEnumeration();
        summary.notableResults += scanBatch(batch, options, cancelled, summary.scanned,
                                            summary.infected, summary.errors,
                                            summary.skippedUnreadable, progress,
                                            summary.discovered, summary.skippedLarge,
                                            summary.skippedArchives, summary.excluded);
        batch.clear();
        batchFiles.clear();
    };

    for (const QString &target : options.targets) {
        if (cancelled.load())
            break;
        const QFileInfo info(target);
        if (options.fullScan && isExcludedPath(target)) {
            ++summary.excluded;
        } else if (info.isFile()) {
            if (info.isSymLink() && !options.followSymlinks) {
                ++summary.excluded;
            } else if (info.size() > options.maxFileBytes) {
                ++summary.skippedLarge;
            } else if (!info.isReadable()) {
                ++summary.skippedUnreadable;
            } else if (!options.scanArchives && isArchive(info)) {
                ++summary.skippedArchives;
            } else {
                const QString key = canonicalOrAbsolute(info);
                if (!explicitFiles.contains(key)) {
                    explicitFiles.insert(key);
                    batchFiles.insert(key);
                    batch.push_back(info.absoluteFilePath());
                    ++summary.discovered;
                }
            }
            if (batch.size() >= 128)
                publish();
        } else if (info.isDir()) {
            directories.push_back(info.absoluteFilePath());
        } else {
            ++summary.skippedUnreadable;
        }
    }

    while (!directories.isEmpty() && !cancelled.load()) {
        const QString directory = directories.takeLast();
        if (options.fullScan && isExcludedPath(directory)) {
            ++summary.excluded;
            continue;
        }
        const QFileInfo directoryInfo(directory);
        if (!directoryInfo.isReadable()) {
            ++summary.skippedUnreadable;
            continue;
        }
        if (directoryInfo.isSymLink() && !options.followSymlinks) {
            ++summary.excluded;
            continue;
        }
        const QString directoryKey = canonicalOrAbsolute(directoryInfo);
        if (seenDirectories.contains(directoryKey))
            continue;
        seenDirectories.insert(directoryKey);

        QDirIterator iterator(directory,
                              QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
        while (iterator.hasNext() && !cancelled.load()) {
            const QString path = iterator.next();
            if (++inspectedEntries % 100 == 0)
                reportEnumeration();
            const QFileInfo info = iterator.fileInfo();
            if (info.isSymLink() && !options.followSymlinks) {
                ++summary.excluded;
                continue;
            }
            if (info.isDir()) {
                if (options.fullScan && isExcludedPath(path)) {
                    ++summary.excluded;
                    continue;
                }
                if (options.recursive)
                    directories.push_back(path);
                continue;
            }
            if (!info.isFile())
                continue;
            if (info.size() > options.maxFileBytes) {
                ++summary.skippedLarge;
                continue;
            }
            if (!info.isReadable()) {
                ++summary.skippedUnreadable;
                continue;
            }
            if (!options.scanArchives && isArchive(info)) {
                ++summary.skippedArchives;
                continue;
            }
            const QString key = canonicalOrAbsolute(info);
            if (explicitFiles.contains(key) || batchFiles.contains(key))
                continue;
            batchFiles.insert(key);
            batch.push_back(info.absoluteFilePath());
            ++summary.discovered;
            if (batch.size() >= 128)
                publish();
        }
    }
    publish();
    summary.cancelled = cancelled.load();
    if (progress) {
        ScanProgress update;
        update.discovered = summary.discovered;
        update.scanned = summary.scanned;
        update.skippedLarge = summary.skippedLarge;
        update.skippedArchives = summary.skippedArchives;
        update.skippedUnreadable = summary.skippedUnreadable;
        update.excluded = summary.excluded;
        progress(update);
    }
    return summary;
}
