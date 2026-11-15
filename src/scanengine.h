#pragma once

#include <QDateTime>
#include <QStringList>
#include <QVector>
#include <atomic>
#include <functional>

struct FileResult {
    QString path;
    QString status;
    QString detail;
    bool infected = false;
};

struct ScanProgress {
    int discovered = 0;
    int scanned = 0;
    int skippedLarge = 0;
    int skippedArchives = 0;
    int skippedUnreadable = 0;
    int excluded = 0;
    QVector<FileResult> notableResults;
};

struct ScanSummary {
    QString target;
    int discovered = 0;
    int scanned = 0;
    int infected = 0;
    int errors = 0;
    int skippedLarge = 0;
    int skippedArchives = 0;
    int skippedUnreadable = 0;
    int excluded = 0;
    bool cancelled = false;
    QVector<FileResult> notableResults;
};

struct ScanOptions {
    QStringList targets;
    bool recursive = true;
    bool followSymlinks = false;
    bool scanArchives = true;
    bool fullScan = false;
    qint64 maxFileBytes = 64 * 1024 * 1024;
    int workers = 2;
    int processTimeoutMs = 120000;
};

class ScanEngine final {
public:
    using ProgressCallback = std::function<void(const ScanProgress &)>;

    static ScanSummary run(const ScanOptions &options, const std::atomic_bool &cancelled,
                           const ProgressCallback &progress = {});
    static FileResult interpretResult(const QString &path, int exitCode,
                                      const QString &output, const QString &processError = {});
    static bool isExcludedPath(const QString &path);
};
