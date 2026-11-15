#include "fileoperations.h"
#include "scanengine.h"

#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QtTest>
#include <atomic>
#include <chrono>
#include <thread>

class CoreTests final : public QObject {
    Q_OBJECT

private slots:
    void reportsSkippedFilesAndScanProgress()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString scannerDirectory = directory.filePath(QStringLiteral("bin"));
        QVERIFY(QDir().mkpath(scannerDirectory));
        QFile scanner(QDir(scannerDirectory).filePath(QStringLiteral("clamdscan")));
        QVERIFY(scanner.open(QIODevice::WriteOnly));
        QCOMPARE(scanner.write("#!/bin/sh\nexit 0\n"), qint64(17));
        scanner.close();
        QVERIFY(scanner.setPermissions(scanner.permissions() | QFileDevice::ExeOwner));

        const QString scanDirectory = directory.filePath(QStringLiteral("scan"));
        QVERIFY(QDir().mkpath(scanDirectory));
        auto createFile = [](const QString &path, const QByteArray &contents) {
            QFile file(path);
            if (!file.open(QIODevice::WriteOnly))
                return false;
            return file.write(contents) == contents.size();
        };
        QVERIFY(createFile(QDir(scanDirectory).filePath(QStringLiteral("clean.txt")), "ok"));
        QVERIFY(createFile(QDir(scanDirectory).filePath(QStringLiteral("large.txt")), "too-large"));
        QVERIFY(createFile(QDir(scanDirectory).filePath(QStringLiteral("archive.zip")), "zip"));

        const QByteArray oldPath = qgetenv("PATH");
        qputenv("PATH", scannerDirectory.toLocal8Bit() + QDir::listSeparator().toLatin1() + oldPath);
        ScanOptions options;
        options.targets = {scanDirectory};
        options.maxFileBytes = 5;
        options.scanArchives = false;
        std::atomic_bool cancelled{false};
        ScanProgress latest;
        const ScanSummary summary = ScanEngine::run(options, cancelled,
            [&latest](const ScanProgress &progress) { latest = progress; });
        qputenv("PATH", oldPath);

        QCOMPARE(summary.scanned, 1);
        QCOMPARE(summary.discovered, 1);
        QCOMPARE(summary.skippedLarge, 1);
        QCOMPARE(summary.skippedArchives, 1);
        QCOMPARE(summary.errors, 0);
        QCOMPARE(latest.discovered, 1);
    }

    void cancelsRunningScannerProcess()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString scannerDirectory = directory.filePath(QStringLiteral("bin"));
        QVERIFY(QDir().mkpath(scannerDirectory));
        QFile scanner(QDir(scannerDirectory).filePath(QStringLiteral("clamdscan")));
        QVERIFY(scanner.open(QIODevice::WriteOnly));
        QCOMPARE(scanner.write("#!/bin/sh\nexec sleep 10\n"), qint64(24));
        scanner.close();
        QVERIFY(scanner.setPermissions(scanner.permissions() | QFileDevice::ExeOwner));
        const QString target = directory.filePath(QStringLiteral("file.txt"));
        QFile file(target);
        QVERIFY(file.open(QIODevice::WriteOnly));
        QCOMPARE(file.write("test"), qint64(4));
        file.close();

        const QByteArray oldPath = qgetenv("PATH");
        qputenv("PATH", scannerDirectory.toLocal8Bit() + QDir::listSeparator().toLatin1() + oldPath);
        ScanOptions options;
        options.targets = {target};
        options.processTimeoutMs = 10000;
        std::atomic_bool cancelled{false};
        std::thread cancelThread([&cancelled] {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            cancelled.store(true);
        });
        QElapsedTimer elapsed;
        elapsed.start();
        const ScanSummary summary = ScanEngine::run(options, cancelled);
        cancelThread.join();
        qputenv("PATH", oldPath);

        QVERIFY(summary.cancelled);
        QVERIFY(elapsed.elapsed() < 2000);
    }

    void timesOutHungScannerProcess()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString scannerDirectory = directory.filePath(QStringLiteral("bin"));
        QVERIFY(QDir().mkpath(scannerDirectory));
        QFile scanner(QDir(scannerDirectory).filePath(QStringLiteral("clamdscan")));
        QVERIFY(scanner.open(QIODevice::WriteOnly));
        QCOMPARE(scanner.write("#!/bin/sh\nexec sleep 10\n"), qint64(24));
        scanner.close();
        QVERIFY(scanner.setPermissions(scanner.permissions() | QFileDevice::ExeOwner));
        const QString target = directory.filePath(QStringLiteral("file.txt"));
        QFile file(target);
        QVERIFY(file.open(QIODevice::WriteOnly));
        QCOMPARE(file.write("test"), qint64(4));
        file.close();

        const QByteArray oldPath = qgetenv("PATH");
        qputenv("PATH", scannerDirectory.toLocal8Bit() + QDir::listSeparator().toLatin1() + oldPath);
        ScanOptions options;
        options.targets = {target};
        options.processTimeoutMs = 100;
        std::atomic_bool cancelled{false};
        const ScanSummary summary = ScanEngine::run(options, cancelled);
        qputenv("PATH", oldPath);

        QCOMPARE(summary.errors, 1);
        QCOMPARE(summary.notableResults.size(), 1);
        QVERIFY(summary.notableResults.first().detail.contains(QStringLiteral("timed out")));
    }

    void interpretsCleanResult()
    {
        const FileResult result = ScanEngine::interpretResult(
            QStringLiteral("/tmp/clean"), 0, QStringLiteral("/tmp/clean: OK"));
        QVERIFY(!result.infected);
        QCOMPARE(result.status, QStringLiteral("Clean"));
    }

    void interpretsDetection()
    {
        const FileResult result = ScanEngine::interpretResult(
            QStringLiteral("/tmp/bad"), 1, QStringLiteral("/tmp/bad: Eicar-Signature FOUND"));
        QVERIFY(result.infected);
        QCOMPARE(result.status, QStringLiteral("Threat detected"));
    }

    void interpretsScannerFailure()
    {
        const FileResult result = ScanEngine::interpretResult(
            QStringLiteral("/tmp/file"), 2, QString(), QStringLiteral("daemon unavailable"));
        QVERIFY(!result.infected);
        QCOMPARE(result.status, QStringLiteral("Error"));
        QCOMPARE(result.detail, QStringLiteral("daemon unavailable"));
    }

    void recognizesExcludedPathsWithoutPrefixCollisions()
    {
        QVERIFY(ScanEngine::isExcludedPath(QStringLiteral("/proc/1/status")));
        QVERIFY(!ScanEngine::isExcludedPath(QStringLiteral("/proc-files/file")));
        QVERIFY(!ScanEngine::isExcludedPath(QStringLiteral("/home/user/file")));
    }

    void movesFilesAcrossDirectories()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString source = directory.filePath(QStringLiteral("source"));
        const QString destination = directory.filePath(QStringLiteral("subdir/destination"));
        QVERIFY(QDir().mkpath(QFileInfo(destination).absolutePath()));
        QFile input(source);
        QVERIFY(input.open(QIODevice::WriteOnly));
        QCOMPARE(input.write("test"), qint64(4));
        input.close();

        QVERIFY(moveFile(source, destination));
        QVERIFY(!QFileInfo::exists(source));
        QFile output(destination);
        QVERIFY(output.open(QIODevice::ReadOnly));
        QCOMPARE(output.readAll(), QByteArray("test"));
    }
};

QTEST_GUILESS_MAIN(CoreTests)
#include "core_tests.moc"
