#include "app_helpers.h"
#include "main_window.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QMessageBox>
#include <QPointer>
#include <QProcess>
#include <QProgressBar>
#include <QPushButton>
#include <QSet>
#include <QSettings>
#include <QSpinBox>
#include <QStandardPaths>
#include <QSystemTrayIcon>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThread>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrent>
#include <atomic>
#include <memory>

using AppHelpers::displayTargets;
using AppHelpers::quickScanTargets;

int MainWindow::workerLimit() const {
  const int cores = qMax(1, QThread::idealThreadCount());
  switch (intensityCombo_
              ? intensityCombo_->currentIndex()
              : settings_.value(QStringLiteral("scan/intensity"), 1).toInt()) {
  case 0:
    return 1;
  case 2:
    return qMin(4, cores);
  case 3:
    return cores;
  default:
    return qMin(2, cores);
  }
}

bool MainWindow::daemonAvailable() const {
  if (QStandardPaths::findExecutable(QStringLiteral("clamdscan")).isEmpty())
    return false;
  QProcess ping;
  ping.start(QStringLiteral("clamdscan"), {QStringLiteral("--ping=1")});
  if (ping.waitForStarted() && ping.waitForFinished(2000))
    return ping.exitStatus() == QProcess::NormalExit && ping.exitCode() == 0;
  if (ping.state() != QProcess::NotRunning) {
    ping.kill();
    ping.waitForFinished();
  }
  return false;
}

void MainWindow::stopScan() {
  if (!scanCancellation_ || !scanActive_)
    return;
  scanCancellation_->store(true);
  stopScanButton_->setEnabled(false);
  stopScanButton_->setText(QStringLiteral("Stopping…"));
  scanStatus_->setText(QStringLiteral("Stopping scan…"));
}

void MainWindow::startScan(const QStringList &targets, bool fullScan) {
  if (scanActive_) {
    QMessageBox::information(
        this, QStringLiteral("Scan in progress"),
        QStringLiteral("Please wait for the current scan to finish."));
    return;
  }
  if (QStandardPaths::findExecutable(QStringLiteral("clamdscan")).isEmpty()) {
    QMessageBox::warning(
        this, QStringLiteral("ClamAV scanner not found"),
        QStringLiteral("Install ClamAV and make sure clamdscan is available on "
                       "your PATH."));
    return;
  }
  if (!daemonAvailable()) {
    QMessageBox::warning(
        this, QStringLiteral("ClamAV daemon is not running"),
        QStringLiteral(
            "Start and configure the ClamAV daemon before scanning."));
    return;
  }
  scanCancellation_ = std::make_shared<std::atomic_bool>(false);
  const auto cancellation = scanCancellation_;
  scanActive_ = true;
  scanResults_->setRowCount(0);
  scanProgress_->setRange(0, 0);
  scanStatus_->setText(QStringLiteral("Preparing scan…"));
  stopScanButton_->setText(QStringLiteral("Stop scan"));
  stopScanButton_->setEnabled(true);
  stopScanButton_->setVisible(true);
  auto *watcher = new QFutureWatcher<ScanSummary>(this);
  scanWatcher_ = watcher;
  connect(
      watcher, &QFutureWatcher<ScanSummary>::finished, this, [this, watcher] {
        const ScanSummary summary = watcher->result();
        scanActive_ = false;
        stopScanButton_->setVisible(false);
        stopScanButton_->setEnabled(true);
        int currentThreats =
            settings_.value(QStringLiteral("stats/threats"), 0).toInt();
        for (const FileResult &file : summary.results) {
          if (!file.infected && file.status != QStringLiteral("Error"))
            continue;
          const int row = scanResults_->rowCount();
          scanResults_->insertRow(row);
          scanResults_->setItem(row, 0, new QTableWidgetItem(file.path));
          scanResults_->setItem(row, 1, new QTableWidgetItem(file.status));
          scanResults_->setItem(row, 2, new QTableWidgetItem(file.detail));
          if (file.infected) {
            ++currentThreats;
            addHistory(QStringLiteral("Detection"), file.path,
                       QStringLiteral("Threat detected"));
          }
        }
        settings_.setValue(QStringLiteral("stats/threats"), currentThreats);
        scanProgress_->setRange(0, 100);
        scanProgress_->setValue(summary.cancelled ? scanProgress_->value()
                                                  : 100);
        const QString result =
            QStringLiteral("%1%2 checked, %3 threat(s), %4 error(s)")
                .arg(summary.cancelled ? QStringLiteral("Stopped · ")
                                       : QString())
                .arg(summary.results.size())
                .arg(summary.infected)
                .arg(summary.errors);
        scanStatus_->setText(
            summary.cancelled
                ? QStringLiteral("Scan stopped · %1 files checked")
                      .arg(summary.results.size())
                : QStringLiteral("Scan complete · %1 files checked · %2 "
                                 "threats · %3 errors")
                      .arg(summary.results.size())
                      .arg(summary.infected)
                      .arg(summary.errors));
        addHistory(QStringLiteral("Scan"), summary.target, result);
        settings_.setValue(QStringLiteral("lastScan/time"),
                           QDateTime::currentDateTime().toString(Qt::ISODate));
        settings_.setValue(QStringLiteral("lastScan/result"), result);
        refreshDashboard();
        if (summary.infected > 0 && notificationCheck_->isChecked() &&
            trayIcon_)
          trayIcon_->showMessage(QStringLiteral("KlamAV detected threats"),
                                 QStringLiteral("%1 infected file(s) found.")
                                     .arg(summary.infected),
                                 QSystemTrayIcon::Warning);
        watcher->deleteLater();
      });

  const qint64 maxBytes =
      static_cast<qint64>(
          maxFileSize_
              ? maxFileSize_->value()
              : settings_.value(QStringLiteral("scan/maxFileSizeMb"), 64)
                    .toInt()) *
      1024 * 1024;
  const bool recursive =
      recursiveCheck_
          ? recursiveCheck_->isChecked()
          : settings_.value(QStringLiteral("scan/recursive"), true).toBool();
  const bool followSymlinks =
      symlinkCheck_
          ? symlinkCheck_->isChecked()
          : settings_.value(QStringLiteral("scan/followSymlinks"), false)
                .toBool();
  const int workers = workerLimit();
  const QStringList excluded =
      fullScan ? QStringList{QStringLiteral("/proc"), QStringLiteral("/sys"),
                             QStringLiteral("/dev"), QStringLiteral("/run"),
                             QStringLiteral("/var/lib/clamav")}
               : QStringList{};
  const bool scanArchives =
      archiveCheck_
          ? archiveCheck_->isChecked()
          : settings_.value(QStringLiteral("scan/archives"), true).toBool();
  const QPointer<MainWindow> guard(this);
  watcher->setFuture(QtConcurrent::run([targets, recursive, followSymlinks,
                                        maxBytes, workers, scanArchives,
                                        excluded, guard, cancellation]() {
    QStringList files;
    QSet<QString> seen;
    QStringList directories = targets;
    const QStringList archiveExtensions{
        QStringLiteral("zip"), QStringLiteral("7z"),  QStringLiteral("rar"),
        QStringLiteral("tar"), QStringLiteral("gz"),  QStringLiteral("bz2"),
        QStringLiteral("xz"),  QStringLiteral("cab"), QStringLiteral("iso"),
        QStringLiteral("arj"), QStringLiteral("zst")};
    for (const QString &target : targets) {
      if (cancellation->load())
        break;
      const QFileInfo info(target);
      if (info.isFile() && (!info.isSymLink() || followSymlinks) &&
          info.size() <= maxBytes &&
          (scanArchives ||
           !archiveExtensions.contains(info.suffix().toLower()))) {
        const QString canonical = info.canonicalFilePath();
        const QString key =
            canonical.isEmpty() ? info.absoluteFilePath() : canonical;
        if (!seen.contains(key)) {
          seen.insert(key);
          files.push_back(info.absoluteFilePath());
        }
      }
    }
    while (!directories.isEmpty() && !cancellation->load()) {
      const QString directory = directories.takeLast();
      const QFileInfo directoryInfo(directory);
      if (!directoryInfo.isDir() ||
          (directoryInfo.isSymLink() && !followSymlinks))
        continue;
      bool excludedDirectory = false;
      for (const QString &root : excluded) {
        if (directory == root ||
            directory.startsWith(root + QLatin1Char('/'))) {
          excludedDirectory = true;
          break;
        }
      }
      if (excludedDirectory)
        continue;
      const QString canonicalDirectory = directoryInfo.canonicalFilePath();
      const QString directoryKey = canonicalDirectory.isEmpty()
                                       ? directoryInfo.absoluteFilePath()
                                       : canonicalDirectory;
      if (seen.contains(directoryKey))
        continue;
      seen.insert(directoryKey);
      const QFileInfoList children = QDir(directory).entryInfoList(
          QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System,
          QDir::DirsFirst);
      for (const QFileInfo &info : children) {
        if (cancellation->load())
          break;
        if (info.isSymLink() && !followSymlinks)
          continue;
        if (info.isDir()) {
          if (recursive)
            directories.push_back(info.absoluteFilePath());
          continue;
        }
        if (!info.isFile() || info.size() > maxBytes)
          continue;
        if (!scanArchives &&
            archiveExtensions.contains(info.suffix().toLower()))
          continue;
        const QString canonical = info.canonicalFilePath();
        const QString key =
            canonical.isEmpty() ? info.absoluteFilePath() : canonical;
        if (!seen.contains(key)) {
          seen.insert(key);
          files.push_back(info.absoluteFilePath());
        }
      }
    }

    if (cancellation->load()) {
      ScanSummary summary;
      summary.target = displayTargets(targets);
      summary.cancelled = true;
      return summary;
    }
    if (guard) {
      QMetaObject::invokeMethod(
          guard,
          [guard, count = files.size()] {
            if (guard) {
              guard->scanProgress_->setRange(0, qMax(1, count));
              guard->scanProgress_->setValue(0);
              guard->scanStatus_->setText(
                  QStringLiteral("Scanning %1 file(s)…").arg(count));
            }
          },
          Qt::QueuedConnection);
    }
    QThreadPool pool;
    pool.setMaxThreadCount(workers);
    std::atomic_int completed{0};
    QFuture<FileResult> scanned = QtConcurrent::mapped(
        &pool, files,
        [guard, cancellation, &completed,
         total = files.size()](const QString &path) {
          FileResult file;
          file.path = path;
          if (cancellation->load()) {
            file.status = QStringLiteral("Stopped");
            return file;
          }
          QProcess process;
          process.start(QStringLiteral("clamdscan"),
                        {QStringLiteral("--no-summary"),
                         QStringLiteral("--infected"),
                         QStringLiteral("--fdpass"), path});
          bool started = process.waitForStarted(100);
          while (!started && process.state() == QProcess::Starting &&
                 !cancellation->load())
            started = process.waitForStarted(100);
          if (!started && cancellation->load() &&
              process.state() != QProcess::NotRunning) {
            process.kill();
            process.waitForFinished();
            file.status = QStringLiteral("Stopped");
            file.detail = QStringLiteral("Stopped by user");
          } else if (!started) {
            file.status = QStringLiteral("Error");
            file.detail = process.errorString();
          } else {
            while (process.state() != QProcess::NotRunning) {
              if (cancellation->load()) {
                process.terminate();
                if (!process.waitForFinished(500)) {
                  process.kill();
                  process.waitForFinished();
                }
                file.status = QStringLiteral("Stopped");
                file.detail = QStringLiteral("Stopped by user");
                break;
              }
              process.waitForFinished(100);
            }
            if (file.status.isEmpty()) {
              const QString output =
                  QString::fromLocal8Bit(process.readAllStandardOutput() +
                                         process.readAllStandardError())
                      .trimmed();
              file.infected = process.exitStatus() == QProcess::NormalExit &&
                              (process.exitCode() == 1 ||
                               output.contains(QStringLiteral("FOUND"),
                                               Qt::CaseInsensitive));
              if (file.infected) {
                file.status = QStringLiteral("Threat detected");
                file.detail = output;
              } else if (process.exitStatus() == QProcess::NormalExit &&
                         process.exitCode() == 0) {
                file.status = QStringLiteral("Clean");
                file.detail = output;
              } else {
                file.status = QStringLiteral("Error");
                file.detail =
                    output.isEmpty()
                        ? QStringLiteral("clamdscan exited with code %1")
                              .arg(process.exitCode())
                        : output;
              }
            }
          }
          const int done = ++completed;
          if (guard) {
            QMetaObject::invokeMethod(
                guard,
                [guard, done, total] {
                  if (guard) {
                    guard->scanProgress_->setRange(0, qMax(1, total));
                    guard->scanProgress_->setValue(done);
                  }
                },
                Qt::QueuedConnection);
          }
          return file;
        });
    scanned.waitForFinished();

    ScanSummary summary;
    summary.target = displayTargets(targets);
    summary.results.reserve(scanned.resultCount());
    for (int i = 0; i < scanned.resultCount(); ++i) {
      const FileResult file = scanned.resultAt(i);
      if (file.status == QStringLiteral("Stopped")) {
        summary.cancelled = true;
        continue;
      }
      summary.results.push_back(file);
      if (file.infected)
        ++summary.infected;
      else if (file.status == QStringLiteral("Error"))
        ++summary.errors;
    }
    return summary;
  }));

  scanStatus_->setText(QStringLiteral("Preparing scan…"));
}

void MainWindow::updateDefinitions() {
  if (QStandardPaths::findExecutable(QStringLiteral("freshclam")).isEmpty()) {
    QMessageBox::warning(
        this, QStringLiteral("Updater not found"),
        QStringLiteral("Install ClamAV and make sure freshclam is available on "
                       "your PATH."));
    return;
  }
  auto *process = new QProcess(this);
  process->setProgram(QStringLiteral("freshclam"));
  process->setArguments({QStringLiteral("--stdout")});
  connect(process, &QProcess::errorOccurred, this,
          [this, process](QProcess::ProcessError) {
            addHistory(
                QStringLiteral("Update"), QStringLiteral("Virus definitions"),
                QStringLiteral("Failed: %1").arg(process->errorString()));
            QMessageBox::warning(this, QStringLiteral("Update failed"),
                                 process->errorString());
            process->deleteLater();
          });
  connect(
      process, &QProcess::finished, this,
      [this, process](int exitCode, QProcess::ExitStatus) {
        const QString output =
            QString::fromLocal8Bit(process->readAllStandardOutput() +
                                   process->readAllStandardError())
                .trimmed();
        const bool success = exitCode == 0;
        addHistory(QStringLiteral("Update"),
                   QStringLiteral("Virus definitions"),
                   success ? QStringLiteral("Updated successfully")
                           : QStringLiteral("Failed (exit %1)").arg(exitCode));
        QMessageBox::information(
            this,
            success ? QStringLiteral("Definitions updated")
                    : QStringLiteral("Update failed"),
            output.isEmpty()
                ? (success ? QStringLiteral("Virus definitions are up to date.")
                           : QStringLiteral("freshclam exited with code %1.")
                                 .arg(exitCode))
                : output);
        refreshDashboard();
        process->deleteLater();
      });
  process->start();
}

void MainWindow::runScheduledScan() {
  const int schedule =
      settings_.value(QStringLiteral("scan/schedule"), 0).toInt();
  if (schedule <= 0)
    return;
  const QDateTime nextRun = QDateTime::fromString(
      settings_.value(QStringLiteral("scan/nextRun")).toString(), Qt::ISODate);
  if (!nextRun.isValid() || QDateTime::currentDateTime() < nextRun)
    return;
  if (scanActive_) {
    settings_.setValue(
        QStringLiteral("scan/nextRun"),
        QDateTime::currentDateTime().addSecs(300).toString(Qt::ISODate));
    return;
  }
  if (!daemonAvailable()) {
    settings_.setValue(
        QStringLiteral("scan/nextRun"),
        QDateTime::currentDateTime().addSecs(300).toString(Qt::ISODate));
    if (trayIcon_ && notificationCheck_ && notificationCheck_->isChecked())
      trayIcon_->showMessage(
          QStringLiteral("Scheduled scan postponed"),
          QStringLiteral("The ClamAV daemon is not responding."),
          QSystemTrayIcon::Warning);
    return;
  }
  const int days = schedule == 1 ? 1 : 7;
  settings_.setValue(
      QStringLiteral("scan/nextRun"),
      QDateTime::currentDateTime().addDays(days).toString(Qt::ISODate));
  startScan(quickScanTargets());
}
