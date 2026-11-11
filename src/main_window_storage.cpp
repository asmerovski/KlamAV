#include "app_helpers.h"
#include "main_window.h"

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QSaveFile>
#include <QSet>
#include <QSettings>
#include <QSpinBox>
#include <QStandardPaths>
#include <QSystemTrayIcon>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QUuid>

using AppHelpers::moveFile;

void MainWindow::saveSettings() {
  settings_.setValue(QStringLiteral("scan/maxFileSizeMb"),
                     maxFileSize_->value());
  settings_.setValue(QStringLiteral("scan/archives"),
                     archiveCheck_->isChecked());
  settings_.setValue(QStringLiteral("scan/followSymlinks"),
                     symlinkCheck_->isChecked());
  settings_.setValue(QStringLiteral("scan/recursive"),
                     recursiveCheck_->isChecked());
  settings_.setValue(QStringLiteral("scan/intensity"),
                     intensityCombo_->currentIndex());
  settings_.setValue(QStringLiteral("desktop/notifications"),
                     notificationCheck_->isChecked());
  settings_.setValue(QStringLiteral("desktop/startup"),
                     startupCheck_->isChecked());
  settings_.setValue(QStringLiteral("desktop/tray"), trayCheck_->isChecked());
  settings_.setValue(QStringLiteral("protection/realtime"),
                     realtimeCheck_->isChecked());
  settings_.setValue(QStringLiteral("scan/schedule"),
                     scheduleCombo_->currentIndex());
  if (scheduleCombo_->currentIndex() == 0) {
    settings_.remove(QStringLiteral("scan/nextRun"));
  } else if (settings_.value(QStringLiteral("scan/schedule")).toInt() !=
                 settings_.value(QStringLiteral("scan/previousSchedule"), -1)
                     .toInt() ||
             settings_.value(QStringLiteral("scan/nextRun"))
                 .toString()
                 .isEmpty()) {
    const int days = scheduleCombo_->currentIndex() == 1 ? 1 : 7;
    settings_.setValue(
        QStringLiteral("scan/nextRun"),
        QDateTime::currentDateTime().addDays(days).toString(Qt::ISODate));
  }
  settings_.setValue(QStringLiteral("scan/previousSchedule"),
                     scheduleCombo_->currentIndex());
  settings_.sync();
  saveAutostartEntry(startupCheck_->isChecked());
  if (trayCheck_->isChecked() && QSystemTrayIcon::isSystemTrayAvailable())
    ensureTrayIcon();
  else if (trayIcon_)
    trayIcon_->hide();
  QMessageBox::information(
      this, QStringLiteral("Settings saved"),
      QStringLiteral(
          "Your preferences have been saved. Scheduled scans run while KlamAV "
          "is open; real-time protection is not activated by this build."));
}

void MainWindow::saveAutostartEntry(bool enabled) {
  const QString path =
      QDir(QStandardPaths::writableLocation(QStandardPaths::ConfigLocation))
          .filePath(QStringLiteral("autostart/org.klamav.KlamAV.desktop"));
  if (!enabled) {
    if (QFileInfo::exists(path) && !QFile::remove(path))
      QMessageBox::warning(
          this, QStringLiteral("Could not update startup settings"),
          QStringLiteral("KlamAV could not remove its autostart entry."));
    return;
  }
  if (!QDir().mkpath(QFileInfo(path).absolutePath())) {
    QMessageBox::warning(
        this, QStringLiteral("Could not update startup settings"),
        QStringLiteral(
            "KlamAV could not create the desktop autostart folder."));
    return;
  }
  QString executable = QCoreApplication::applicationFilePath();
  executable.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
  executable.replace(QLatin1Char('"'), QStringLiteral("\\\""));
  QSaveFile file(path);
  const QByteArray entry =
      (QStringLiteral("[Desktop Entry]\nType=Application\nName=KlamAV\n") +
       QStringLiteral(
           "Comment=ClamAV antivirus frontend\nExec=\"%1\"\nTerminal=false\n")
           .arg(executable))
          .toUtf8();
  if (!file.open(QIODevice::WriteOnly) || file.write(entry) != entry.size() ||
      !file.commit())
    QMessageBox::warning(
        this, QStringLiteral("Could not update startup settings"),
        QStringLiteral("KlamAV could not write its autostart entry."));
}

void MainWindow::ensureTrayIcon() {
  if (trayIcon_)
    return;
  trayIcon_ = new QSystemTrayIcon(
      QIcon::fromTheme(QStringLiteral("org.klamav.KlamAV"), windowIcon()),
      this);
  trayIcon_->setToolTip(QStringLiteral("KlamAV"));
  auto *menu = new QMenu(this);
  auto *open = menu->addAction(QStringLiteral("Open KlamAV"));
  auto *quit = menu->addAction(QStringLiteral("Quit"));
  connect(open, &QAction::triggered, this, [this] {
    showNormal();
    raise();
    activateWindow();
  });
  connect(quit, &QAction::triggered, qApp, &QApplication::quit);
  trayIcon_->setContextMenu(menu);
  connect(trayIcon_, &QSystemTrayIcon::activated, this,
          [this](QSystemTrayIcon::ActivationReason reason) {
            if (reason == QSystemTrayIcon::Trigger ||
                reason == QSystemTrayIcon::DoubleClick) {
              showNormal();
              raise();
              activateWindow();
            }
          });
  trayIcon_->show();
}

void MainWindow::addHistory(const QString &type, const QString &target,
                            const QString &result) {
  QStringList entries =
      settings_.value(QStringLiteral("history/entries")).toStringList();
  entries.prepend(QStringList{
      QDateTime::currentDateTime().toString(Qt::ISODate), type, target, result}
                      .join(QLatin1Char('\t')));
  while (entries.size() > 300)
    entries.removeLast();
  settings_.setValue(QStringLiteral("history/entries"), entries);
  refreshHistory();
}

void MainWindow::refreshDashboard() {
  const bool scannerInstalled =
      !QStandardPaths::findExecutable(QStringLiteral("clamdscan")).isEmpty();
  const bool daemonIsAvailable = scannerInstalled && daemonAvailable();
  if (headerStatus_)
    headerStatus_->setText(
        daemonIsAvailable
            ? QStringLiteral("●  ClamAV active")
            : (scannerInstalled ? QStringLiteral("●  Daemon offline")
                                : QStringLiteral("●  Scanner not installed")));
  if (dashboardProtection_)
    dashboardProtection_->setText(
        daemonIsAvailable
            ? QStringLiteral("Active")
            : (scannerInstalled ? QStringLiteral("Daemon offline")
                                : QStringLiteral("Not installed")));
  if (dashboardHeroStatus_)
    dashboardHeroStatus_->setText(
        daemonIsAvailable
            ? QStringLiteral("Protection ready")
            : (scannerInstalled
                   ? QStringLiteral("ClamAV daemon is not responding")
                   : QStringLiteral("ClamAV is not installed")));
  if (dashboardDefinitions_) {
    const QStringList definitions =
        QDir(QStringLiteral("/var/lib/clamav"))
            .entryList({QStringLiteral("*.cvd"), QStringLiteral("*.cld")},
                       QDir::Files);
    const QStringList userDefinitions =
        QDir(QDir::homePath() + QStringLiteral("/.clamav"))
            .entryList({QStringLiteral("*.cvd"), QStringLiteral("*.cld")},
                       QDir::Files);
    dashboardDefinitions_->setText(!definitions.isEmpty() ||
                                           !userDefinitions.isEmpty()
                                       ? QStringLiteral("Installed")
                                       : QStringLiteral("Check updater"));
  }
  if (dashboardThreats_)
    dashboardThreats_->setText(QString::number(
        settings_.value(QStringLiteral("stats/threats"), 0).toInt()));
  if (lastScanLabel_) {
    const QString time =
        settings_.value(QStringLiteral("lastScan/time")).toString();
    const QString result =
        settings_.value(QStringLiteral("lastScan/result")).toString();
    lastScanLabel_->setText(
        time.isEmpty()
            ? QStringLiteral("No scans yet")
            : QDateTime::fromString(time, Qt::ISODate)
                      .toLocalTime()
                      .toString(QStringLiteral("MMM d, yyyy · h:mm AP")) +
                  QStringLiteral("  —  ") + result);
  }
}

void MainWindow::refreshHistory() {
  if (!historyTable_)
    return;
  const QString filter = historyFilter_ ? historyFilter_->currentText()
                                        : QStringLiteral("Everything");
  const QStringList entries =
      settings_.value(QStringLiteral("history/entries")).toStringList();
  historyTable_->setRowCount(0);
  for (const QString &entry : entries) {
    const QStringList columns = entry.split(QLatin1Char('\t'));
    if (columns.size() != 4)
      continue;
    const QString type = columns.at(1);
    if ((filter == QStringLiteral("Scans") && type != QStringLiteral("Scan")) ||
        (filter == QStringLiteral("Detections") &&
         type != QStringLiteral("Detection")) ||
        (filter == QStringLiteral("Updates") &&
         type != QStringLiteral("Update")))
      continue;
    const int row = historyTable_->rowCount();
    historyTable_->insertRow(row);
    historyTable_->setItem(
        row, 0,
        new QTableWidgetItem(
            QDateTime::fromString(columns.at(0), Qt::ISODate)
                .toLocalTime()
                .toString(QStringLiteral("MMM d, yyyy · h:mm AP"))));
    historyTable_->setItem(row, 1, new QTableWidgetItem(type));
    historyTable_->setItem(row, 2, new QTableWidgetItem(columns.at(2)));
    historyTable_->setItem(row, 3, new QTableWidgetItem(columns.at(3)));
  }
}

void MainWindow::refreshQuarantine() {
  if (!quarantineTable_)
    return;
  quarantineTable_->setRowCount(0);
  const int count =
      settings_.beginReadArray(QStringLiteral("quarantine/items"));
  for (int i = 0; i < count; ++i) {
    settings_.setArrayIndex(i);
    const QString original =
        settings_.value(QStringLiteral("original")).toString();
    const QString stored = settings_.value(QStringLiteral("stored")).toString();
    const QString date = settings_.value(QStringLiteral("date")).toString();
    const int row = quarantineTable_->rowCount();
    quarantineTable_->insertRow(row);
    auto *file = new QTableWidgetItem(original);
    file->setData(Qt::UserRole, stored);
    quarantineTable_->setItem(row, 0, file);
    quarantineTable_->setItem(row, 1, new QTableWidgetItem(date));
    quarantineTable_->setItem(
        row, 2, new QTableWidgetItem(QFileInfo(stored).fileName()));
  }
  settings_.endArray();
}

QVector<QStringList> MainWindow::quarantineEntries() {
  QVector<QStringList> entries;
  const int count =
      settings_.beginReadArray(QStringLiteral("quarantine/items"));
  for (int i = 0; i < count; ++i) {
    settings_.setArrayIndex(i);
    entries.push_back(
        {settings_.value(QStringLiteral("original")).toString(),
         settings_.value(QStringLiteral("stored")).toString(),
         settings_.value(QStringLiteral("date")).toString(),
         settings_.value(QStringLiteral("permissions")).toString()});
  }
  settings_.endArray();
  return entries;
}

void MainWindow::saveQuarantineEntries(const QVector<QStringList> &entries) {
  settings_.beginWriteArray(QStringLiteral("quarantine/items"));
  for (int i = 0; i < entries.size(); ++i) {
    settings_.setArrayIndex(i);
    settings_.setValue(QStringLiteral("original"), entries.at(i).value(0));
    settings_.setValue(QStringLiteral("stored"), entries.at(i).value(1));
    settings_.setValue(QStringLiteral("date"), entries.at(i).value(2));
    settings_.setValue(QStringLiteral("permissions"), entries.at(i).value(3));
  }
  settings_.endArray();
  refreshQuarantine();
}

void MainWindow::quarantineSelectedDetections() {
  QVector<int> selectedRows;
  for (const QModelIndex &index :
       scanResults_->selectionModel()->selectedRows())
    selectedRows.push_back(index.row());
  if (selectedRows.isEmpty()) {
    QMessageBox::information(
        this, QStringLiteral("Select detections"),
        QStringLiteral("Select one or more scan results first."));
    return;
  }
  const QString directory =
      QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) +
      QStringLiteral("/quarantine");
  if (!QDir().mkpath(directory) ||
      !QFile::setPermissions(directory, QFileDevice::ReadOwner |
                                            QFileDevice::WriteOwner |
                                            QFileDevice::ExeOwner)) {
    QMessageBox::critical(
        this, QStringLiteral("Quarantine unavailable"),
        QStringLiteral("Could not create or secure the quarantine directory."));
    return;
  }
  QVector<QStringList> entries = quarantineEntries();
  int moved = 0;
  for (int row : selectedRows) {
    if (scanResults_->item(row, 1)->text() != QStringLiteral("Threat detected"))
      continue;
    const QString source = scanResults_->item(row, 0)->text();
    const int permissions = static_cast<int>(QFileInfo(source).permissions());
    const QString destination = QDir(directory).filePath(
        QUuid::createUuid().toString(QUuid::WithoutBraces) + QLatin1Char('_') +
        QFileInfo(source).fileName());
    if (!moveFile(source, destination)) {
      QMessageBox::warning(this, QStringLiteral("Could not quarantine file"),
                           QStringLiteral("KlamAV could not move %1. Check "
                                          "permissions and filesystem space.")
                               .arg(source));
      continue;
    }
    if (!QFile::setPermissions(destination, QFileDevice::ReadOwner |
                                                QFileDevice::WriteOwner)) {
      QMessageBox::warning(
          this, QStringLiteral("Could not secure quarantined file"),
          QStringLiteral("KlamAV could not restrict file permissions for %1. "
                         "The private quarantine folder still limits access.")
              .arg(source));
    }
    entries.push_back({source, destination,
                       QDateTime::currentDateTime().toString(Qt::ISODate),
                       QString::number(permissions)});
    ++moved;
    addHistory(QStringLiteral("Detection"), source,
               QStringLiteral("Quarantined"));
  }
  saveQuarantineEntries(entries);
  if (moved > 0)
    refreshDashboard();
}

void MainWindow::restoreSelected() {
  const auto rows = quarantineTable_->selectionModel()->selectedRows();
  if (rows.isEmpty()) {
    QMessageBox::information(
        this, QStringLiteral("Select a file"),
        QStringLiteral("Select a quarantined file to restore."));
    return;
  }
  auto entries = quarantineEntries();
  QSet<int> selected;
  for (const QModelIndex &row : rows)
    selected.insert(row.row());
  QVector<QStringList> remaining;
  for (int i = 0; i < entries.size(); ++i) {
    auto entry = entries.at(i);
    if (!selected.contains(i)) {
      remaining.push_back(entry);
      continue;
    }
    QString destination = entry.value(0);
    if (QFileInfo::exists(destination)) {
      const QFileInfo original(destination);
      const QString restoredName =
          original.completeBaseName() + QStringLiteral("_restored") +
          (original.suffix().isEmpty() ? QString()
                                       : QLatin1Char('.') + original.suffix());
      destination = original.dir().filePath(restoredName);
    }
    if (!moveFile(entry.value(1), destination)) {
      QMessageBox::warning(
          this, QStringLiteral("Restore failed"),
          QStringLiteral("Could not restore %1. Check permissions and "
                         "available disk space.")
              .arg(destination));
      remaining.push_back(entry);
      continue;
    }
    if (!entry.value(3).isEmpty() &&
        !QFile::setPermissions(
            destination,
            static_cast<QFileDevice::Permissions>(entry.value(3).toInt()))) {
      QMessageBox::warning(
          this, QStringLiteral("Could not restore file permissions"),
          QStringLiteral("The file was restored, but its original permissions "
                         "could not be reapplied."));
    }
    addHistory(QStringLiteral("Detection"), destination,
               QStringLiteral("Restored from quarantine"));
  }
  saveQuarantineEntries(remaining);
}

void MainWindow::deleteQuarantined(bool all) {
  const auto selectedRows =
      all ? QModelIndexList{}
          : quarantineTable_->selectionModel()->selectedRows();
  if (!all && selectedRows.isEmpty()) {
    QMessageBox::information(this, QStringLiteral("Select a file"),
                             QStringLiteral("Select files to delete."));
    return;
  }
  const QString prompt =
      all ? QStringLiteral("Permanently delete every quarantined file?")
          : QStringLiteral(
                "Permanently delete the selected quarantined files?");
  if (QMessageBox::question(this, QStringLiteral("Delete quarantined files"),
                            prompt, QMessageBox::Yes | QMessageBox::No,
                            QMessageBox::No) != QMessageBox::Yes)
    return;
  auto entries = quarantineEntries();
  QSet<int> selected;
  for (const QModelIndex &row : selectedRows)
    selected.insert(row.row());
  QVector<QStringList> remaining;
  for (int i = 0; i < entries.size(); ++i) {
    const auto &entry = entries.at(i);
    if (!all && !selected.contains(i)) {
      remaining.push_back(entry);
      continue;
    }
    if (QFileInfo::exists(entry.value(1)) && !QFile::remove(entry.value(1))) {
      QMessageBox::warning(
          this, QStringLiteral("Delete failed"),
          QStringLiteral("Could not delete %1. Check permissions.")
              .arg(entry.value(1)));
      remaining.push_back(entry);
    }
  }
  saveQuarantineEntries(remaining);
}

void MainWindow::closeEvent(QCloseEvent *event) {
  if (trayCheck_ && trayCheck_->isChecked() &&
      QSystemTrayIcon::isSystemTrayAvailable()) {
    ensureTrayIcon();
    hide();
    event->ignore();
    return;
  }
  QMainWindow::closeEvent(event);
}
