#pragma once

#include "scan_types.h"

#include <QFutureWatcher>
#include <QMainWindow>
#include <QPointer>
#include <QSettings>
#include <QStringList>
#include <QTimer>
#include <QVector>
#include <atomic>
#include <memory>

class QCheckBox;
class QCloseEvent;
class QComboBox;
class QLabel;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QStackedWidget;
class QSystemTrayIcon;
class QTableWidget;
class QWidget;

class MainWindow final : public QMainWindow {
  Q_OBJECT

public:
  MainWindow();
  ~MainWindow() override;
  void scanPaths(const QStringList &paths);

protected:
  void closeEvent(QCloseEvent *event) override;

private:
  QSettings settings_;
  QStackedWidget *pages_ = nullptr;
  QLabel *headerStatus_ = nullptr;
  QLabel *dashboardHeroStatus_ = nullptr;
  QLabel *dashboardProtection_ = nullptr;
  QLabel *dashboardDefinitions_ = nullptr;
  QLabel *dashboardThreats_ = nullptr;
  QLabel *lastScanLabel_ = nullptr;
  QLabel *scanStatus_ = nullptr;
  QProgressBar *scanProgress_ = nullptr;
  QPushButton *stopScanButton_ = nullptr;
  QPushButton *scanNavigationButton_ = nullptr;
  QTableWidget *scanResults_ = nullptr;
  QTableWidget *quarantineTable_ = nullptr;
  QTableWidget *historyTable_ = nullptr;
  QComboBox *historyFilter_ = nullptr;
  QComboBox *intensityCombo_ = nullptr;
  QSpinBox *maxFileSize_ = nullptr;
  QCheckBox *archiveCheck_ = nullptr;
  QCheckBox *symlinkCheck_ = nullptr;
  QCheckBox *recursiveCheck_ = nullptr;
  QCheckBox *notificationCheck_ = nullptr;
  QCheckBox *startupCheck_ = nullptr;
  QCheckBox *trayCheck_ = nullptr;
  QCheckBox *realtimeCheck_ = nullptr;
  QComboBox *scheduleCombo_ = nullptr;
  QPointer<QFutureWatcher<ScanSummary>> scanWatcher_;
  std::shared_ptr<std::atomic_bool> scanCancellation_;
  bool scanActive_ = false;
  QSystemTrayIcon *trayIcon_ = nullptr;
  QTimer scheduleTimer_;

  void buildInterface();
  QWidget *pageContainer(const QString &title, const QString &description);
  QWidget *buildDashboard();
  QWidget *buildScanPage();
  QWidget *buildQuarantinePage();
  QWidget *buildHistoryPage();
  QWidget *buildSettingsPage();
  void setupTable(QTableWidget *table);
  void applyStyle();

  int workerLimit() const;
  bool daemonAvailable() const;
  void stopScan();
  void startScan(const QStringList &targets, bool fullScan = false);
  void updateDefinitions();
  void runScheduledScan();

  void saveSettings();
  void saveAutostartEntry(bool enabled);
  void ensureTrayIcon();
  void addHistory(const QString &type, const QString &target,
                  const QString &result);
  void refreshDashboard();
  void refreshHistory();
  void refreshQuarantine();
  QVector<QStringList> quarantineEntries();
  void saveQuarantineEntries(const QVector<QStringList> &entries);
  void quarantineSelectedDetections();
  void restoreSelected();
  void deleteQuarantined(bool all);
};
