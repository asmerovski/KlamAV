#include "app_helpers.h"
#include "main_window.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QFileDialog>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTableWidget>
#include <QVBoxLayout>
#include <functional>

using AppHelpers::makeButton;
using AppHelpers::makeCard;
using AppHelpers::quickScanTargets;

MainWindow::MainWindow()
    : settings_(QStringLiteral("KlamAV"), QStringLiteral("KlamAV")) {
  setWindowTitle(QStringLiteral("KlamAV"));
  setWindowIcon(
      QIcon::fromTheme(QStringLiteral("org.klamav.KlamAV"),
                       QIcon(QStringLiteral(":/icons/org.klamav.KlamAV.svg"))));
  setMinimumSize(1080, 720);
  resize(1240, 820);
  buildInterface();
  applyStyle();
  connect(&scheduleTimer_, &QTimer::timeout, this,
          &MainWindow::runScheduledScan);
  scheduleTimer_.start(30000);
  if (settings_.value(QStringLiteral("desktop/tray"), true).toBool() &&
      QSystemTrayIcon::isSystemTrayAvailable())
    ensureTrayIcon();
  if (settings_.value(QStringLiteral("scan/schedule"), 0).toInt() > 0 &&
      settings_.value(QStringLiteral("scan/nextRun")).toString().isEmpty()) {
    const int days =
        settings_.value(QStringLiteral("scan/schedule")).toInt() == 1 ? 1 : 7;
    settings_.setValue(
        QStringLiteral("scan/nextRun"),
        QDateTime::currentDateTime().addDays(days).toString(Qt::ISODate));
  }
  refreshDashboard();
  refreshQuarantine();
  refreshHistory();
}

void MainWindow::scanPaths(const QStringList &paths) {
  if (paths.isEmpty()) {
    QMessageBox::warning(
        this, QStringLiteral("No files selected"),
        QStringLiteral("Choose one or more files or folders to scan."));
    return;
  }
  pages_->setCurrentIndex(1);
  if (scanNavigationButton_)
    scanNavigationButton_->setChecked(true);
  startScan(paths);
}

MainWindow::~MainWindow() {
  if (scanCancellation_)
    scanCancellation_->store(true);
  if (scanWatcher_)
    scanWatcher_->waitForFinished();
}

void MainWindow::buildInterface() {
  auto *root = new QWidget(this);
  root->setObjectName(QStringLiteral("root"));
  auto *outer = new QHBoxLayout(root);
  outer->setContentsMargins(0, 0, 0, 0);
  outer->setSpacing(0);

  auto *sidebar = new QWidget(root);
  sidebar->setObjectName(QStringLiteral("sidebar"));
  sidebar->setFixedWidth(238);
  auto *sideLayout = new QVBoxLayout(sidebar);
  sideLayout->setContentsMargins(18, 24, 18, 20);
  sideLayout->setSpacing(8);

  auto *brand = new QHBoxLayout;
  auto *mark = new QLabel(QStringLiteral("K"), sidebar);
  mark->setObjectName(QStringLiteral("brandMark"));
  mark->setAlignment(Qt::AlignCenter);
  mark->setFixedSize(40, 40);
  auto *brandName = new QLabel(QStringLiteral("KlamAV"), sidebar);
  brandName->setObjectName(QStringLiteral("brandName"));
  brand->addWidget(mark);
  brand->addSpacing(10);
  brand->addWidget(brandName);
  brand->addStretch();
  sideLayout->addLayout(brand);
  sideLayout->addSpacing(28);

  const QStringList navNames{QStringLiteral("Overview"), QStringLiteral("Scan"),
                             QStringLiteral("Quarantine"),
                             QStringLiteral("History"),
                             QStringLiteral("Settings")};
  const QStringList navIcons{QStringLiteral("⌂"), QStringLiteral("⌕"),
                             QStringLiteral("◈"), QStringLiteral("◷"),
                             QStringLiteral("⚙")};
  for (int i = 0; i < navNames.size(); ++i) {
    auto *nav = new QPushButton(
        navIcons.at(i) + QStringLiteral("   ") + navNames.at(i), sidebar);
    nav->setObjectName(QStringLiteral("navButton"));
    nav->setCheckable(true);
    nav->setCursor(Qt::PointingHandCursor);
    nav->setMinimumHeight(44);
    sideLayout->addWidget(nav);
    if (i == 1)
      scanNavigationButton_ = nav;
    connect(nav, &QPushButton::clicked, this, [this, i, nav] {
      pages_->setCurrentIndex(i);
      for (auto *button :
           findChildren<QPushButton *>(QStringLiteral("navButton")))
        button->setChecked(button == nav);
      if (i == 0)
        refreshDashboard();
      else if (i == 2)
        refreshQuarantine();
      else if (i == 3)
        refreshHistory();
    });
    if (i == 0)
      nav->setChecked(true);
  }

  sideLayout->addStretch();
  auto *sideNote = new QLabel(
      QStringLiteral("CLAMAV PROTECTION\nLocal antivirus controls"), sidebar);
  sideNote->setObjectName(QStringLiteral("sideNote"));
  sideLayout->addWidget(sideNote);
  auto *aboutButton =
      makeButton(QStringLiteral("About KlamAV"), false, sidebar);
  aboutButton->setObjectName(QStringLiteral("aboutButton"));
  sideLayout->addWidget(aboutButton);
  connect(aboutButton, &QPushButton::clicked, this, [this] {
    QMessageBox::about(
        this, QStringLiteral("About KlamAV"),
        QStringLiteral("<h2>KlamAV %1</h2>"
                       "<p>A KDE-friendly ClamAV antivirus frontend.</p>"
                       "<p>Licensed under the GNU General Public License, "
                       "version 3 or later.</p>")
            .arg(QCoreApplication::applicationVersion()));
  });
  outer->addWidget(sidebar);

  auto *mainArea = new QWidget(root);
  auto *mainLayout = new QVBoxLayout(mainArea);
  mainLayout->setContentsMargins(30, 22, 30, 24);
  mainLayout->setSpacing(18);

  auto *header = new QHBoxLayout;
  auto *pageTitle = new QLabel(QStringLiteral("Antivirus"), mainArea);
  pageTitle->setObjectName(QStringLiteral("pageTitle"));
  headerStatus_ = new QLabel(mainArea);
  headerStatus_->setObjectName(QStringLiteral("statusPill"));
  header->addWidget(pageTitle);
  header->addStretch();
  header->addWidget(headerStatus_);
  mainLayout->addLayout(header);

  pages_ = new QStackedWidget(mainArea);
  pages_->addWidget(buildDashboard());
  pages_->addWidget(buildScanPage());
  pages_->addWidget(buildQuarantinePage());
  pages_->addWidget(buildHistoryPage());
  pages_->addWidget(buildSettingsPage());
  mainLayout->addWidget(pages_, 1);
  outer->addWidget(mainArea, 1);
  setCentralWidget(root);
}

QWidget *MainWindow::pageContainer(const QString &title,
                                   const QString &description) {
  auto *page = new QWidget;
  auto *layout = new QVBoxLayout(page);
  layout->setContentsMargins(0, 0, 0, 0);
  layout->setSpacing(18);
  auto *heading = new QLabel(title, page);
  heading->setObjectName(QStringLiteral("sectionTitle"));
  auto *subheading = new QLabel(description, page);
  subheading->setObjectName(QStringLiteral("muted"));
  subheading->setWordWrap(true);
  layout->addWidget(heading);
  layout->addWidget(subheading);
  return page;
}

QWidget *MainWindow::buildDashboard() {
  auto *page =
      pageContainer(QStringLiteral("Good afternoon"),
                    QStringLiteral("Your device security at a glance."));
  auto *layout = qobject_cast<QVBoxLayout *>(page->layout());

  auto *hero =
      makeCard(QStringLiteral("Your protection, in one place"),
               QStringLiteral("Keep ClamAV definitions up to date and run "
                              "regular scans to help keep your files safe."),
               page);
  auto *heroLayout = qobject_cast<QVBoxLayout *>(hero->layout());
  auto *heroRow = new QHBoxLayout;
  dashboardHeroStatus_ =
      new QLabel(QStringLiteral("Checking protection…"), hero);
  dashboardHeroStatus_->setObjectName(QStringLiteral("heroStatus"));
  auto *scanNow = makeButton(QStringLiteral("Start quick scan"), true, hero);
  heroRow->addWidget(dashboardHeroStatus_);
  heroRow->addStretch();
  heroRow->addWidget(scanNow);
  heroLayout->addLayout(heroRow);
  connect(scanNow, &QPushButton::clicked, this, [this] {
    pages_->setCurrentIndex(1);
    startScan(quickScanTargets());
  });
  layout->addWidget(hero);

  auto *stats = new QHBoxLayout;
  stats->setSpacing(14);
  auto addStat = [this, stats, page](const QString &label, QLabel **value) {
    auto *card = makeCard(label, QString(), page);
    *value = new QLabel(QStringLiteral("—"), card);
    (*value)->setObjectName(QStringLiteral("statValue"));
    qobject_cast<QVBoxLayout *>(card->layout())->addWidget(*value);
    stats->addWidget(card, 1);
  };
  addStat(QStringLiteral("Protection status"), &dashboardProtection_);
  addStat(QStringLiteral("Virus definitions"), &dashboardDefinitions_);
  addStat(QStringLiteral("Threats detected"), &dashboardThreats_);
  layout->addLayout(stats);

  auto *quickActions =
      makeCard(QStringLiteral("Quick actions"),
               QStringLiteral("Common tasks, ready when you are."), page);
  auto *actionsLayout = qobject_cast<QVBoxLayout *>(quickActions->layout());
  auto *actions = new QHBoxLayout;
  auto *quick = makeButton(QStringLiteral("Quick scan"), false, quickActions);
  auto *update =
      makeButton(QStringLiteral("Update definitions"), false, quickActions);
  auto *full = makeButton(QStringLiteral("Full scan"), false, quickActions);
  actions->addWidget(quick);
  actions->addWidget(update);
  actions->addWidget(full);
  actionsLayout->addLayout(actions);
  connect(quick, &QPushButton::clicked, this, [this] {
    pages_->setCurrentIndex(1);
    startScan(quickScanTargets());
  });
  connect(full, &QPushButton::clicked, this, [this] {
    pages_->setCurrentIndex(1);
    startScan({QStringLiteral("/")}, true);
  });
  connect(update, &QPushButton::clicked, this, &MainWindow::updateDefinitions);
  layout->addWidget(quickActions);

  auto *last = makeCard(QStringLiteral("Last scan"), QString(), page);
  lastScanLabel_ = new QLabel(QStringLiteral("No scans yet"), last);
  lastScanLabel_->setObjectName(QStringLiteral("lastScan"));
  qobject_cast<QVBoxLayout *>(last->layout())->addWidget(lastScanLabel_);
  layout->addWidget(last);
  layout->addStretch();
  return page;
}

QWidget *MainWindow::buildScanPage() {
  auto *page =
      pageContainer(QStringLiteral("Scan your files"),
                    QStringLiteral("Choose a scan type. Scans run in the "
                                   "background so you can keep using KlamAV."));
  auto *layout = qobject_cast<QVBoxLayout *>(page->layout());

  auto *choices = new QHBoxLayout;
  const auto addScanCard = [this, choices,
                            page](const QString &title, const QString &text,
                                  const QString &action,
                                  std::function<void()> callback) {
    auto *card = makeCard(title, text, page);
    auto *button = makeButton(action, true, card);
    qobject_cast<QVBoxLayout *>(card->layout())->addStretch();
    qobject_cast<QVBoxLayout *>(card->layout())->addWidget(button);
    choices->addWidget(card, 1);
    connect(button, &QPushButton::clicked, this, std::move(callback));
  };
  addScanCard(QStringLiteral("Quick scan"),
              QStringLiteral("Check your common personal folders."),
              QStringLiteral("Scan common folders"),
              [this] { startScan(quickScanTargets()); });
  addScanCard(
      QStringLiteral("Full scan"),
      QStringLiteral(
          "Scan mounted local files, excluding virtual system filesystems."),
      QStringLiteral("Scan the system"),
      [this] { startScan({QStringLiteral("/")}, true); });
  addScanCard(
      QStringLiteral("Custom scan"),
      QStringLiteral("Choose one or more files or folders to inspect."),
      QStringLiteral("Choose locations"), [this] {
        QMessageBox choice(this);
        choice.setWindowTitle(QStringLiteral("Choose scan locations"));
        choice.setText(
            QStringLiteral("Would you like to scan files or a folder?"));
        auto *filesButton = choice.addButton(QStringLiteral("Choose files"),
                                             QMessageBox::AcceptRole);
        auto *folderButton = choice.addButton(QStringLiteral("Choose folder"),
                                              QMessageBox::ActionRole);
        choice.addButton(QMessageBox::Cancel);
        choice.exec();
        if (choice.clickedButton() == filesButton) {
          const QStringList paths = QFileDialog::getOpenFileNames(
              this, QStringLiteral("Choose files to scan"), QDir::homePath());
          if (!paths.isEmpty())
            startScan(paths);
        } else if (choice.clickedButton() == folderButton) {
          const QString path = QFileDialog::getExistingDirectory(
              this, QStringLiteral("Choose a folder to scan"),
              QDir::homePath());
          if (!path.isEmpty())
            startScan({path});
        }
      });
  layout->addLayout(choices);

  auto *progressCard =
      makeCard(QStringLiteral("Scan progress"),
               QStringLiteral("Threats are listed below when found."), page);
  auto *progressLayout = qobject_cast<QVBoxLayout *>(progressCard->layout());
  scanStatus_ = new QLabel(QStringLiteral("Ready to scan"), progressCard);
  scanStatus_->setObjectName(QStringLiteral("muted"));
  scanProgress_ = new QProgressBar(progressCard);
  scanProgress_->setRange(0, 100);
  scanProgress_->setValue(0);
  auto *progressHeader = new QHBoxLayout;
  progressHeader->addWidget(scanStatus_);
  progressHeader->addStretch();
  stopScanButton_ =
      makeButton(QStringLiteral("Stop scan"), false, progressCard);
  stopScanButton_->setVisible(false);
  progressHeader->addWidget(stopScanButton_);
  progressLayout->addLayout(progressHeader);
  progressLayout->addWidget(scanProgress_);
  connect(stopScanButton_, &QPushButton::clicked, this, &MainWindow::stopScan);
  layout->addWidget(progressCard);

  auto *resultsCard = makeCard(QStringLiteral("Scan results"), QString(), page);
  auto *resultsLayout = qobject_cast<QVBoxLayout *>(resultsCard->layout());
  scanResults_ = new QTableWidget(0, 3, resultsCard);
  scanResults_->setHorizontalHeaderLabels({QStringLiteral("File"),
                                           QStringLiteral("Result"),
                                           QStringLiteral("Details")});
  setupTable(scanResults_);
  resultsLayout->addWidget(scanResults_);
  auto *quarantine = makeButton(
      QStringLiteral("Quarantine selected detections"), false, resultsCard);
  resultsLayout->addWidget(quarantine, 0, Qt::AlignRight);
  connect(quarantine, &QPushButton::clicked, this,
          &MainWindow::quarantineSelectedDetections);
  layout->addWidget(resultsCard, 1);
  return page;
}

QWidget *MainWindow::buildQuarantinePage() {
  auto *page = pageContainer(
      QStringLiteral("Quarantine"),
      QStringLiteral("Isolated files are stored in your local application data "
                     "folder. Review them before restoring or deleting."));
  auto *layout = qobject_cast<QVBoxLayout *>(page->layout());
  auto *card = makeCard(QStringLiteral("Isolated files"), QString(), page);
  auto *cardLayout = qobject_cast<QVBoxLayout *>(card->layout());
  quarantineTable_ = new QTableWidget(0, 3, card);
  quarantineTable_->setHorizontalHeaderLabels({QStringLiteral("Original file"),
                                               QStringLiteral("Date added"),
                                               QStringLiteral("Stored as")});
  setupTable(quarantineTable_);
  cardLayout->addWidget(quarantineTable_);
  auto *actions = new QHBoxLayout;
  auto *restore = makeButton(QStringLiteral("Restore selected"), false, card);
  auto *remove = makeButton(QStringLiteral("Delete selected"), false, card);
  auto *removeAll = makeButton(QStringLiteral("Delete all"), false, card);
  actions->addWidget(restore);
  actions->addWidget(remove);
  actions->addStretch();
  actions->addWidget(removeAll);
  cardLayout->addLayout(actions);
  connect(restore, &QPushButton::clicked, this, &MainWindow::restoreSelected);
  connect(remove, &QPushButton::clicked, this,
          [this] { deleteQuarantined(false); });
  connect(removeAll, &QPushButton::clicked, this,
          [this] { deleteQuarantined(true); });
  layout->addWidget(card, 1);
  return page;
}

QWidget *MainWindow::buildHistoryPage() {
  auto *page = pageContainer(
      QStringLiteral("Activity history"),
      QStringLiteral(
          "A local log of scans, detections, and definition updates."));
  auto *layout = qobject_cast<QVBoxLayout *>(page->layout());
  auto *card = makeCard(QStringLiteral("Recent activity"), QString(), page);
  auto *cardLayout = qobject_cast<QVBoxLayout *>(card->layout());
  auto *filters = new QHBoxLayout;
  filters->addWidget(new QLabel(QStringLiteral("Show:"), card));
  historyFilter_ = new QComboBox(card);
  historyFilter_->addItems(
      {QStringLiteral("Everything"), QStringLiteral("Scans"),
       QStringLiteral("Detections"), QStringLiteral("Updates")});
  filters->addWidget(historyFilter_);
  filters->addStretch();
  cardLayout->addLayout(filters);
  historyTable_ = new QTableWidget(0, 4, card);
  historyTable_->setHorizontalHeaderLabels(
      {QStringLiteral("Date and time"), QStringLiteral("Activity"),
       QStringLiteral("Target"), QStringLiteral("Result")});
  setupTable(historyTable_);
  cardLayout->addWidget(historyTable_);
  connect(historyFilter_, &QComboBox::currentTextChanged, this,
          &MainWindow::refreshHistory);
  layout->addWidget(card, 1);
  return page;
}

QWidget *MainWindow::buildSettingsPage() {
  auto *page = pageContainer(
      QStringLiteral("Settings"),
      QStringLiteral("Tune scanning and notifications. Daemon-level features "
                     "may require administrator configuration."));
  auto *layout = qobject_cast<QVBoxLayout *>(page->layout());
  auto *scroll = new QScrollArea(page);
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  auto *content = new QWidget(scroll);
  auto *contentLayout = new QVBoxLayout(content);
  contentLayout->setContentsMargins(0, 0, 8, 0);
  contentLayout->setSpacing(14);

  auto *scanCard = makeCard(
      QStringLiteral("Scanning"),
      QStringLiteral("Preferences used by scans started from this app."),
      content);
  auto *scanLayout = qobject_cast<QVBoxLayout *>(scanCard->layout());
  auto *sizeRow = new QHBoxLayout;
  sizeRow->addWidget(new QLabel(QStringLiteral("Maximum file size"), scanCard));
  sizeRow->addStretch();
  maxFileSize_ = new QSpinBox(scanCard);
  maxFileSize_->setRange(1, 2048);
  maxFileSize_->setSuffix(QStringLiteral(" MB"));
  sizeRow->addWidget(maxFileSize_);
  scanLayout->addLayout(sizeRow);
  archiveCheck_ = new QCheckBox(
      QStringLiteral(
          "Scan inside archives (when supported by the ClamAV daemon)"),
      scanCard);
  symlinkCheck_ =
      new QCheckBox(QStringLiteral("Follow symbolic links"), scanCard);
  recursiveCheck_ =
      new QCheckBox(QStringLiteral("Scan folders recursively"), scanCard);
  auto *intensityRow = new QHBoxLayout;
  intensityRow->addWidget(new QLabel(QStringLiteral("CPU usage"), scanCard));
  intensityRow->addStretch();
  intensityCombo_ = new QComboBox(scanCard);
  intensityCombo_->addItems({QStringLiteral("Quiet · 1 worker"),
                             QStringLiteral("Balanced · 2 workers"),
                             QStringLiteral("Fast · up to 4 workers"),
                             QStringLiteral("Aggressive · all cores")});
  intensityCombo_->setToolTip(QStringLiteral(
      "Limits concurrent file scans. The default is two workers."));
  intensityRow->addWidget(intensityCombo_);
  scanLayout->addWidget(archiveCheck_);
  scanLayout->addWidget(symlinkCheck_);
  scanLayout->addWidget(recursiveCheck_);
  scanLayout->addLayout(intensityRow);
  contentLayout->addWidget(scanCard);

  auto *experienceCard =
      makeCard(QStringLiteral("Desktop experience"), QString(), content);
  auto *experienceLayout =
      qobject_cast<QVBoxLayout *>(experienceCard->layout());
  notificationCheck_ = new QCheckBox(
      QStringLiteral("Show desktop notifications (via system tray)"),
      experienceCard);
  startupCheck_ = new QCheckBox(QStringLiteral("Start KlamAV when I log in"),
                                experienceCard);
  trayCheck_ = new QCheckBox(QStringLiteral("Show an icon in the system tray"),
                             experienceCard);
  experienceLayout->addWidget(notificationCheck_);
  experienceLayout->addWidget(startupCheck_);
  experienceLayout->addWidget(trayCheck_);
  contentLayout->addWidget(experienceCard);

  auto *protectionCard = makeCard(
      QStringLiteral("Protection and schedule"),
      QStringLiteral("Scheduled scans run while KlamAV is open. Real-time "
                     "enforcement is not activated by this build."),
      content);
  auto *protectionLayout =
      qobject_cast<QVBoxLayout *>(protectionCard->layout());
  realtimeCheck_ = new QCheckBox(
      QStringLiteral("Enable real-time protection preference"), protectionCard);
  scheduleCombo_ = new QComboBox(protectionCard);
  scheduleCombo_->addItems({QStringLiteral("No scheduled scan"),
                            QStringLiteral("Daily"), QStringLiteral("Weekly")});
  auto *scheduleRow = new QHBoxLayout;
  scheduleRow->addWidget(
      new QLabel(QStringLiteral("Scan schedule"), protectionCard));
  scheduleRow->addStretch();
  scheduleRow->addWidget(scheduleCombo_);
  protectionLayout->addWidget(realtimeCheck_);
  protectionLayout->addLayout(scheduleRow);
  contentLayout->addWidget(protectionCard);

  auto *saveRow = new QHBoxLayout;
  saveRow->addStretch();
  auto *save = makeButton(QStringLiteral("Save settings"), true, content);
  saveRow->addWidget(save);
  contentLayout->addLayout(saveRow);
  contentLayout->addStretch();
  scroll->setWidget(content);
  layout->addWidget(scroll, 1);

  maxFileSize_->setValue(
      settings_.value(QStringLiteral("scan/maxFileSizeMb"), 64).toInt());
  archiveCheck_->setChecked(
      settings_.value(QStringLiteral("scan/archives"), true).toBool());
  symlinkCheck_->setChecked(
      settings_.value(QStringLiteral("scan/followSymlinks"), false).toBool());
  recursiveCheck_->setChecked(
      settings_.value(QStringLiteral("scan/recursive"), true).toBool());
  intensityCombo_->setCurrentIndex(
      settings_.value(QStringLiteral("scan/intensity"), 1).toInt());
  notificationCheck_->setChecked(
      settings_.value(QStringLiteral("desktop/notifications"), true).toBool());
  startupCheck_->setChecked(
      settings_.value(QStringLiteral("desktop/startup"), false).toBool());
  trayCheck_->setChecked(
      settings_.value(QStringLiteral("desktop/tray"), true).toBool());
  realtimeCheck_->setChecked(
      settings_.value(QStringLiteral("protection/realtime"), false).toBool());
  scheduleCombo_->setCurrentIndex(
      settings_.value(QStringLiteral("scan/schedule"), 0).toInt());
  connect(save, &QPushButton::clicked, this, &MainWindow::saveSettings);
  return page;
}

void MainWindow::setupTable(QTableWidget *table) {
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table->setSelectionBehavior(QAbstractItemView::SelectRows);
  table->setSelectionMode(QAbstractItemView::ExtendedSelection);
  table->setAlternatingRowColors(false);
  table->verticalHeader()->hide();
  table->horizontalHeader()->setStretchLastSection(true);
  table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  table->setMinimumHeight(180);
}

void MainWindow::applyStyle() {
  setStyleSheet(QStringLiteral(R"(
        QWidget#root, QWidget { background: #f5f7fb; color: #17233c; font-family: "Noto Sans", "Inter", sans-serif; font-size: 13px; }
        QLabel { background: transparent; }
        QWidget#sidebar { background: #111d35; color: #f5f7ff; }
        QWidget#sidebar QLabel { background: transparent; }
        QLabel#brandMark { background: #54d6a1; color: #0c3025; border-radius: 12px; font-size: 22px; font-weight: 800; }
        QLabel#brandName { color: #fff; font-size: 19px; font-weight: 700; }
        QLabel#sideNote { color: #8492ad; font-size: 10px; letter-spacing: 1px; }
        QPushButton#navButton { text-align: left; padding: 0 14px; border: 0; border-radius: 10px; color: #aab6cb; background: transparent; font-weight: 600; }
        QPushButton#navButton:hover { background: #1c2b49; color: white; }
        QPushButton#navButton:checked { background: #243653; color: #66e0af; }
        QLabel#pageTitle { font-size: 20px; font-weight: 700; color: #17233c; }
        QLabel#sectionTitle { font-size: 25px; font-weight: 750; color: #14213b; }
        QLabel#muted { color: #71809a; }
        QLabel#cardTitle { color: #182743; font-size: 15px; font-weight: 700; }
        QLabel#heroStatus { color: #14845c; font-size: 17px; font-weight: 700; }
        QLabel#statValue { color: #192845; font-size: 24px; font-weight: 750; }
        QLabel#lastScan { color: #52617a; font-size: 14px; }
        QLabel#statusPill { background: #e0f6ec; color: #18835b; border-radius: 12px; padding: 7px 12px; font-weight: 700; }
        QWidget#card { background: #fff; border: 1px solid #e8edf4; border-radius: 14px; }
        QPushButton#button, QPushButton#primaryButton { border-radius: 9px; padding: 0 16px; font-weight: 650; }
        QPushButton#button { background: #f3f6fa; border: 1px solid #e1e7f0; color: #263650; }
        QPushButton#button:hover { background: #e8eef6; }
        QPushButton#aboutButton { background: #1b2b48; border: 1px solid #354766; color: #e2eaf5; border-radius: 9px; padding: 0 16px; font-weight: 650; }
        QPushButton#aboutButton:hover { background: #263958; }
        QPushButton#primaryButton { background: #176f56; color: white; border: 1px solid #176f56; }
        QPushButton#primaryButton:hover { background: #0f5d47; }
        QTableWidget { background: white; border: 1px solid #e8edf4; border-radius: 9px; gridline-color: #edf1f6; selection-background-color: #e2f5ed; selection-color: #173c30; }
        QHeaderView::section { background: #f7f9fc; color: #6a7890; border: 0; border-bottom: 1px solid #e7edf4; padding: 10px 8px; font-weight: 650; }
        QProgressBar { background: #edf2f6; border: 0; border-radius: 5px; height: 10px; text-align: center; }
        QProgressBar::chunk { background: #24ad7a; border-radius: 5px; }
        QComboBox, QSpinBox { background: white; border: 1px solid #dfe6ef; border-radius: 8px; padding: 7px 10px; min-width: 130px; }
        QCheckBox { spacing: 9px; color: #293852; padding: 5px 0; }
        QCheckBox::indicator { width: 17px; height: 17px; }
        QScrollArea { background: transparent; }
    )"));
}
