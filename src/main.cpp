#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QCloseEvent>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileDialog>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QLabel>
#include <QMainWindow>
#include <QMessageBox>
#include <QProcess>
#include <QProgressBar>
#include <QPushButton>
#include <QPointer>
#include <QScrollArea>
#include <QSaveFile>
#include <QSet>
#include <QSettings>
#include <QSpinBox>
#include <QStandardPaths>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTableWidget>
#include <QThreadPool>
#include <QThread>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMenu>
#include <QAction>
#include <QCoreApplication>
#include <QApplication>
#include <QtConcurrent/QtConcurrent>
#include <atomic>
#include <functional>

namespace {

const QString AppName = QStringLiteral("KlamAV");

struct FileResult {
    QString path;
    QString status;
    QString detail;
    bool infected = false;
};

struct ScanSummary {
    QString target;
    QVector<FileResult> results;
    int infected = 0;
    int errors = 0;
};

QWidget *makeCard(const QString &title, const QString &subtitle, QWidget *parent = nullptr)
{
    auto *card = new QWidget(parent);
    card->setObjectName(QStringLiteral("card"));
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(20, 18, 20, 18);
    layout->setSpacing(8);
    auto *heading = new QLabel(title, card);
    heading->setObjectName(QStringLiteral("cardTitle"));
    layout->addWidget(heading);
    if (!subtitle.isEmpty()) {
        auto *description = new QLabel(subtitle, card);
        description->setObjectName(QStringLiteral("muted"));
        description->setWordWrap(true);
        layout->addWidget(description);
    }
    return card;
}

QPushButton *makeButton(const QString &text, bool primary = false, QWidget *parent = nullptr)
{
    auto *button = new QPushButton(text, parent);
    button->setObjectName(primary ? QStringLiteral("primaryButton") : QStringLiteral("button"));
    button->setCursor(Qt::PointingHandCursor);
    button->setMinimumHeight(40);
    return button;
}

QStringList quickScanTargets()
{
    const QString home = QDir::homePath();
    QStringList targets;
    for (const QString &folder : {QStringLiteral("Downloads"), QStringLiteral("Desktop"),
                                  QStringLiteral("Documents")}) {
        const QString path = QDir(home).filePath(folder);
        if (QFileInfo(path).isDir())
            targets.push_back(path);
    }
    if (targets.isEmpty())
        targets.push_back(home);
    return targets;
}

QString displayTargets(const QStringList &targets)
{
    return targets.join(QStringLiteral(", "));
}

bool moveFile(const QString &source, const QString &destination)
{
    if (QFile::rename(source, destination))
        return true;
    if (!QFile::copy(source, destination))
        return false;
    if (QFile::remove(source))
        return true;
    QFile::remove(destination);
    return false;
}

} // namespace

class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    MainWindow()
        : settings_(QStringLiteral("KlamAV"), QStringLiteral("KlamAV"))
    {
        setWindowTitle(QStringLiteral("KlamAV"));
        setMinimumSize(1080, 720);
        resize(1240, 820);
        buildInterface();
        applyStyle();
        connect(&scheduleTimer_, &QTimer::timeout, this, &MainWindow::runScheduledScan);
        scheduleTimer_.start(30000);
        if (settings_.value(QStringLiteral("desktop/tray"), true).toBool()
            && QSystemTrayIcon::isSystemTrayAvailable())
            ensureTrayIcon();
        if (settings_.value(QStringLiteral("scan/schedule"), 0).toInt() > 0
            && settings_.value(QStringLiteral("scan/nextRun")).toString().isEmpty()) {
            const int days = settings_.value(QStringLiteral("scan/schedule")).toInt() == 1 ? 1 : 7;
            settings_.setValue(QStringLiteral("scan/nextRun"), QDateTime::currentDateTime().addDays(days).toString(Qt::ISODate));
        }
        refreshDashboard();
        refreshQuarantine();
        refreshHistory();
    }

    ~MainWindow() override
    {
        if (scanWatcher_)
            scanWatcher_->waitForFinished();
    }

private:
    QSettings settings_;
    QWidget *root_ = nullptr;
    QStackedWidget *pages_ = nullptr;
    QLabel *headerStatus_ = nullptr;
    QLabel *dashboardHeroStatus_ = nullptr;
    QLabel *dashboardProtection_ = nullptr;
    QLabel *dashboardDefinitions_ = nullptr;
    QLabel *dashboardThreats_ = nullptr;
    QLabel *lastScanLabel_ = nullptr;
    QLabel *scanStatus_ = nullptr;
    QProgressBar *scanProgress_ = nullptr;
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
    QFutureWatcher<ScanSummary> *scanWatcher_ = nullptr;
    QSystemTrayIcon *trayIcon_ = nullptr;
    QTimer scheduleTimer_;

    void buildInterface()
    {
        root_ = new QWidget(this);
        root_->setObjectName(QStringLiteral("root"));
        auto *outer = new QHBoxLayout(root_);
        outer->setContentsMargins(0, 0, 0, 0);
        outer->setSpacing(0);

        auto *sidebar = new QWidget(root_);
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
                                   QStringLiteral("Quarantine"), QStringLiteral("History"),
                                   QStringLiteral("Settings")};
        const QStringList navIcons{QStringLiteral("⌂"), QStringLiteral("⌕"),
                                   QStringLiteral("◈"), QStringLiteral("◷"),
                                   QStringLiteral("⚙")};
        for (int i = 0; i < navNames.size(); ++i) {
            auto *nav = new QPushButton(navIcons.at(i) + QStringLiteral("   ") + navNames.at(i), sidebar);
            nav->setObjectName(QStringLiteral("navButton"));
            nav->setCheckable(true);
            nav->setCursor(Qt::PointingHandCursor);
            nav->setMinimumHeight(44);
            sideLayout->addWidget(nav);
            connect(nav, &QPushButton::clicked, this, [this, i, nav] {
                pages_->setCurrentIndex(i);
                for (auto *button : findChildren<QPushButton *>(QStringLiteral("navButton")))
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
        auto *sideNote = new QLabel(QStringLiteral("CLAMAV PROTECTION\nLocal antivirus controls"), sidebar);
        sideNote->setObjectName(QStringLiteral("sideNote"));
        sideLayout->addWidget(sideNote);
        outer->addWidget(sidebar);

        auto *mainArea = new QWidget(root_);
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
        setCentralWidget(root_);
    }

    QWidget *pageContainer(const QString &title, const QString &description)
    {
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

    QWidget *buildDashboard()
    {
        auto *page = pageContainer(QStringLiteral("Good afternoon"),
                                   QStringLiteral("Your device security at a glance."));
        auto *layout = qobject_cast<QVBoxLayout *>(page->layout());

        auto *hero = makeCard(QStringLiteral("Your protection, in one place"),
                              QStringLiteral("Keep ClamAV definitions up to date and run regular scans to help keep your files safe."),
                              page);
        auto *heroLayout = qobject_cast<QVBoxLayout *>(hero->layout());
        auto *heroRow = new QHBoxLayout;
        dashboardHeroStatus_ = new QLabel(QStringLiteral("Checking protection…"), hero);
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

        auto *quickActions = makeCard(QStringLiteral("Quick actions"),
                                      QStringLiteral("Common tasks, ready when you are."), page);
        auto *actionsLayout = qobject_cast<QVBoxLayout *>(quickActions->layout());
        auto *actions = new QHBoxLayout;
        auto *quick = makeButton(QStringLiteral("Quick scan"), false, quickActions);
        auto *update = makeButton(QStringLiteral("Update definitions"), false, quickActions);
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

    QWidget *buildScanPage()
    {
        auto *page = pageContainer(QStringLiteral("Scan your files"),
                                   QStringLiteral("Choose a scan type. Scans run in the background so you can keep using KlamAV."));
        auto *layout = qobject_cast<QVBoxLayout *>(page->layout());

        auto *choices = new QHBoxLayout;
        const auto addScanCard = [this, choices, page](const QString &title, const QString &text,
                                                       const QString &action, std::function<void()> callback) {
            auto *card = makeCard(title, text, page);
            auto *button = makeButton(action, true, card);
            qobject_cast<QVBoxLayout *>(card->layout())->addStretch();
            qobject_cast<QVBoxLayout *>(card->layout())->addWidget(button);
            choices->addWidget(card, 1);
            connect(button, &QPushButton::clicked, this, std::move(callback));
        };
        addScanCard(QStringLiteral("Quick scan"), QStringLiteral("Check your common personal folders."),
                    QStringLiteral("Scan common folders"), [this] { startScan(quickScanTargets()); });
        addScanCard(QStringLiteral("Full scan"), QStringLiteral("Scan mounted local files, excluding virtual system filesystems."),
                    QStringLiteral("Scan the system"), [this] { startScan({QStringLiteral("/")}, true); });
        addScanCard(QStringLiteral("Custom scan"), QStringLiteral("Choose one or more files or folders to inspect."),
                    QStringLiteral("Choose locations"), [this] {
                        QMessageBox choice(this);
                        choice.setWindowTitle(QStringLiteral("Choose scan locations"));
                        choice.setText(QStringLiteral("Would you like to scan files or a folder?"));
                        auto *filesButton = choice.addButton(QStringLiteral("Choose files"), QMessageBox::AcceptRole);
                        auto *folderButton = choice.addButton(QStringLiteral("Choose folder"), QMessageBox::ActionRole);
                        choice.addButton(QMessageBox::Cancel);
                        choice.exec();
                        if (choice.clickedButton() == filesButton) {
                            const QStringList paths = QFileDialog::getOpenFileNames(this, QStringLiteral("Choose files to scan"),
                                                                                   QDir::homePath());
                            if (!paths.isEmpty())
                                startScan(paths);
                        } else if (choice.clickedButton() == folderButton) {
                            const QString path = QFileDialog::getExistingDirectory(this, QStringLiteral("Choose a folder to scan"),
                                                                                   QDir::homePath());
                            if (!path.isEmpty())
                                startScan({path});
                        }
                    });
        layout->addLayout(choices);

        auto *progressCard = makeCard(QStringLiteral("Scan progress"), QStringLiteral("Threats are listed below when found."), page);
        auto *progressLayout = qobject_cast<QVBoxLayout *>(progressCard->layout());
        scanStatus_ = new QLabel(QStringLiteral("Ready to scan"), progressCard);
        scanStatus_->setObjectName(QStringLiteral("muted"));
        scanProgress_ = new QProgressBar(progressCard);
        scanProgress_->setRange(0, 100);
        scanProgress_->setValue(0);
        progressLayout->addWidget(scanStatus_);
        progressLayout->addWidget(scanProgress_);
        layout->addWidget(progressCard);

        auto *resultsCard = makeCard(QStringLiteral("Scan results"), QString(), page);
        auto *resultsLayout = qobject_cast<QVBoxLayout *>(resultsCard->layout());
        scanResults_ = new QTableWidget(0, 3, resultsCard);
        scanResults_->setHorizontalHeaderLabels({QStringLiteral("File"), QStringLiteral("Result"), QStringLiteral("Details")});
        setupTable(scanResults_);
        resultsLayout->addWidget(scanResults_);
        auto *quarantine = makeButton(QStringLiteral("Quarantine selected detections"), false, resultsCard);
        resultsLayout->addWidget(quarantine, 0, Qt::AlignRight);
        connect(quarantine, &QPushButton::clicked, this, &MainWindow::quarantineSelectedDetections);
        layout->addWidget(resultsCard, 1);
        return page;
    }

    QWidget *buildQuarantinePage()
    {
        auto *page = pageContainer(QStringLiteral("Quarantine"),
                                   QStringLiteral("Isolated files are stored in your local application data folder. Review them before restoring or deleting."));
        auto *layout = qobject_cast<QVBoxLayout *>(page->layout());
        auto *card = makeCard(QStringLiteral("Isolated files"), QString(), page);
        auto *cardLayout = qobject_cast<QVBoxLayout *>(card->layout());
        quarantineTable_ = new QTableWidget(0, 3, card);
        quarantineTable_->setHorizontalHeaderLabels({QStringLiteral("Original file"), QStringLiteral("Date added"), QStringLiteral("Stored as")});
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
        connect(remove, &QPushButton::clicked, this, [this] { deleteQuarantined(false); });
        connect(removeAll, &QPushButton::clicked, this, [this] { deleteQuarantined(true); });
        layout->addWidget(card, 1);
        return page;
    }

    QWidget *buildHistoryPage()
    {
        auto *page = pageContainer(QStringLiteral("Activity history"),
                                   QStringLiteral("A local log of scans, detections, and definition updates."));
        auto *layout = qobject_cast<QVBoxLayout *>(page->layout());
        auto *card = makeCard(QStringLiteral("Recent activity"), QString(), page);
        auto *cardLayout = qobject_cast<QVBoxLayout *>(card->layout());
        auto *filters = new QHBoxLayout;
        filters->addWidget(new QLabel(QStringLiteral("Show:"), card));
        historyFilter_ = new QComboBox(card);
        historyFilter_->addItems({QStringLiteral("Everything"), QStringLiteral("Scans"),
                                  QStringLiteral("Detections"), QStringLiteral("Updates")});
        filters->addWidget(historyFilter_);
        filters->addStretch();
        cardLayout->addLayout(filters);
        historyTable_ = new QTableWidget(0, 4, card);
        historyTable_->setHorizontalHeaderLabels({QStringLiteral("Date and time"), QStringLiteral("Activity"),
                                                  QStringLiteral("Target"), QStringLiteral("Result")});
        setupTable(historyTable_);
        cardLayout->addWidget(historyTable_);
        connect(historyFilter_, &QComboBox::currentTextChanged, this, &MainWindow::refreshHistory);
        layout->addWidget(card, 1);
        return page;
    }

    QWidget *buildSettingsPage()
    {
        auto *page = pageContainer(QStringLiteral("Settings"),
                                   QStringLiteral("Tune scanning and notifications. Daemon-level features may require administrator configuration."));
        auto *layout = qobject_cast<QVBoxLayout *>(page->layout());
        auto *scroll = new QScrollArea(page);
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        auto *content = new QWidget(scroll);
        auto *contentLayout = new QVBoxLayout(content);
        contentLayout->setContentsMargins(0, 0, 8, 0);
        contentLayout->setSpacing(14);

        auto *scanCard = makeCard(QStringLiteral("Scanning"), QStringLiteral("Preferences used by scans started from this app."), content);
        auto *scanLayout = qobject_cast<QVBoxLayout *>(scanCard->layout());
        auto *sizeRow = new QHBoxLayout;
        sizeRow->addWidget(new QLabel(QStringLiteral("Maximum file size"), scanCard));
        sizeRow->addStretch();
        maxFileSize_ = new QSpinBox(scanCard);
        maxFileSize_->setRange(1, 2048);
        maxFileSize_->setSuffix(QStringLiteral(" MB"));
        sizeRow->addWidget(maxFileSize_);
        scanLayout->addLayout(sizeRow);
        archiveCheck_ = new QCheckBox(QStringLiteral("Scan inside archives (when supported by the ClamAV daemon)"), scanCard);
        symlinkCheck_ = new QCheckBox(QStringLiteral("Follow symbolic links"), scanCard);
        recursiveCheck_ = new QCheckBox(QStringLiteral("Scan folders recursively"), scanCard);
        auto *intensityRow = new QHBoxLayout;
        intensityRow->addWidget(new QLabel(QStringLiteral("CPU usage"), scanCard));
        intensityRow->addStretch();
        intensityCombo_ = new QComboBox(scanCard);
        intensityCombo_->addItems({QStringLiteral("Quiet · 1 worker"), QStringLiteral("Balanced · 2 workers"),
                                   QStringLiteral("Fast · up to 4 workers"), QStringLiteral("Aggressive · all cores")});
        intensityCombo_->setToolTip(QStringLiteral("Limits concurrent file scans. The default is two workers."));
        intensityRow->addWidget(intensityCombo_);
        scanLayout->addWidget(archiveCheck_);
        scanLayout->addWidget(symlinkCheck_);
        scanLayout->addWidget(recursiveCheck_);
        scanLayout->addLayout(intensityRow);
        contentLayout->addWidget(scanCard);

        auto *experienceCard = makeCard(QStringLiteral("Desktop experience"), QString(), content);
        auto *experienceLayout = qobject_cast<QVBoxLayout *>(experienceCard->layout());
        notificationCheck_ = new QCheckBox(QStringLiteral("Show desktop notifications (via system tray)"), experienceCard);
        startupCheck_ = new QCheckBox(QStringLiteral("Start KlamAV when I log in"), experienceCard);
        trayCheck_ = new QCheckBox(QStringLiteral("Show an icon in the system tray"), experienceCard);
        experienceLayout->addWidget(notificationCheck_);
        experienceLayout->addWidget(startupCheck_);
        experienceLayout->addWidget(trayCheck_);
        contentLayout->addWidget(experienceCard);

        auto *protectionCard = makeCard(QStringLiteral("Protection and schedule"),
                                        QStringLiteral("Scheduled scans run while KlamAV is open. Real-time enforcement is not activated by this build."), content);
        auto *protectionLayout = qobject_cast<QVBoxLayout *>(protectionCard->layout());
        realtimeCheck_ = new QCheckBox(QStringLiteral("Enable real-time protection preference"), protectionCard);
        scheduleCombo_ = new QComboBox(protectionCard);
        scheduleCombo_->addItems({QStringLiteral("No scheduled scan"), QStringLiteral("Daily"),
                                  QStringLiteral("Weekly")});
        auto *scheduleRow = new QHBoxLayout;
        scheduleRow->addWidget(new QLabel(QStringLiteral("Scan schedule"), protectionCard));
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

        maxFileSize_->setValue(settings_.value(QStringLiteral("scan/maxFileSizeMb"), 64).toInt());
        archiveCheck_->setChecked(settings_.value(QStringLiteral("scan/archives"), true).toBool());
        symlinkCheck_->setChecked(settings_.value(QStringLiteral("scan/followSymlinks"), false).toBool());
        recursiveCheck_->setChecked(settings_.value(QStringLiteral("scan/recursive"), true).toBool());
        intensityCombo_->setCurrentIndex(settings_.value(QStringLiteral("scan/intensity"), 1).toInt());
        notificationCheck_->setChecked(settings_.value(QStringLiteral("desktop/notifications"), true).toBool());
        startupCheck_->setChecked(settings_.value(QStringLiteral("desktop/startup"), false).toBool());
        trayCheck_->setChecked(settings_.value(QStringLiteral("desktop/tray"), true).toBool());
        realtimeCheck_->setChecked(settings_.value(QStringLiteral("protection/realtime"), false).toBool());
        scheduleCombo_->setCurrentIndex(settings_.value(QStringLiteral("scan/schedule"), 0).toInt());
        connect(save, &QPushButton::clicked, this, &MainWindow::saveSettings);
        return page;
    }

    void setupTable(QTableWidget *table)
    {
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table->setAlternatingRowColors(false);
        table->verticalHeader()->hide();
        table->horizontalHeader()->setStretchLastSection(true);
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        table->setMinimumHeight(180);
    }

    void applyStyle()
    {
        setStyleSheet(QStringLiteral(R"(
            QWidget#root, QWidget { background: #f5f7fb; color: #17233c; font-family: "Noto Sans", "Inter", sans-serif; font-size: 13px; }
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

    int workerLimit() const
    {
        const int cores = qMax(1, QThread::idealThreadCount());
        switch (intensityCombo_ ? intensityCombo_->currentIndex() : settings_.value(QStringLiteral("scan/intensity"), 1).toInt()) {
        case 0: return 1;
        case 2: return qMin(4, cores);
        case 3: return cores;
        default: return qMin(2, cores);
        }
    }

    bool daemonAvailable() const
    {
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

    void startScan(const QStringList &targets, bool fullScan = false)
    {
        if (scanWatcher_ && !scanWatcher_->isFinished()) {
            QMessageBox::information(this, QStringLiteral("Scan in progress"),
                                     QStringLiteral("Please wait for the current scan to finish."));
            return;
        }
        if (QStandardPaths::findExecutable(QStringLiteral("clamdscan")).isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("ClamAV scanner not found"),
                                 QStringLiteral("Install ClamAV and make sure clamdscan is available on your PATH."));
            return;
        }
        if (!daemonAvailable()) {
            QMessageBox::warning(this, QStringLiteral("ClamAV daemon is not running"),
                                 QStringLiteral("Start and configure the ClamAV daemon before scanning."));
            return;
        }
        scanResults_->setRowCount(0);
        scanProgress_->setRange(0, 0);
        scanStatus_->setText(QStringLiteral("Preparing scan…"));
        scanWatcher_ = new QFutureWatcher<ScanSummary>(this);
        connect(scanWatcher_, &QFutureWatcher<ScanSummary>::finished, this, [this] {
            const ScanSummary summary = scanWatcher_->result();
            int currentThreats = settings_.value(QStringLiteral("stats/threats"), 0).toInt();
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
                    addHistory(QStringLiteral("Detection"), file.path, QStringLiteral("Threat detected"));
                }
            }
            settings_.setValue(QStringLiteral("stats/threats"), currentThreats);
            scanProgress_->setRange(0, 100);
            scanProgress_->setValue(100);
            scanStatus_->setText(QStringLiteral("Scan complete · %1 files checked · %2 threats · %3 errors")
                                     .arg(summary.results.size()).arg(summary.infected).arg(summary.errors));
            const QString result = QStringLiteral("%1 checked, %2 threat(s), %3 error(s)")
                                       .arg(summary.results.size()).arg(summary.infected).arg(summary.errors);
            addHistory(QStringLiteral("Scan"), summary.target, result);
            settings_.setValue(QStringLiteral("lastScan/time"), QDateTime::currentDateTime().toString(Qt::ISODate));
            settings_.setValue(QStringLiteral("lastScan/result"), result);
            refreshDashboard();
            if (summary.infected > 0 && notificationCheck_->isChecked() && trayIcon_)
                trayIcon_->showMessage(QStringLiteral("KlamAV detected threats"),
                                       QStringLiteral("%1 infected file(s) found.").arg(summary.infected),
                                       QSystemTrayIcon::Warning);
        });

        const qint64 maxBytes = static_cast<qint64>(maxFileSize_ ? maxFileSize_->value()
                                                                 : settings_.value(QStringLiteral("scan/maxFileSizeMb"), 64).toInt())
            * 1024 * 1024;
        const bool recursive = recursiveCheck_ ? recursiveCheck_->isChecked()
                                                : settings_.value(QStringLiteral("scan/recursive"), true).toBool();
        const bool followSymlinks = symlinkCheck_ ? symlinkCheck_->isChecked()
                                                   : settings_.value(QStringLiteral("scan/followSymlinks"), false).toBool();
        const int workers = workerLimit();
        const QStringList excluded = fullScan
            ? QStringList{QStringLiteral("/proc"), QStringLiteral("/sys"), QStringLiteral("/dev"),
                          QStringLiteral("/run"), QStringLiteral("/var/lib/clamav")}
            : QStringList{};
        const bool scanArchives = archiveCheck_ ? archiveCheck_->isChecked()
                                                 : settings_.value(QStringLiteral("scan/archives"), true).toBool();
        const QPointer<MainWindow> guard(this);
        scanWatcher_->setFuture(QtConcurrent::run([targets, recursive, followSymlinks, maxBytes, workers,
                                                   scanArchives, excluded, guard]() {
            QStringList files;
            QSet<QString> seen;
            QStringList directories = targets;
            const QStringList archiveExtensions{QStringLiteral("zip"), QStringLiteral("7z"),
                                                QStringLiteral("rar"), QStringLiteral("tar"),
                                                QStringLiteral("gz"), QStringLiteral("bz2"),
                                                QStringLiteral("xz"), QStringLiteral("cab"),
                                                QStringLiteral("iso"), QStringLiteral("arj"),
                                                QStringLiteral("zst")};
            for (const QString &target : targets) {
                const QFileInfo info(target);
                if (info.isFile() && (!info.isSymLink() || followSymlinks) && info.size() <= maxBytes
                    && (scanArchives || !archiveExtensions.contains(info.suffix().toLower()))) {
                    const QString canonical = info.canonicalFilePath();
                    const QString key = canonical.isEmpty() ? info.absoluteFilePath() : canonical;
                    if (!seen.contains(key)) {
                        seen.insert(key);
                        files.push_back(info.absoluteFilePath());
                    }
                }
            }
            while (!directories.isEmpty()) {
                const QString directory = directories.takeLast();
                const QFileInfo directoryInfo(directory);
                if (!directoryInfo.isDir() || (directoryInfo.isSymLink() && !followSymlinks))
                    continue;
                bool excludedDirectory = false;
                for (const QString &root : excluded) {
                    if (directory == root || directory.startsWith(root + QLatin1Char('/'))) {
                        excludedDirectory = true;
                        break;
                    }
                }
                if (excludedDirectory)
                    continue;
                const QString canonicalDirectory = directoryInfo.canonicalFilePath();
                const QString directoryKey = canonicalDirectory.isEmpty() ? directoryInfo.absoluteFilePath() : canonicalDirectory;
                if (seen.contains(directoryKey))
                    continue;
                seen.insert(directoryKey);
                const QFileInfoList children = QDir(directory).entryInfoList(
                    QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System, QDir::DirsFirst);
                for (const QFileInfo &info : children) {
                    if (info.isSymLink() && !followSymlinks)
                        continue;
                    if (info.isDir()) {
                        if (recursive)
                            directories.push_back(info.absoluteFilePath());
                        continue;
                    }
                    if (!info.isFile() || info.size() > maxBytes)
                        continue;
                    if (!scanArchives && archiveExtensions.contains(info.suffix().toLower()))
                        continue;
                    const QString canonical = info.canonicalFilePath();
                    const QString key = canonical.isEmpty() ? info.absoluteFilePath() : canonical;
                    if (!seen.contains(key)) {
                        seen.insert(key);
                        files.push_back(info.absoluteFilePath());
                    }
                }
            }

            if (guard) {
                QMetaObject::invokeMethod(guard, [guard, count = files.size()] {
                    if (guard) {
                        guard->scanProgress_->setRange(0, qMax(1, count));
                        guard->scanProgress_->setValue(0);
                        guard->scanStatus_->setText(QStringLiteral("Scanning %1 file(s)…").arg(count));
                    }
                }, Qt::QueuedConnection);
            }
            QThreadPool pool;
            pool.setMaxThreadCount(workers);
            std::atomic_int completed{0};
            QFuture<FileResult> scanned = QtConcurrent::mapped(&pool, files,
                [guard, &completed, total = files.size()](const QString &path) {
                    QProcess process;
                    process.start(QStringLiteral("clamdscan"),
                                  {QStringLiteral("--no-summary"), QStringLiteral("--infected"),
                                   QStringLiteral("--fdpass"), path});
                    FileResult file;
                    file.path = path;
                    if (!process.waitForStarted() || !process.waitForFinished(-1)) {
                        file.status = QStringLiteral("Error");
                        file.detail = process.errorString();
                    } else {
                        const QString output = QString::fromLocal8Bit(process.readAllStandardOutput()
                                                                      + process.readAllStandardError()).trimmed();
                        file.infected = process.exitCode() == 1
                            || output.contains(QStringLiteral("FOUND"), Qt::CaseInsensitive);
                        if (file.infected) {
                            file.status = QStringLiteral("Threat detected");
                            file.detail = output;
                        } else if (process.exitCode() == 0) {
                            file.status = QStringLiteral("Clean");
                            file.detail = output;
                        } else {
                            file.status = QStringLiteral("Error");
                            file.detail = output.isEmpty() ? QStringLiteral("clamdscan exited with code %1").arg(process.exitCode()) : output;
                        }
                    }
                    const int done = ++completed;
                    if (guard) {
                        QMetaObject::invokeMethod(guard, [guard, done, total] {
                            if (guard) {
                                guard->scanProgress_->setRange(0, qMax(1, total));
                                guard->scanProgress_->setValue(done);
                            }
                        }, Qt::QueuedConnection);
                    }
                    return file;
                });
            scanned.waitForFinished();

            ScanSummary summary;
            summary.target = displayTargets(targets);
            summary.results.reserve(scanned.resultCount());
            for (int i = 0; i < scanned.resultCount(); ++i) {
                const FileResult file = scanned.resultAt(i);
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

    void updateDefinitions()
    {
        if (QStandardPaths::findExecutable(QStringLiteral("freshclam")).isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("Updater not found"),
                                 QStringLiteral("Install ClamAV and make sure freshclam is available on your PATH."));
            return;
        }
        auto *process = new QProcess(this);
        process->setProgram(QStringLiteral("freshclam"));
        process->setArguments({QStringLiteral("--stdout")});
        connect(process, &QProcess::errorOccurred, this, [this, process](QProcess::ProcessError) {
            addHistory(QStringLiteral("Update"), QStringLiteral("Virus definitions"),
                       QStringLiteral("Failed: %1").arg(process->errorString()));
            QMessageBox::warning(this, QStringLiteral("Update failed"), process->errorString());
            process->deleteLater();
        });
        connect(process, &QProcess::finished, this, [this, process](int exitCode, QProcess::ExitStatus) {
            const QString output = QString::fromLocal8Bit(process->readAllStandardOutput()
                                                          + process->readAllStandardError()).trimmed();
            const bool success = exitCode == 0;
            addHistory(QStringLiteral("Update"), QStringLiteral("Virus definitions"),
                       success ? QStringLiteral("Updated successfully") : QStringLiteral("Failed (exit %1)").arg(exitCode));
            QMessageBox::information(this, success ? QStringLiteral("Definitions updated") : QStringLiteral("Update failed"),
                                     output.isEmpty() ? (success ? QStringLiteral("Virus definitions are up to date.")
                                                                 : QStringLiteral("freshclam exited with code %1.").arg(exitCode))
                                                      : output);
            refreshDashboard();
            process->deleteLater();
        });
        process->start();
    }

    void saveSettings()
    {
        settings_.setValue(QStringLiteral("scan/maxFileSizeMb"), maxFileSize_->value());
        settings_.setValue(QStringLiteral("scan/archives"), archiveCheck_->isChecked());
        settings_.setValue(QStringLiteral("scan/followSymlinks"), symlinkCheck_->isChecked());
        settings_.setValue(QStringLiteral("scan/recursive"), recursiveCheck_->isChecked());
        settings_.setValue(QStringLiteral("scan/intensity"), intensityCombo_->currentIndex());
        settings_.setValue(QStringLiteral("desktop/notifications"), notificationCheck_->isChecked());
        settings_.setValue(QStringLiteral("desktop/startup"), startupCheck_->isChecked());
        settings_.setValue(QStringLiteral("desktop/tray"), trayCheck_->isChecked());
        settings_.setValue(QStringLiteral("protection/realtime"), realtimeCheck_->isChecked());
        settings_.setValue(QStringLiteral("scan/schedule"), scheduleCombo_->currentIndex());
        if (scheduleCombo_->currentIndex() == 0) {
            settings_.remove(QStringLiteral("scan/nextRun"));
        } else if (settings_.value(QStringLiteral("scan/schedule")).toInt()
                   != settings_.value(QStringLiteral("scan/previousSchedule"), -1).toInt()
                   || settings_.value(QStringLiteral("scan/nextRun")).toString().isEmpty()) {
            const int days = scheduleCombo_->currentIndex() == 1 ? 1 : 7;
            settings_.setValue(QStringLiteral("scan/nextRun"),
                               QDateTime::currentDateTime().addDays(days).toString(Qt::ISODate));
        }
        settings_.setValue(QStringLiteral("scan/previousSchedule"), scheduleCombo_->currentIndex());
        settings_.sync();
        saveAutostartEntry(startupCheck_->isChecked());
        if (trayCheck_->isChecked() && QSystemTrayIcon::isSystemTrayAvailable())
            ensureTrayIcon();
        else if (trayIcon_)
            trayIcon_->hide();
        QMessageBox::information(this, QStringLiteral("Settings saved"),
                                 QStringLiteral("Your preferences have been saved. Scheduled scans run while KlamAV is open; real-time protection is not activated by this build."));
    }

    void runScheduledScan()
    {
        const int schedule = settings_.value(QStringLiteral("scan/schedule"), 0).toInt();
        if (schedule <= 0)
            return;
        const QDateTime nextRun = QDateTime::fromString(settings_.value(QStringLiteral("scan/nextRun")).toString(), Qt::ISODate);
        if (!nextRun.isValid() || QDateTime::currentDateTime() < nextRun)
            return;
        if (scanWatcher_ && !scanWatcher_->isFinished()) {
            settings_.setValue(QStringLiteral("scan/nextRun"),
                               QDateTime::currentDateTime().addSecs(300).toString(Qt::ISODate));
            return;
        }
        if (!daemonAvailable()) {
            settings_.setValue(QStringLiteral("scan/nextRun"),
                               QDateTime::currentDateTime().addSecs(300).toString(Qt::ISODate));
            if (trayIcon_ && notificationCheck_ && notificationCheck_->isChecked())
                trayIcon_->showMessage(QStringLiteral("Scheduled scan postponed"),
                                       QStringLiteral("The ClamAV daemon is not responding."),
                                       QSystemTrayIcon::Warning);
            return;
        }
        const int days = schedule == 1 ? 1 : 7;
        settings_.setValue(QStringLiteral("scan/nextRun"),
                           QDateTime::currentDateTime().addDays(days).toString(Qt::ISODate));
        startScan(quickScanTargets());
    }

    void saveAutostartEntry(bool enabled)
    {
        const QString path = QDir(QStandardPaths::writableLocation(QStandardPaths::ConfigLocation))
                                 .filePath(QStringLiteral("autostart/org.klamav.KlamAV.desktop"));
        if (!enabled) {
            if (QFileInfo::exists(path) && !QFile::remove(path))
                QMessageBox::warning(this, QStringLiteral("Could not update startup settings"),
                                     QStringLiteral("KlamAV could not remove its autostart entry."));
            return;
        }
        if (!QDir().mkpath(QFileInfo(path).absolutePath())) {
            QMessageBox::warning(this, QStringLiteral("Could not update startup settings"),
                                 QStringLiteral("KlamAV could not create the desktop autostart folder."));
            return;
        }
        QString executable = QCoreApplication::applicationFilePath();
        executable.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
        executable.replace(QLatin1Char('"'), QStringLiteral("\\\""));
        QSaveFile file(path);
        const QByteArray entry = (QStringLiteral("[Desktop Entry]\nType=Application\nName=KlamAV\n")
            + QStringLiteral("Comment=ClamAV antivirus frontend\nExec=\"%1\"\nTerminal=false\n")
                  .arg(executable)).toUtf8();
        if (!file.open(QIODevice::WriteOnly) || file.write(entry) != entry.size() || !file.commit())
            QMessageBox::warning(this, QStringLiteral("Could not update startup settings"),
                                 QStringLiteral("KlamAV could not write its autostart entry."));
    }

    void ensureTrayIcon()
    {
        if (trayIcon_)
            return;
        trayIcon_ = new QSystemTrayIcon(style()->standardIcon(QStyle::SP_ComputerIcon), this);
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
        connect(trayIcon_, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason) {
            if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
                showNormal();
                raise();
                activateWindow();
            }
        });
        trayIcon_->show();
    }

    void addHistory(const QString &type, const QString &target, const QString &result)
    {
        QStringList entries = settings_.value(QStringLiteral("history/entries")).toStringList();
        entries.prepend(QStringList{QDateTime::currentDateTime().toString(Qt::ISODate), type, target, result}.join(QLatin1Char('\t')));
        while (entries.size() > 300)
            entries.removeLast();
        settings_.setValue(QStringLiteral("history/entries"), entries);
        refreshHistory();
    }

    void refreshDashboard()
    {
        const bool scannerInstalled = !QStandardPaths::findExecutable(QStringLiteral("clamdscan")).isEmpty();
        const bool daemonIsAvailable = scannerInstalled && daemonAvailable();
        if (headerStatus_)
            headerStatus_->setText(daemonIsAvailable ? QStringLiteral("●  ClamAV active")
                                                     : (scannerInstalled ? QStringLiteral("●  Daemon offline")
                                                                         : QStringLiteral("●  Scanner not installed")));
        if (dashboardProtection_)
            dashboardProtection_->setText(daemonIsAvailable ? QStringLiteral("Active")
                                                            : (scannerInstalled ? QStringLiteral("Daemon offline")
                                                                                : QStringLiteral("Not installed")));
        if (dashboardHeroStatus_)
            dashboardHeroStatus_->setText(daemonIsAvailable ? QStringLiteral("Protection ready")
                                                            : (scannerInstalled ? QStringLiteral("ClamAV daemon is not responding")
                                                                                : QStringLiteral("ClamAV is not installed")));
        if (dashboardDefinitions_) {
            const QStringList definitions = QDir(QStringLiteral("/var/lib/clamav"))
                                                .entryList({QStringLiteral("*.cvd"), QStringLiteral("*.cld")}, QDir::Files);
            const QStringList userDefinitions = QDir(QDir::homePath() + QStringLiteral("/.clamav"))
                                                   .entryList({QStringLiteral("*.cvd"), QStringLiteral("*.cld")}, QDir::Files);
            dashboardDefinitions_->setText(!definitions.isEmpty() || !userDefinitions.isEmpty()
                                               ? QStringLiteral("Installed")
                                               : QStringLiteral("Check updater"));
        }
        if (dashboardThreats_)
            dashboardThreats_->setText(QString::number(settings_.value(QStringLiteral("stats/threats"), 0).toInt()));
        if (lastScanLabel_) {
            const QString time = settings_.value(QStringLiteral("lastScan/time")).toString();
            const QString result = settings_.value(QStringLiteral("lastScan/result")).toString();
            lastScanLabel_->setText(time.isEmpty() ? QStringLiteral("No scans yet")
                                                   : QDateTime::fromString(time, Qt::ISODate).toLocalTime().toString(QStringLiteral("MMM d, yyyy · h:mm AP"))
                                                         + QStringLiteral("  —  ") + result);
        }
    }

    void refreshHistory()
    {
        if (!historyTable_)
            return;
        const QString filter = historyFilter_ ? historyFilter_->currentText() : QStringLiteral("Everything");
        const QStringList entries = settings_.value(QStringLiteral("history/entries")).toStringList();
        historyTable_->setRowCount(0);
        for (const QString &entry : entries) {
            const QStringList columns = entry.split(QLatin1Char('\t'));
            if (columns.size() != 4)
                continue;
            const QString type = columns.at(1);
            if ((filter == QStringLiteral("Scans") && type != QStringLiteral("Scan"))
                || (filter == QStringLiteral("Detections") && type != QStringLiteral("Detection"))
                || (filter == QStringLiteral("Updates") && type != QStringLiteral("Update")))
                continue;
            const int row = historyTable_->rowCount();
            historyTable_->insertRow(row);
            historyTable_->setItem(row, 0, new QTableWidgetItem(QDateTime::fromString(columns.at(0), Qt::ISODate)
                                                                    .toLocalTime().toString(QStringLiteral("MMM d, yyyy · h:mm AP"))));
            historyTable_->setItem(row, 1, new QTableWidgetItem(type));
            historyTable_->setItem(row, 2, new QTableWidgetItem(columns.at(2)));
            historyTable_->setItem(row, 3, new QTableWidgetItem(columns.at(3)));
        }
    }

    void refreshQuarantine()
    {
        if (!quarantineTable_)
            return;
        quarantineTable_->setRowCount(0);
        const int count = settings_.beginReadArray(QStringLiteral("quarantine/items"));
        for (int i = 0; i < count; ++i) {
            settings_.setArrayIndex(i);
            const QString original = settings_.value(QStringLiteral("original")).toString();
            const QString stored = settings_.value(QStringLiteral("stored")).toString();
            const QString date = settings_.value(QStringLiteral("date")).toString();
            const int row = quarantineTable_->rowCount();
            quarantineTable_->insertRow(row);
            auto *file = new QTableWidgetItem(original);
            file->setData(Qt::UserRole, stored);
            quarantineTable_->setItem(row, 0, file);
            quarantineTable_->setItem(row, 1, new QTableWidgetItem(date));
            quarantineTable_->setItem(row, 2, new QTableWidgetItem(QFileInfo(stored).fileName()));
        }
        settings_.endArray();
    }

    QVector<QStringList> quarantineEntries()
    {
        QVector<QStringList> entries;
        const int count = settings_.beginReadArray(QStringLiteral("quarantine/items"));
        for (int i = 0; i < count; ++i) {
            settings_.setArrayIndex(i);
            entries.push_back({settings_.value(QStringLiteral("original")).toString(),
                               settings_.value(QStringLiteral("stored")).toString(),
                               settings_.value(QStringLiteral("date")).toString(),
                               settings_.value(QStringLiteral("permissions")).toString()});
        }
        settings_.endArray();
        return entries;
    }

    void saveQuarantineEntries(const QVector<QStringList> &entries)
    {
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

    void quarantineSelectedDetections()
    {
        QVector<int> selectedRows;
        for (const QModelIndex &index : scanResults_->selectionModel()->selectedRows())
            selectedRows.push_back(index.row());
        if (selectedRows.isEmpty()) {
            QMessageBox::information(this, QStringLiteral("Select detections"),
                                     QStringLiteral("Select one or more scan results first."));
            return;
        }
        const QString directory = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
            + QStringLiteral("/quarantine");
        if (!QDir().mkpath(directory)
            || !QFile::setPermissions(directory, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner)) {
            QMessageBox::critical(this, QStringLiteral("Quarantine unavailable"),
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
            const QString destination = QDir(directory).filePath(QUuid::createUuid().toString(QUuid::WithoutBraces)
                                                                 + QLatin1Char('_') + QFileInfo(source).fileName());
            if (!moveFile(source, destination)) {
                QMessageBox::warning(this, QStringLiteral("Could not quarantine file"),
                                     QStringLiteral("KlamAV could not move %1. Check permissions and filesystem space.")
                                         .arg(source));
                continue;
            }
            if (!QFile::setPermissions(destination, QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
                QMessageBox::warning(this, QStringLiteral("Could not secure quarantined file"),
                                     QStringLiteral("KlamAV could not restrict file permissions for %1. The private quarantine folder still limits access.")
                                         .arg(source));
            }
            entries.push_back({source, destination, QDateTime::currentDateTime().toString(Qt::ISODate),
                               QString::number(permissions)});
            ++moved;
            addHistory(QStringLiteral("Detection"), source, QStringLiteral("Quarantined"));
        }
        saveQuarantineEntries(entries);
        if (moved > 0)
            refreshDashboard();
    }

    void restoreSelected()
    {
        const auto rows = quarantineTable_->selectionModel()->selectedRows();
        if (rows.isEmpty()) {
            QMessageBox::information(this, QStringLiteral("Select a file"), QStringLiteral("Select a quarantined file to restore."));
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
                const QString restoredName = original.completeBaseName() + QStringLiteral("_restored")
                    + (original.suffix().isEmpty() ? QString() : QLatin1Char('.') + original.suffix());
                destination = original.dir().filePath(restoredName);
            }
            if (!moveFile(entry.value(1), destination)) {
                QMessageBox::warning(this, QStringLiteral("Restore failed"),
                                     QStringLiteral("Could not restore %1. Check permissions and available disk space.")
                                         .arg(destination));
                remaining.push_back(entry);
                continue;
            }
            if (!entry.value(3).isEmpty()
                && !QFile::setPermissions(destination,
                                          static_cast<QFileDevice::Permissions>(entry.value(3).toInt()))) {
                QMessageBox::warning(this, QStringLiteral("Could not restore file permissions"),
                                     QStringLiteral("The file was restored, but its original permissions could not be reapplied."));
            }
            addHistory(QStringLiteral("Detection"), destination, QStringLiteral("Restored from quarantine"));
        }
        saveQuarantineEntries(remaining);
    }

    void deleteQuarantined(bool all)
    {
        const auto selectedRows = all ? QModelIndexList{} : quarantineTable_->selectionModel()->selectedRows();
        if (!all && selectedRows.isEmpty()) {
            QMessageBox::information(this, QStringLiteral("Select a file"), QStringLiteral("Select files to delete."));
            return;
        }
        const QString prompt = all ? QStringLiteral("Permanently delete every quarantined file?")
                                   : QStringLiteral("Permanently delete the selected quarantined files?");
        if (QMessageBox::question(this, QStringLiteral("Delete quarantined files"), prompt,
                                  QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
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
                QMessageBox::warning(this, QStringLiteral("Delete failed"),
                                     QStringLiteral("Could not delete %1. Check permissions.").arg(entry.value(1)));
                remaining.push_back(entry);
            }
        }
        saveQuarantineEntries(remaining);
    }

    void closeEvent(QCloseEvent *event) override
    {
        if (trayCheck_ && trayCheck_->isChecked() && QSystemTrayIcon::isSystemTrayAvailable()) {
            ensureTrayIcon();
            hide();
            event->ignore();
            return;
        }
        QMainWindow::closeEvent(event);
    }
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(AppName);
    QApplication::setOrganizationName(AppName);
    QApplication::setApplicationDisplayName(QStringLiteral("KlamAV Antivirus"));
    MainWindow window;
    window.show();
    return app.exec();
}

#include "main.moc"
