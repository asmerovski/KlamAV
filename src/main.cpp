#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QCloseEvent>
#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QFileDialog>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QIcon>
#include <QMap>
#include <QLabel>
#include <QMainWindow>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QProcess>
#include <QProgressBar>
#include <QPushButton>
#include <QPointer>
#include <QResizeEvent>
#include <QScrollArea>
#include <QSaveFile>
#include <QSet>
#include <QSettings>
#include <QSpinBox>
#include <QStandardPaths>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTableWidget>
#include <QTimer>
#include <QThread>
#include <QUuid>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMenu>
#include <QAction>
#include <QApplication>
#include <QCoreApplication>
#include <QtConcurrent/QtConcurrentRun>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>

#include "fileoperations.h"
#include "scanengine.h"
#include "systemdscheduler.h"

namespace {

const QString AppName = QStringLiteral("KlamAV");

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

int configuredWorkerLimit(int intensity)
{
    const int cores = qMax(1, QThread::idealThreadCount());
    switch (intensity) {
    case 0: return 1;
    case 2: return qMin(4, cores);
    case 3: return cores;
    default: return qMin(2, cores);
    }
}

int runScheduledScan()
{
    if (QStandardPaths::findExecutable(QStringLiteral("clamdscan")).isEmpty()) {
        qCritical("KlamAV scheduled scan: clamdscan was not found on PATH.");
        return 1;
    }
    QProcess ping;
    ping.start(QStringLiteral("clamdscan"), {QStringLiteral("--ping=1")});
    if (!ping.waitForStarted(3000) || !ping.waitForFinished(3000)
        || ping.exitStatus() != QProcess::NormalExit || ping.exitCode() != 0) {
        if (ping.state() != QProcess::NotRunning) {
            ping.kill();
            ping.waitForFinished();
        }
        qCritical("KlamAV scheduled scan: the ClamAV daemon is not responding.");
        return 1;
    }

    QSettings settings(QStringLiteral("KlamAV"), QStringLiteral("KlamAV"));
    ScanOptions options;
    options.targets = quickScanTargets();
    options.maxFileBytes = static_cast<qint64>(
        settings.value(QStringLiteral("scan/maxFileSizeMb"), 64).toInt()) * 1024 * 1024;
    options.recursive = settings.value(QStringLiteral("scan/recursive"), true).toBool();
    options.followSymlinks = settings.value(QStringLiteral("scan/followSymlinks"), false).toBool();
    options.scanArchives = settings.value(QStringLiteral("scan/archives"), true).toBool();
    options.workers = configuredWorkerLimit(settings.value(QStringLiteral("scan/intensity"), 1).toInt());

    std::atomic_bool cancelled{false};
    std::mutex resultMutex;
    QVector<FileResult> detections;
    const ScanSummary summary = ScanEngine::run(options, cancelled, [&](const ScanProgress &progress) {
        std::lock_guard<std::mutex> lock(resultMutex);
        for (const FileResult &result : progress.notableResults) {
            if (result.infected)
                detections.push_back(result);
        }
    });

    int totalThreats = settings.value(QStringLiteral("stats/threats"), 0).toInt();
    totalThreats += summary.infected;
    settings.setValue(QStringLiteral("stats/threats"), totalThreats);
    QStringList history = settings.value(QStringLiteral("history/entries")).toStringList();
    for (const FileResult &detection : detections) {
        history.prepend(QStringList{QDateTime::currentDateTime().toString(Qt::ISODate),
                                    QStringLiteral("Detection"), detection.path,
                                    QStringLiteral("Threat detected")}.join(QLatin1Char('\t')));
    }
    const QString result = QStringLiteral("%1 checked, %2 threat(s), %3 error(s), %4 skipped by size, %5 archive(s) excluded, %6 unreadable")
        .arg(summary.scanned).arg(summary.infected).arg(summary.errors)
        .arg(summary.skippedLarge).arg(summary.skippedArchives)
        .arg(summary.skippedUnreadable);
    history.prepend(QStringList{QDateTime::currentDateTime().toString(Qt::ISODate),
                                QStringLiteral("Scan"), displayTargets(options.targets), result}
                        .join(QLatin1Char('\t')));
    while (history.size() > 300)
        history.removeLast();
    settings.setValue(QStringLiteral("history/entries"), history);
    settings.setValue(QStringLiteral("lastScan/time"), QDateTime::currentDateTime().toString(Qt::ISODate));
    settings.setValue(QStringLiteral("lastScan/result"), result);
    settings.sync();
    if (settings.status() != QSettings::NoError) {
        qCritical("KlamAV scheduled scan: could not persist scan results.");
        return 1;
    }
    qInfo().noquote() << "KlamAV scheduled scan:" << result;
    return summary.errors == 0 ? 0 : 1;
}

QIcon makeTrayIcon(int animationFrame = -1)
{
    QPixmap pixmap(64, 64);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);

    QPainterPath shield;
    shield.moveTo(32, 4);
    shield.cubicTo(41, 9, 49, 10, 57, 12);
    shield.lineTo(55, 33);
    shield.cubicTo(54, 45, 45, 54, 32, 61);
    shield.cubicTo(19, 54, 10, 45, 9, 33);
    shield.lineTo(7, 12);
    shield.cubicTo(15, 10, 23, 9, 32, 4);
    shield.closeSubpath();

    painter.setPen(QPen(QColor(QStringLiteral("#14213d")), 6,
                        Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.setBrush(QColor(QStringLiteral("#13a89e")));
    painter.drawPath(shield);
    painter.setPen(QPen(Qt::white, 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.setBrush(Qt::NoBrush);
    painter.drawPath(shield);

    QPainterPath check;
    check.moveTo(19, 32);
    check.lineTo(28, 41);
    check.lineTo(46, 23);
    painter.setPen(QPen(QColor(QStringLiteral("#14213d")), 9,
                        Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawPath(check);
    painter.setPen(QPen(Qt::white, 4, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawPath(check);

    if (animationFrame >= 0) {
        painter.setPen(QPen(QColor(QStringLiteral("#ffca3a")), 5,
                            Qt::SolidLine, Qt::RoundCap));
        painter.drawArc(QRectF(3, 3, 58, 58), animationFrame * 30 * 16, 110 * 16);
    }

    QIcon icon;
    for (const int size : {16, 22, 24, 32, 48, 64})
        icon.addPixmap(pixmap.scaled(size, size, Qt::IgnoreAspectRatio,
                                     Qt::SmoothTransformation));
    return icon;
}

} // namespace

class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    MainWindow()
        : settings_(QStringLiteral("KlamAV"), QStringLiteral("KlamAV"))
    {
        setWindowTitle(QStringLiteral("KlamAV"));
        setMinimumSize(700, 500);
        resize(1240, 820);
        buildInterface();
        applyStyle();
        connect(&trayAnimationTimer_, &QTimer::timeout, this, [this] {
            if (activeJobs_.isEmpty() || !trayIcon_ || !trayIcon_->isVisible())
                return;
            trayAnimationFrame_ = (trayAnimationFrame_ + 1) % 12;
            trayIcon_->setIcon(makeTrayIcon(trayAnimationFrame_));
        });
        trayAnimationTimer_.setInterval(120);
        connect(&daemonRefreshTimer_, &QTimer::timeout, this, [this] {
            daemonStatusKnown_ = false;
            refreshDashboardStatus();
            checkDaemonAvailability();
        });
        daemonRefreshTimer_.start(60000);
        if (settings_.value(QStringLiteral("desktop/tray"), true).toBool()
            && QSystemTrayIcon::isSystemTrayAvailable())
            ensureTrayIcon();
        refreshDashboard();
        refreshQuarantine();
        refreshHistory();
    }

    ~MainWindow() override
    {
        if (scanCancelled_)
            scanCancelled_->store(true);
        if (scanWatcher_)
            scanWatcher_->waitForFinished();
    }

    bool startsMinimizedToTray() const
    {
        return settings_.value(QStringLiteral("desktop/startMinimized"), false).toBool()
            && settings_.value(QStringLiteral("desktop/tray"), true).toBool()
            && QSystemTrayIcon::isSystemTrayAvailable();
    }

private:
    QSettings settings_;
    QWidget *root_ = nullptr;
    QWidget *sidebar_ = nullptr;
    QLabel *brandName_ = nullptr;
    QLabel *sideNote_ = nullptr;
    QLabel *versionLabel_ = nullptr;
    QStackedWidget *pages_ = nullptr;
    QPushButton *saveSettingsButton_ = nullptr;
    QLabel *jobStatusLabel_ = nullptr;
    QProgressBar *jobProgressBar_ = nullptr;
    QLabel *headerStatus_ = nullptr;
    QLabel *dashboardHeroStatus_ = nullptr;
    QLabel *dashboardProtection_ = nullptr;
    QLabel *dashboardDefinitions_ = nullptr;
    QLabel *dashboardThreats_ = nullptr;
    QLabel *lastScanLabel_ = nullptr;
    QLabel *scanStatus_ = nullptr;
    QProgressBar *scanProgress_ = nullptr;
    QTableWidget *scanResults_ = nullptr;
    QPushButton *cancelScanButton_ = nullptr;
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
    QCheckBox *startMinimizedCheck_ = nullptr;
    QCheckBox *realtimeCheck_ = nullptr;
    QComboBox *scheduleCombo_ = nullptr;
    QFutureWatcher<ScanSummary> *scanWatcher_ = nullptr;
    QSystemTrayIcon *trayIcon_ = nullptr;
    bool definitionUpdateInProgress_ = false;
    QProcess *daemonProbe_ = nullptr;
    QList<std::function<void(bool)>> daemonProbeCallbacks_;
    QSet<QString> displayedScanResults_;
    QMap<QString, QString> activeJobs_;
    std::shared_ptr<std::atomic_bool> scanCancelled_;
    bool daemonStatusKnown_ = false;
    bool daemonIsAvailable_ = false;
    bool scanInProgress_ = false;
    int scanGeneration_ = 0;
    int trayAnimationFrame_ = 0;
    QTimer daemonRefreshTimer_;
    QTimer trayAnimationTimer_;

    void buildInterface()
    {
        root_ = new QWidget(this);
        root_->setObjectName(QStringLiteral("root"));
        auto *outer = new QHBoxLayout(root_);
        outer->setContentsMargins(0, 0, 0, 0);
        outer->setSpacing(0);

        sidebar_ = new QWidget(root_);
        sidebar_->setObjectName(QStringLiteral("sidebar"));
        sidebar_->setFixedWidth(238);
        auto *sideLayout = new QVBoxLayout(sidebar_);
        sideLayout->setContentsMargins(18, 24, 18, 20);
        sideLayout->setSpacing(8);

        auto *brand = new QHBoxLayout;
        auto *mark = new QLabel(QStringLiteral("K"), sidebar_);
        mark->setObjectName(QStringLiteral("brandMark"));
        mark->setAlignment(Qt::AlignCenter);
        mark->setFixedSize(40, 40);
        brandName_ = new QLabel(QStringLiteral("KlamAV"), sidebar_);
        brandName_->setObjectName(QStringLiteral("brandName"));
        brand->addWidget(mark);
        brand->addSpacing(10);
        brand->addWidget(brandName_);
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
            auto *nav = new QPushButton(navIcons.at(i) + QStringLiteral("   ") + navNames.at(i), sidebar_);
            nav->setObjectName(QStringLiteral("navButton"));
            nav->setProperty("navIcon", navIcons.at(i));
            nav->setProperty("navLabel", navNames.at(i));
            nav->setToolTip(navNames.at(i));
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
        sideNote_ = new QLabel(QStringLiteral("CLAMAV SCANNING\nOn-demand file scanning"), sidebar_);
        sideNote_->setObjectName(QStringLiteral("sideNote"));
        sideLayout->addWidget(sideNote_);
        versionLabel_ = new QLabel(QStringLiteral("KlamAV %1").arg(QCoreApplication::applicationVersion()), sidebar_);
        versionLabel_->setObjectName(QStringLiteral("versionLabel"));
        sideLayout->addWidget(versionLabel_);
        outer->addWidget(sidebar_);

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
        auto *jobStatus = new QWidget(mainArea);
        jobStatus->setObjectName(QStringLiteral("jobStatusBar"));
        auto *jobLayout = new QHBoxLayout(jobStatus);
        jobLayout->setContentsMargins(12, 8, 12, 8);
        jobLayout->setSpacing(12);
        jobStatusLabel_ = new QLabel(QStringLiteral("Ready"), jobStatus);
        jobStatusLabel_->setObjectName(QStringLiteral("jobStatusLabel"));
        jobStatusLabel_->setWordWrap(true);
        jobProgressBar_ = new QProgressBar(jobStatus);
        jobProgressBar_->setRange(0, 0);
        jobProgressBar_->setFixedWidth(100);
        jobProgressBar_->hide();
        jobLayout->addWidget(jobStatusLabel_, 1);
        jobLayout->addWidget(jobProgressBar_);
        mainLayout->addWidget(jobStatus);
        outer->addWidget(mainArea, 1);
        setCentralWidget(root_);
        updateResponsiveLayout();
    }

    QWidget *pageContainer(const QString &title, const QString &description,
                           QWidget *headerAction = nullptr)
    {
        auto *page = new QWidget;
        auto *layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(18);
        auto *heading = new QLabel(title, page);
        heading->setObjectName(QStringLiteral("sectionTitle"));
        if (headerAction) {
            auto *headingRow = new QHBoxLayout;
            headingRow->addWidget(heading);
            headingRow->addStretch();
            headingRow->addWidget(headerAction);
            layout->addLayout(headingRow);
        } else {
            layout->addWidget(heading);
        }
        auto *subheading = new QLabel(description, page);
        subheading->setObjectName(QStringLiteral("muted"));
        subheading->setWordWrap(true);
        layout->addWidget(subheading);
        return page;
    }

    QWidget *buildDashboard()
    {
        auto *page = pageContainer(QStringLiteral("Good afternoon"),
                                   QStringLiteral("ClamAV scanner and on-demand scan status."));
        auto *layout = qobject_cast<QVBoxLayout *>(page->layout());

        auto *hero = makeCard(QStringLiteral("On-demand ClamAV scanning"),
                              QStringLiteral("Run scans when you choose. Real-time protection is not active in this build."),
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
        addStat(QStringLiteral("Scanner availability"), &dashboardProtection_);
        addStat(QStringLiteral("Virus definitions"), &dashboardDefinitions_);
        addStat(QStringLiteral("Detection events"), &dashboardThreats_);
        dashboardThreats_->setToolTip(QStringLiteral(
            "Cumulative detection events. Repeated scans of the same file are counted again."));
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

        auto *progressCard = makeCard(QStringLiteral("Scan progress"),
                                       QStringLiteral("Detections and scan errors appear below as they are found."), page);
        auto *progressLayout = qobject_cast<QVBoxLayout *>(progressCard->layout());
        scanStatus_ = new QLabel(QStringLiteral("Ready to scan"), progressCard);
        scanStatus_->setObjectName(QStringLiteral("muted"));
        scanProgress_ = new QProgressBar(progressCard);
        scanProgress_->setRange(0, 100);
        scanProgress_->setValue(0);
        cancelScanButton_ = makeButton(QStringLiteral("Cancel scan"), false, progressCard);
        cancelScanButton_->setEnabled(false);
        progressLayout->addWidget(scanStatus_);
        progressLayout->addWidget(scanProgress_);
        progressLayout->addWidget(cancelScanButton_, 0, Qt::AlignRight);
        connect(cancelScanButton_, &QPushButton::clicked, this, [this] {
            if (scanCancelled_)
                scanCancelled_->store(true);
            cancelScanButton_->setEnabled(false);
            scanStatus_->setText(QStringLiteral("Cancelling scan…"));
        });
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
        saveSettingsButton_ = makeButton(QStringLiteral("Save settings"), true);
        saveSettingsButton_->setEnabled(false);
        auto *page = pageContainer(QStringLiteral("Settings"),
                                   QStringLiteral("Tune scanning and notifications. Daemon-level features may require administrator configuration."),
                                   saveSettingsButton_);
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
        startMinimizedCheck_ = new QCheckBox(QStringLiteral("Start KlamAV minimized to the system tray"), experienceCard);
        startMinimizedCheck_->setObjectName(QStringLiteral("startMinimizedCheck"));
        startMinimizedCheck_->setToolTip(QStringLiteral(
            "When enabled, KlamAV starts hidden in the tray. Selecting this also enables the tray icon."));
        experienceLayout->addWidget(notificationCheck_);
        experienceLayout->addWidget(startupCheck_);
        experienceLayout->addWidget(trayCheck_);
        experienceLayout->addWidget(startMinimizedCheck_);
        contentLayout->addWidget(experienceCard);

        auto *protectionCard = makeCard(QStringLiteral("Protection and schedule"),
                                        QStringLiteral("Scheduled scans use a per-user systemd timer and run without the window open. Real-time protection is not active in this build."), content);
        auto *protectionLayout = qobject_cast<QVBoxLayout *>(protectionCard->layout());
        realtimeCheck_ = new QCheckBox(QStringLiteral("Store real-time protection preference (not active in this build)"), protectionCard);
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
        startMinimizedCheck_->setChecked(settings_.value(QStringLiteral("desktop/startMinimized"), false).toBool());
        connect(trayCheck_, &QCheckBox::toggled, this, [this](bool enabled) {
            if (!enabled)
                startMinimizedCheck_->setChecked(false);
        });
        connect(startMinimizedCheck_, &QCheckBox::toggled, this, [this](bool enabled) {
            if (enabled && !trayCheck_->isChecked())
                trayCheck_->setChecked(true);
        });
        realtimeCheck_->setChecked(settings_.value(QStringLiteral("protection/realtime"), false).toBool());
        scheduleCombo_->setCurrentIndex(settings_.value(QStringLiteral("scan/schedule"), 0).toInt());
        connect(saveSettingsButton_, &QPushButton::clicked, this, &MainWindow::saveSettings);
        const auto updateSaveState = [this] { updateSettingsSaveButton(); };
        connect(maxFileSize_, &QSpinBox::valueChanged, this, updateSaveState);
        connect(archiveCheck_, &QCheckBox::toggled, this, updateSaveState);
        connect(symlinkCheck_, &QCheckBox::toggled, this, updateSaveState);
        connect(recursiveCheck_, &QCheckBox::toggled, this, updateSaveState);
        connect(intensityCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, updateSaveState);
        connect(notificationCheck_, &QCheckBox::toggled, this, updateSaveState);
        connect(startupCheck_, &QCheckBox::toggled, this, updateSaveState);
        connect(trayCheck_, &QCheckBox::toggled, this, updateSaveState);
        connect(startMinimizedCheck_, &QCheckBox::toggled, this, updateSaveState);
        connect(realtimeCheck_, &QCheckBox::toggled, this, updateSaveState);
        connect(scheduleCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, updateSaveState);
        updateSettingsSaveButton();
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
        QString stylesheet = QStringLiteral(R"(
            QWidget#root { background: #f5f7fb; color: #17233c; font-family: "Noto Sans", "Inter", sans-serif; font-size: 13px; }
            QLabel { background-color: transparent; background-image: none; }
            QWidget#sidebar { background: #111d35; color: #f5f7ff; }
            QWidget#sidebar QLabel { background: transparent; }
            QLabel#brandMark { background-color: transparent; color: #0c3025; border-radius: 12px; font-size: 22px; font-weight: 800; }
            QLabel#brandName { color: #fff; font-size: 19px; font-weight: 700; }
            QLabel#sideNote { color: #8492ad; font-size: 10px; letter-spacing: 1px; }
            QPushButton#navButton { text-align: left; padding: 0 14px; border: 0; border-radius: 10px; color: #aab6cb; background: transparent; font-weight: 600; }
            QPushButton#navButton[compact="true"] { text-align: center; padding: 0; }
            QPushButton#navButton:hover { background: #1c2b49; color: white; }
            QPushButton#navButton:checked { background: #243653; color: #66e0af; }
            QLabel#pageTitle { font-size: 20px; font-weight: 700; color: #17233c; }
            QLabel#sectionTitle { font-size: 25px; font-weight: 750; color: #14213b; }
            QLabel#muted { color: #71809a; }
            QLabel#cardTitle { color: #182743; font-size: 15px; font-weight: 700; }
            QLabel#heroStatus { color: #14845c; font-size: 17px; font-weight: 700; }
            QLabel#statValue { color: #192845; font-size: 24px; font-weight: 750; }
            QLabel#lastScan { color: #52617a; font-size: 14px; }
            QLabel#statusPill { background-color: transparent; color: #18835b; border-radius: 12px; padding: 7px 12px; font-weight: 700; }
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
            QWidget#jobStatusBar { background: #e9eef5; border-radius: 8px; }
            QLabel#jobStatusLabel { color: #52617a; }
            QLabel#versionLabel { color: #8492ad; font-size: 10px; }
        )");
        if (palette().color(QPalette::Window).lightness() < 128) {
            stylesheet += QStringLiteral(R"(
                QWidget#root { background: #171b24; color: #e6eaf2; }
                QLabel { background-color: transparent; background-image: none; }
                QWidget#sidebar { background: #10141c; color: #f5f7ff; }
                QLabel#pageTitle, QLabel#sectionTitle, QLabel#cardTitle,
                QLabel#statValue, QLabel#lastScan { color: #e6eaf2; }
                QLabel#muted { color: #a4afc2; }
                QLabel#heroStatus { color: #63d7a4; }
                QLabel#statusPill { background: #153a30; color: #7ee0b6; }
                QWidget#card { background: #202632; border-color: #303948; }
                QPushButton#button { background: #293241; border-color: #3a4659; color: #e6eaf2; }
                QPushButton#button:hover { background: #354156; }
                QTableWidget { background: #202632; color: #e6eaf2; border-color: #303948;
                               gridline-color: #303948; selection-background-color: #234b3f;
                               selection-color: #f3fff9; }
                QHeaderView::section { background: #252d3a; color: #bbc5d5; border-bottom-color: #3a4659; }
                QProgressBar { background: #303948; }
                QComboBox, QSpinBox { background: #202632; color: #e6eaf2; border-color: #3a4659; }
                QCheckBox { color: #d7deea; }
                QWidget#jobStatusBar { background: #252d3a; }
                QLabel#jobStatusLabel, QLabel#versionLabel { color: #a4afc2; }
            )");
        }
        setStyleSheet(stylesheet);
    }

    void updateResponsiveLayout()
    {
        const bool compact = width() < 900;
        sidebar_->setFixedWidth(compact ? 74 : 238);
        brandName_->setVisible(!compact);
        sideNote_->setVisible(!compact);
        for (auto *button : findChildren<QPushButton *>(QStringLiteral("navButton"))) {
            button->setText(compact
                ? button->property("navIcon").toString()
                : button->property("navIcon").toString() + QStringLiteral("   ")
                    + button->property("navLabel").toString());
            button->setProperty("compact", compact);
            button->style()->unpolish(button);
            button->style()->polish(button);
        }
        if (root_)
            root_->style()->unpolish(root_);
        if (root_)
            root_->style()->polish(root_);
    }

    void resizeEvent(QResizeEvent *event) override
    {
        QMainWindow::resizeEvent(event);
        updateResponsiveLayout();
    }

    void changeEvent(QEvent *event) override
    {
        QMainWindow::changeEvent(event);
        if (event->type() == QEvent::ApplicationPaletteChange)
            applyStyle();
    }

    int workerLimit() const
    {
        return configuredWorkerLimit(intensityCombo_ ? intensityCombo_->currentIndex()
            : settings_.value(QStringLiteral("scan/intensity"), 1).toInt());
    }

    bool settingsHaveChanged() const
    {
        return maxFileSize_->value() != settings_.value(QStringLiteral("scan/maxFileSizeMb"), 64).toInt()
            || archiveCheck_->isChecked() != settings_.value(QStringLiteral("scan/archives"), true).toBool()
            || symlinkCheck_->isChecked() != settings_.value(QStringLiteral("scan/followSymlinks"), false).toBool()
            || recursiveCheck_->isChecked() != settings_.value(QStringLiteral("scan/recursive"), true).toBool()
            || intensityCombo_->currentIndex() != settings_.value(QStringLiteral("scan/intensity"), 1).toInt()
            || notificationCheck_->isChecked() != settings_.value(QStringLiteral("desktop/notifications"), true).toBool()
            || startupCheck_->isChecked() != settings_.value(QStringLiteral("desktop/startup"), false).toBool()
            || trayCheck_->isChecked() != settings_.value(QStringLiteral("desktop/tray"), true).toBool()
            || startMinimizedCheck_->isChecked()
                != settings_.value(QStringLiteral("desktop/startMinimized"), false).toBool()
            || realtimeCheck_->isChecked() != settings_.value(QStringLiteral("protection/realtime"), false).toBool()
            || scheduleCombo_->currentIndex() != settings_.value(QStringLiteral("scan/schedule"), 0).toInt();
    }

    void updateSettingsSaveButton()
    {
        if (saveSettingsButton_)
            saveSettingsButton_->setEnabled(settingsHaveChanged());
    }

    void refreshJobStatus()
    {
        if (activeJobs_.isEmpty()) {
            jobStatusLabel_->setText(QStringLiteral("Ready"));
            jobProgressBar_->hide();
            trayAnimationTimer_.stop();
            trayAnimationFrame_ = 0;
            if (trayIcon_) {
                trayIcon_->setIcon(makeTrayIcon());
                trayIcon_->setToolTip(QStringLiteral("KlamAV"));
            }
            return;
        }

        QStringList jobDescriptions;
        for (auto it = activeJobs_.cbegin(); it != activeJobs_.cend(); ++it)
            jobDescriptions.push_back(it.value());
        jobStatusLabel_->setText(jobDescriptions.join(QStringLiteral("  |  ")));
        jobProgressBar_->show();
        if (trayIcon_) {
            trayIcon_->setToolTip(QStringLiteral("KlamAV — Running: %1")
                                      .arg(jobDescriptions.join(QStringLiteral(", "))));
            if (trayIcon_->isVisible() && !trayAnimationTimer_.isActive())
                trayAnimationTimer_.start();
        }
    }

    void startJob(const QString &id, const QString &description)
    {
        activeJobs_.insert(id, description);
        refreshJobStatus();
    }

    void updateJob(const QString &id, const QString &description)
    {
        if (!activeJobs_.contains(id))
            return;
        activeJobs_[id] = description;
        refreshJobStatus();
    }

    void finishJob(const QString &id)
    {
        activeJobs_.remove(id);
        refreshJobStatus();
    }

    void finishDaemonCheck(QProcess *process, bool available)
    {
        if (daemonProbe_ != process)
            return;
        daemonProbe_ = nullptr;
        daemonStatusKnown_ = true;
        daemonIsAvailable_ = available;
        process->deleteLater();
        refreshDashboardStatus();
        const auto callbacks = std::exchange(daemonProbeCallbacks_, {});
        for (const auto &callback : callbacks)
            callback(available);
    }

    void checkDaemonAvailability(std::function<void(bool)> callback = {})
    {
        if (callback)
            daemonProbeCallbacks_.push_back(std::move(callback));
        if (daemonProbe_)
            return;
        if (QStandardPaths::findExecutable(QStringLiteral("clamdscan")).isEmpty()) {
            daemonStatusKnown_ = true;
            daemonIsAvailable_ = false;
            refreshDashboardStatus();
            const auto callbacks = std::exchange(daemonProbeCallbacks_, {});
            for (const auto &pending : callbacks)
                pending(false);
            return;
        }
        auto *process = new QProcess(this);
        daemonProbe_ = process;
        connect(process, &QProcess::finished, this,
                [this, process](int exitCode, QProcess::ExitStatus exitStatus) {
            finishDaemonCheck(process, exitStatus == QProcess::NormalExit && exitCode == 0);
        });
        connect(process, &QProcess::errorOccurred, this,
                [this, process](QProcess::ProcessError) {
            if (process->state() == QProcess::NotRunning)
                finishDaemonCheck(process, false);
        });
        QTimer::singleShot(3000, process, [this, process] {
            if (daemonProbe_ != process)
                return;
            process->kill();
            finishDaemonCheck(process, false);
        });
        process->start(QStringLiteral("clamdscan"), {QStringLiteral("--ping=1")});
    }

    void startScan(const QStringList &targets, bool fullScan = false)
    {
        if (scanInProgress_) {
            QMessageBox::information(this, QStringLiteral("Scan in progress"),
                                     QStringLiteral("Please wait for the current scan to finish."));
            return;
        }
        if (QStandardPaths::findExecutable(QStringLiteral("clamdscan")).isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("ClamAV scanner not found"),
                                 QStringLiteral("Install ClamAV and make sure clamdscan is available on your PATH."));
            return;
        }
        checkDaemonAvailability([this, targets, fullScan](bool available) {
            if (!available) {
                QMessageBox::warning(this, QStringLiteral("ClamAV daemon is not running"),
                                     QStringLiteral("Start and configure the ClamAV daemon before scanning."));
                return;
            }
            beginScan(targets, fullScan);
        });
    }

    void appendScanResults(const QVector<FileResult> &results)
    {
        int currentThreats = settings_.value(QStringLiteral("stats/threats"), 0).toInt();
        bool threatCountChanged = false;
        for (const FileResult &file : results) {
            if (!file.infected && file.status != QStringLiteral("Error"))
                continue;
            if (displayedScanResults_.contains(file.path))
                continue;
            displayedScanResults_.insert(file.path);
            const int row = scanResults_->rowCount();
            scanResults_->insertRow(row);
            scanResults_->setItem(row, 0, new QTableWidgetItem(file.path));
            scanResults_->setItem(row, 1, new QTableWidgetItem(file.status));
            scanResults_->setItem(row, 2, new QTableWidgetItem(file.detail));
            if (file.infected) {
                ++currentThreats;
                threatCountChanged = true;
                addHistory(QStringLiteral("Detection"), file.path, QStringLiteral("Threat detected"));
            }
        }
        if (threatCountChanged)
            settings_.setValue(QStringLiteral("stats/threats"), currentThreats);
        if (!results.isEmpty())
            refreshDashboard();
    }

    void updateScanProgress(const ScanProgress &progress)
    {
        appendScanResults(progress.notableResults);
        if (progress.scanned > 0) {
            scanProgress_->setRange(0, 0);
            scanStatus_->setText(QStringLiteral("Scanned %1 of %2 found · %3 too large · %4 archive(s) skipped · %5 unreadable · %6 excluded")
                                     .arg(progress.scanned).arg(progress.discovered)
                                     .arg(progress.skippedLarge)
                                     .arg(progress.skippedArchives).arg(progress.skippedUnreadable)
                                     .arg(progress.excluded));
        } else {
            scanStatus_->setText(QStringLiteral("Finding files · %1 found so far · %2 too large · %3 archive(s) skipped")
                                     .arg(progress.discovered).arg(progress.skippedLarge)
                                     .arg(progress.skippedArchives));
        }
        updateJob(QStringLiteral("scan"), scanStatus_->text());
    }

    void beginScan(const QStringList &targets, bool fullScan)
    {
        if (scanInProgress_)
            return;
        scanInProgress_ = true;
        startJob(QStringLiteral("scan"), QStringLiteral("Scanning %1").arg(targets.join(QStringLiteral(", "))));
        const int generation = ++scanGeneration_;
        scanResults_->setRowCount(0);
        displayedScanResults_.clear();
        scanProgress_->setRange(0, 0);
        scanStatus_->setText(QStringLiteral("Preparing scan…"));
        cancelScanButton_->setEnabled(true);
        scanCancelled_ = std::make_shared<std::atomic_bool>(false);
        const auto cancellation = scanCancelled_;
        ScanOptions options;
        options.targets = targets;
        options.fullScan = fullScan;
        options.maxFileBytes = static_cast<qint64>(maxFileSize_ ? maxFileSize_->value()
            : settings_.value(QStringLiteral("scan/maxFileSizeMb"), 64).toInt()) * 1024 * 1024;
        options.recursive = recursiveCheck_ ? recursiveCheck_->isChecked()
            : settings_.value(QStringLiteral("scan/recursive"), true).toBool();
        options.followSymlinks = symlinkCheck_ ? symlinkCheck_->isChecked()
            : settings_.value(QStringLiteral("scan/followSymlinks"), false).toBool();
        options.scanArchives = archiveCheck_ ? archiveCheck_->isChecked()
            : settings_.value(QStringLiteral("scan/archives"), true).toBool();
        options.workers = workerLimit();
        auto *watcher = new QFutureWatcher<ScanSummary>(this);
        scanWatcher_ = watcher;
        connect(watcher, &QFutureWatcher<ScanSummary>::finished, this, [this, watcher, generation] {
            const ScanSummary summary = watcher->result();
            if (generation == scanGeneration_)
                appendScanResults(summary.notableResults);
            cancelScanButton_->setEnabled(false);
            scanProgress_->setRange(0, 100);
            scanProgress_->setValue(summary.cancelled ? 0 : 100);
            const QString result = QStringLiteral("%1 checked, %2 threat(s), %3 error(s), %4 skipped by size, %5 archive(s) excluded, %6 unreadable, %7 excluded path(s)%8")
                .arg(summary.scanned).arg(summary.infected).arg(summary.errors)
                .arg(summary.skippedLarge).arg(summary.skippedArchives)
                .arg(summary.skippedUnreadable).arg(summary.excluded)
                .arg(summary.cancelled ? QStringLiteral(" (cancelled)") : QString());
            scanStatus_->setText(summary.cancelled
                ? QStringLiteral("Scan cancelled · %1").arg(result)
                : QStringLiteral("Scan complete · %1").arg(result));
            addHistory(QStringLiteral("Scan"), summary.target, result);
            settings_.setValue(QStringLiteral("lastScan/time"), QDateTime::currentDateTime().toString(Qt::ISODate));
            settings_.setValue(QStringLiteral("lastScan/result"), result);
            settings_.sync();
            if (settings_.status() != QSettings::NoError)
                QMessageBox::warning(this, QStringLiteral("Could not save scan history"),
                                     QStringLiteral("The scan completed, but KlamAV could not save the updated history."));
            refreshDashboard();
            if (summary.infected > 0 && notificationCheck_->isChecked() && trayIcon_)
                trayIcon_->showMessage(QStringLiteral("KlamAV detected threats"),
                                       QStringLiteral("%1 infected file(s) found.").arg(summary.infected),
                                       QSystemTrayIcon::Warning);
            if (scanWatcher_ == watcher)
                scanWatcher_ = nullptr;
            scanInProgress_ = false;
            finishJob(QStringLiteral("scan"));
            ++scanGeneration_;
            watcher->deleteLater();
        });
        QPointer<MainWindow> guard(this);
        const auto progress = [guard, generation](const ScanProgress &update) {
            if (!guard)
                return;
            QMetaObject::invokeMethod(guard, [guard, update, generation] {
                if (guard && guard->scanGeneration_ == generation)
                    guard->updateScanProgress(update);
            }, Qt::QueuedConnection);
        };
        watcher->setFuture(QtConcurrent::run([options, cancellation, progress] {
            return ScanEngine::run(options, *cancellation, progress);
        }));
    }

    void updateDefinitions()
    {
        if (definitionUpdateInProgress_) {
            QMessageBox::information(this, QStringLiteral("Update in progress"),
                                     QStringLiteral("Virus definitions are already being updated."));
            return;
        }
        if (QStandardPaths::findExecutable(QStringLiteral("freshclam")).isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("Updater not found"),
                                 QStringLiteral("Install ClamAV and make sure freshclam is available on your PATH."));
            return;
        }
        definitionUpdateInProgress_ = true;
        auto *process = new QProcess(this);
        process->setProgram(QStringLiteral("freshclam"));
        process->setArguments({QStringLiteral("--stdout")});
        const auto handled = std::make_shared<bool>(false);
        connect(process, &QProcess::errorOccurred, this, [this, process, handled](QProcess::ProcessError error) {
            if (error != QProcess::FailedToStart || *handled)
                return;
            *handled = true;
            definitionUpdateInProgress_ = false;
            finishJob(QStringLiteral("definitions"));
            addHistory(QStringLiteral("Update"), QStringLiteral("Virus definitions"),
                       QStringLiteral("Failed: %1").arg(process->errorString()));
            QMessageBox::warning(this, QStringLiteral("Update failed"), process->errorString());
            process->deleteLater();
        });
        connect(process, &QProcess::finished, this, [this, process, handled](int exitCode, QProcess::ExitStatus) {
            if (*handled)
                return;
            *handled = true;
            const QString output = QString::fromLocal8Bit(process->readAllStandardOutput()
                                                          + process->readAllStandardError()).trimmed();
            const bool success = exitCode == 0;
            definitionUpdateInProgress_ = false;
            finishJob(QStringLiteral("definitions"));
            addHistory(QStringLiteral("Update"), QStringLiteral("Virus definitions"),
                       success ? QStringLiteral("Updated successfully") : QStringLiteral("Failed (exit %1)").arg(exitCode));
            QMessageBox::information(this, success ? QStringLiteral("Definitions updated") : QStringLiteral("Update failed"),
                                     output.isEmpty() ? (success ? QStringLiteral("Virus definitions are up to date.")
                                                                 : QStringLiteral("freshclam exited with code %1.").arg(exitCode))
                                                      : output);
            refreshDashboard();
            process->deleteLater();
        });
        startJob(QStringLiteral("definitions"), QStringLiteral("Updating virus definitions"));
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
        settings_.setValue(QStringLiteral("desktop/startMinimized"),
                           startMinimizedCheck_->isChecked() && trayCheck_->isChecked());
        settings_.setValue(QStringLiteral("protection/realtime"), realtimeCheck_->isChecked());
        settings_.setValue(QStringLiteral("scan/schedule"), scheduleCombo_->currentIndex());
        settings_.remove(QStringLiteral("scan/nextRun"));
        settings_.remove(QStringLiteral("scan/previousSchedule"));
        settings_.sync();
        if (settings_.status() != QSettings::NoError) {
            QMessageBox::warning(this, QStringLiteral("Could not save settings"),
                                 QStringLiteral("KlamAV could not write preferences to the settings store."));
            return;
        }
        updateSettingsSaveButton();

        QStringList failures;
        QString error;
        if (!saveAutostartEntry(startupCheck_->isChecked(), &error))
            failures.push_back(QStringLiteral("Login startup: %1").arg(error));
        if (!SystemdScheduler::configure(scheduleCombo_->currentIndex(),
                                         QCoreApplication::applicationFilePath(), &error))
            failures.push_back(QStringLiteral("Scheduled scans: %1").arg(error));
        if (trayCheck_->isChecked() && QSystemTrayIcon::isSystemTrayAvailable())
            ensureTrayIcon();
        else if (trayIcon_) {
            trayIcon_->hide();
            trayAnimationTimer_.stop();
            trayIcon_->setIcon(makeTrayIcon());
            trayIcon_->setToolTip(QStringLiteral("KlamAV"));
        }
        if (failures.isEmpty()) {
            QMessageBox::information(this, QStringLiteral("Settings saved"),
                                     QStringLiteral("Preferences and desktop integrations were updated."));
        } else {
            QMessageBox::warning(this, QStringLiteral("Settings partially saved"),
                                 QStringLiteral("Preferences were saved, but these integrations were not updated:\n\n%1")
                                     .arg(failures.join(QLatin1Char('\n'))));
        }
    }

    bool saveAutostartEntry(bool enabled, QString *error)
    {
        const QString path = QDir(QStandardPaths::writableLocation(QStandardPaths::ConfigLocation))
                                 .filePath(QStringLiteral("autostart/org.klamav.KlamAV.desktop"));
        if (!enabled) {
            if (QFileInfo::exists(path) && !QFile::remove(path)) {
                if (error)
                    *error = QStringLiteral("Could not remove the autostart entry.");
                return false;
            }
            return true;
        }
        if (!QDir().mkpath(QFileInfo(path).absolutePath())) {
            if (error)
                *error = QStringLiteral("Could not create the autostart folder.");
            return false;
        }
        QString executable = QCoreApplication::applicationFilePath();
        executable.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
        executable.replace(QLatin1Char('"'), QStringLiteral("\\\""));
        QSaveFile file(path);
        const QByteArray entry = (QStringLiteral("[Desktop Entry]\nType=Application\nName=KlamAV\n")
            + QStringLiteral("Comment=ClamAV antivirus frontend\nExec=\"%1\"\nTerminal=false\n")
                  .arg(executable)).toUtf8();
        if (!file.open(QIODevice::WriteOnly) || file.write(entry) != entry.size() || !file.commit()) {
            if (error)
                *error = QStringLiteral("Could not write the autostart entry.");
            return false;
        }
        return true;
    }

    void ensureTrayIcon()
    {
        if (trayIcon_) {
            trayIcon_->show();
            refreshJobStatus();
            return;
        }
        trayIcon_ = new QSystemTrayIcon(makeTrayIcon(), this);
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
        refreshJobStatus();
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

    void refreshDashboardStatus()
    {
        const bool scannerInstalled = !QStandardPaths::findExecutable(QStringLiteral("clamdscan")).isEmpty();
        const QString status = !scannerInstalled ? QStringLiteral("Scanner not installed")
            : (!daemonStatusKnown_ ? QStringLiteral("Checking scanner…")
               : (daemonIsAvailable_ ? QStringLiteral("Scanner ready") : QStringLiteral("Daemon offline")));
        if (headerStatus_)
            headerStatus_->setText(QStringLiteral("●  %1").arg(status));
        if (dashboardProtection_)
            dashboardProtection_->setText(status);
        if (dashboardHeroStatus_) {
            const QString heroStatus = !scannerInstalled ? QStringLiteral("ClamAV scanner is not installed")
                : (!daemonStatusKnown_ ? QStringLiteral("Checking ClamAV scanner…")
                   : (daemonIsAvailable_ ? QStringLiteral("On-demand scans are ready")
                                         : QStringLiteral("ClamAV daemon is not responding")));
            dashboardHeroStatus_->setText(heroStatus);
        }
    }

    void refreshDashboard()
    {
        refreshDashboardStatus();
        if (!daemonStatusKnown_ && !daemonProbe_)
            checkDaemonAvailability();
        if (dashboardDefinitions_) {
            const QStringList definitions = QDir(QStringLiteral("/var/lib/clamav"))
                                                .entryList({QStringLiteral("*.cvd"), QStringLiteral("*.cld")}, QDir::Files);
            const QStringList userDefinitions = QDir(QDir::homePath() + QStringLiteral("/.clamav"))
                                                   .entryList({QStringLiteral("*.cvd"), QStringLiteral("*.cld")}, QDir::Files);
            dashboardDefinitions_->setText(!definitions.isEmpty() || !userDefinitions.isEmpty()
                                               ? QStringLiteral("Files found")
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
    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == QStringLiteral("--scheduled-scan")) {
        QCoreApplication app(argc, argv);
        QCoreApplication::setApplicationName(AppName);
        QCoreApplication::setOrganizationName(AppName);
        QCoreApplication::setApplicationVersion(QStringLiteral(KLAMAV_VERSION));
        return runScheduledScan();
    }
    QApplication app(argc, argv);
    QApplication::setApplicationName(AppName);
    QApplication::setOrganizationName(AppName);
    QApplication::setApplicationDisplayName(QStringLiteral("KlamAV Antivirus"));
    QCoreApplication::setApplicationVersion(QStringLiteral(KLAMAV_VERSION));
    MainWindow window;
    if (!window.startsMinimizedToTray())
        window.show();
    return app.exec();
}

#include "main.moc"
