#include "main_window.h"

#include <QApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QIcon>
#include <QTimer>
#include <cstdio>

namespace {
const QString AppName = QStringLiteral("KlamAV");
}

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);
  QApplication::setApplicationName(AppName);
  QApplication::setOrganizationName(AppName);
  QApplication::setApplicationDisplayName(QStringLiteral("KlamAV Antivirus"));
  QApplication::setApplicationVersion(QStringLiteral(KLAMAV_VERSION));
  QApplication::setWindowIcon(
      QIcon::fromTheme(QStringLiteral("org.klamav.KlamAV"),
                       QIcon(QStringLiteral(":/icons/org.klamav.KlamAV.svg"))));
  QCommandLineParser parser;
  parser.setApplicationDescription(
      QStringLiteral("KDE-friendly ClamAV antivirus frontend"));
  parser.addHelpOption();
  parser.addVersionOption();
  parser.addOption(QCommandLineOption(
      QStringList{QStringLiteral("s"), QStringLiteral("scan")},
      QStringLiteral("Scan the specified files and folders.")));
  parser.addPositionalArgument(QStringLiteral("paths"),
                               QStringLiteral("Files or folders to scan."),
                               QStringLiteral("[paths...]"));
  parser.process(app);
  const QStringList paths = parser.positionalArguments();
  if (parser.isSet(QStringLiteral("scan")) && paths.isEmpty()) {
    fprintf(stderr,
            "klamav: --scan requires at least one file or folder path\n");
    return 2;
  }
  MainWindow window;
  window.show();
  if (parser.isSet(QStringLiteral("scan")))
    QTimer::singleShot(0, &window,
                       [&window, paths] { window.scanPaths(paths); });
  return app.exec();
}
