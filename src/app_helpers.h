#pragma once

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QPushButton>
#include <QStringList>
#include <QVBoxLayout>
#include <QWidget>

namespace AppHelpers {

inline QWidget *makeCard(const QString &title, const QString &subtitle,
                         QWidget *parent = nullptr) {
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

inline QPushButton *makeButton(const QString &text, bool primary = false,
                               QWidget *parent = nullptr) {
  auto *button = new QPushButton(text, parent);
  button->setObjectName(primary ? QStringLiteral("primaryButton")
                                : QStringLiteral("button"));
  button->setCursor(Qt::PointingHandCursor);
  button->setMinimumHeight(40);
  return button;
}

inline QStringList quickScanTargets() {
  const QString home = QDir::homePath();
  QStringList targets;
  for (const QString &folder :
       {QStringLiteral("Downloads"), QStringLiteral("Desktop"),
        QStringLiteral("Documents")}) {
    const QString path = QDir(home).filePath(folder);
    if (QFileInfo(path).isDir())
      targets.push_back(path);
  }
  if (targets.isEmpty())
    targets.push_back(home);
  return targets;
}

inline QString displayTargets(const QStringList &targets) {
  return targets.join(QStringLiteral(", "));
}

inline bool moveFile(const QString &source, const QString &destination) {
  if (QFile::rename(source, destination))
    return true;
  if (!QFile::copy(source, destination))
    return false;
  if (QFile::remove(source))
    return true;
  QFile::remove(destination);
  return false;
}

} // namespace AppHelpers
