#pragma once

#include <QString>
#include <QVector>

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
  bool cancelled = false;
};
