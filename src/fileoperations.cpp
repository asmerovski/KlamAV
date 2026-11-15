#include "fileoperations.h"

#include <QFile>

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
