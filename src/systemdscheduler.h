#pragma once

#include <QString>

class SystemdScheduler final {
public:
    static bool configure(int schedule, const QString &executable, QString *error = nullptr);
};
