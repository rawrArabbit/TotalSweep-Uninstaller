#pragma once

#include <QString>
#include <QStringList>

struct RemovalResult {
    bool success = false;
    bool authenticationRequired = false;

    QString message;
    QString error;

    QStringList removedItems;
    QStringList preservedItems;
    QStringList warnings;
};
