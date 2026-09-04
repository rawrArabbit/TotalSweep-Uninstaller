#pragma once

#include "ApplicationInfo.h"

struct RemovalRequest {
    ApplicationInfo application;

    bool removeUserData = false;
    bool removeConfiguration = false;
    bool removeCaches = false;
    bool removeDesktopEntries = false;
    bool removeDependencies = false;

    bool quarantine = true;
    bool force = false;

    RiskLevel confirmedRisk = RiskLevel::Unknown;
};
