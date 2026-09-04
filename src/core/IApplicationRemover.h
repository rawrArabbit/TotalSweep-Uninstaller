#pragma once

#include "ApplicationInfo.h"
#include "RemovalRequest.h"
#include "RemovalResult.h"

class IApplicationRemover
{
public:
    virtual ~IApplicationRemover() = default;

    virtual QString name() const = 0;

    virtual bool supports(const ApplicationInfo &application) const = 0;

    virtual RemovalResult remove(
        const RemovalRequest &request) = 0;
};
