#pragma once

#include "IApplicationDetector.h"
#include "IApplicationRemover.h"

class IApplicationBackend
{
public:
    virtual ~IApplicationBackend() = default;

    virtual QString name() const = 0;

    virtual bool isAvailable() const = 0;

    virtual IApplicationDetector *detector() = 0;

    virtual IApplicationRemover *remover() = 0;
};
