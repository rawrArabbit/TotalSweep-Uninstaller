#pragma once

#include "../../core/IApplicationBackend.h"
#include "RpmDetector.h"
#include "RpmRemover.h"

class RpmBackend final : public IApplicationBackend
{
public:
    RpmBackend();

    QString name() const override;
    bool isAvailable() const override;

    IApplicationDetector *detector() override;
    IApplicationRemover *remover() override;

private:
    RpmDetector m_detector;
    RpmRemover m_remover;
};
