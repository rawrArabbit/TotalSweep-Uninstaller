#pragma once

#include "../../core/IApplicationBackend.h"
#include "FlatpakDetector.h"
#include "FlatpakRemover.h"

class FlatpakBackend final : public IApplicationBackend
{
public:
    FlatpakBackend();

    QString name() const override;
    bool isAvailable() const override;

    IApplicationDetector *detector() override;
    IApplicationRemover *remover() override;

private:
    FlatpakDetector m_detector;
    FlatpakRemover m_remover;
};
