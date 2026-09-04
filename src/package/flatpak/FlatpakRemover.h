#pragma once
#include "../../core/IApplicationRemover.h"

class FlatpakRemover final : public IApplicationRemover
{
public:
    QString name() const override;
    bool supports(const ApplicationInfo &application) const override;
    RemovalResult remove(const RemovalRequest &request) override;
};
