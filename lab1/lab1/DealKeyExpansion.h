#pragma once
#include "IKeyExpansion.h"
namespace crypto
{
    class DealKeyExpansion final : public IKeyExpansion
    {
    public:
        std::vector<std::vector<std::uint8_t>> expandKey(
            const std::vector<std::uint8_t>& key) const override;
    };
}
