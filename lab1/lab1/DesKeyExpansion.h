#pragma once
#include "IKeyExpansion.h"
namespace crypto
{
    class DesKeyExpansion final : public IKeyExpansion
    {
    public:
        // Ключ 8 байтов, биты чётности отбрасываем в PC-1 без проверки.
        std::vector<std::vector<std::uint8_t>> expandKey(
            const std::vector<std::uint8_t>& key) const override;
    };
}
