#pragma once
#include "IRoundFunction.h"
namespace crypto
{
    // Используем полное шифрование DES как раундовую функцию DEAL.
    class DesRoundAdapter final : public IRoundFunction
    {
    public:
        std::vector<std::uint8_t> transform(
            const std::vector<std::uint8_t>& block,
            const std::vector<std::uint8_t>& roundKey) const override;
    };
}
