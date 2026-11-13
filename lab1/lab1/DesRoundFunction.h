#pragma once
#include "IRoundFunction.h"
namespace crypto
{
    class DesRoundFunction final : public IRoundFunction
    {
    public:
        std::vector<std::uint8_t> transform(
            const std::vector<std::uint8_t>& block,
            const std::vector<std::uint8_t>& roundKey) const override;
    };
}
