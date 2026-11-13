#pragma once
#include <cstdint>
#include <vector>

namespace crypto
{
    class IRoundFunction
    {
    public:
        virtual ~IRoundFunction() = default;

        virtual std::vector<std::uint8_t> transform(
            const std::vector<std::uint8_t>& block,
            const std::vector<std::uint8_t>& roundKey) const = 0;
    };
}
