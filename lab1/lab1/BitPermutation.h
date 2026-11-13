#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace crypto
{
    enum class BitOrder { MostSignificantFirst, LeastSignificantFirst };
    enum class BitIndexBase { Zero, One };

    // Байты идём с начала массива, порядок битов задаём внутри байта.
    // pBlock[i] — номер входного бита, который ставим на место i.
    // Индексы могут повторяться, длина таблицы может быть любой.
    // Лишние биты последнего байта оставляем нулевыми.
    inline std::vector<std::uint8_t> permuteBits(
        const std::vector<std::uint8_t>& input,
        const std::vector<std::size_t>& pBlock,
        BitOrder order = BitOrder::MostSignificantFirst,
        BitIndexBase indexBase = BitIndexBase::One)
    {
        if (order != BitOrder::MostSignificantFirst &&
            order != BitOrder::LeastSignificantFirst)
            throw std::invalid_argument("Unknown bit order");
        if (indexBase != BitIndexBase::Zero && indexBase != BitIndexBase::One)
            throw std::invalid_argument("Unknown bit index base");

        const std::size_t base = indexBase == BitIndexBase::One ? 1 : 0;
        std::vector<std::uint8_t> output(
            pBlock.size() / 8 + (pBlock.size() % 8 != 0), 0);

        for (std::size_t i = 0; i < pBlock.size(); ++i)
        {
            if (pBlock[i] < base)
                throw std::out_of_range("P-block index is below the index base");
            const std::size_t source = pBlock[i] - base;
            if (source / 8 >= input.size())
                throw std::out_of_range("P-block index exceeds the input size");

            const std::size_t sourceShift = order == BitOrder::MostSignificantFirst
                ? 7 - source % 8 : source % 8;
            const std::size_t targetShift = order == BitOrder::MostSignificantFirst
                ? 7 - i % 8 : i % 8;
            const auto bit = (input[source / 8] >> sourceShift) & 1u;
            output[i / 8] |= static_cast<std::uint8_t>(bit << targetShift);
        }
        return output;
    }
}
