#pragma once

#include <cstdint>
#include <vector>

namespace crypto
{
    // Интерфейс для получения раундовых ключей из исходного ключа.
    class IKeyExpansion
    {
    public:
        virtual ~IKeyExpansion() = default;

        // Каждый элемент результата — отдельный раундовый ключ из байтов.
        // Длина ключа и число раундов зависят от алгоритма.
        virtual std::vector<std::vector<std::uint8_t>> expandKey(
            const std::vector<std::uint8_t>& key) const = 0;
    };
}
