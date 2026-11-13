#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace crypto
{
    class IBlockCipher
    {
    public:
        virtual ~IBlockCipher() = default;
        virtual void setKey(const std::vector<std::uint8_t>& key) = 0;
        virtual std::size_t blockSize() const = 0; // Размер в байтах.

        // После установки ключа методы должны допускать вызовы из разных потоков.
        virtual std::vector<std::uint8_t> encryptBlock(
            const std::vector<std::uint8_t>& block) const = 0;
        virtual std::vector<std::uint8_t> decryptBlock(
            const std::vector<std::uint8_t>& block) const = 0;
    };
}
