#include "DealCipher.h"
#include "DealKeyExpansion.h"
#include "DesRoundAdapter.h"
#include "DesCipher.h"
#include <stdexcept>

namespace crypto
{
    std::vector<std::uint8_t> DesRoundAdapter::transform(
        const std::vector<std::uint8_t>& block,
        const std::vector<std::uint8_t>& roundKey) const
    {
        if (block.size() != 8 || roundKey.size() != 8)
            throw std::invalid_argument("DEAL round requires 8 data bytes and 8 key bytes");
        // У каждого вызова свой DES, чтобы потоки не мешали друг другу.
        DesCipher des;
        des.setKey(roundKey);
        return des.encryptBlock(block);
    }

    std::vector<std::vector<std::uint8_t>> DealKeyExpansion::expandKey(
        const std::vector<std::uint8_t>& key) const
    {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32)
            throw std::invalid_argument("DEAL key must contain 16, 24 or 32 bytes");
        DesCipher des;
        des.setKey({0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF});

        // Складываем часть ключа, прошлый раундовый ключ и константу через XOR.
        const auto mix = [](const std::vector<std::uint8_t>& part,
            const std::vector<std::uint8_t>& previous, std::uint8_t constant)
        {
            return std::vector<std::uint8_t>{
                static_cast<std::uint8_t>(part[0] ^ previous[0] ^ constant),
                static_cast<std::uint8_t>(part[1] ^ previous[1]),
                static_cast<std::uint8_t>(part[2] ^ previous[2]),
                static_cast<std::uint8_t>(part[3] ^ previous[3]),
                static_cast<std::uint8_t>(part[4] ^ previous[4]),
                static_cast<std::uint8_t>(part[5] ^ previous[5]),
                static_cast<std::uint8_t>(part[6] ^ previous[6]),
                static_cast<std::uint8_t>(part[7] ^ previous[7])
            };
        };

        const std::vector<std::uint8_t> k1(key.begin(), key.begin() + 8);
        const std::vector<std::uint8_t> k2(key.begin() + 8, key.begin() + 16);
        const auto r1 = des.encryptBlock(k1);
        const auto r2 = des.encryptBlock(mix(k2, r1, 0x00));

        if (key.size() == 16)
        {
            // Для ключа 128 бит получаем 6 раундовых ключей.
            const auto r3 = des.encryptBlock(mix(k1, r2, 0x80));
            const auto r4 = des.encryptBlock(mix(k2, r3, 0x40));
            const auto r5 = des.encryptBlock(mix(k1, r4, 0x20));
            const auto r6 = des.encryptBlock(mix(k2, r5, 0x10));
            return {r1, r2, r3, r4, r5, r6};
        }

        const std::vector<std::uint8_t> k3(key.begin() + 16, key.begin() + 24);
        const auto r3 = des.encryptBlock(mix(k3, r2, 0x00));
        if (key.size() == 24)
        {
            // Для ключа 192 бита тоже получаем 6 раундовых ключей.
            const auto r4 = des.encryptBlock(mix(k1, r3, 0x80));
            const auto r5 = des.encryptBlock(mix(k2, r4, 0x40));
            const auto r6 = des.encryptBlock(mix(k3, r5, 0x20));
            return {r1, r2, r3, r4, r5, r6};
        }

        // Для ключа 256 бит получаем 8 раундовых ключей.
        const std::vector<std::uint8_t> k4(key.begin() + 24, key.end());
        const auto r4 = des.encryptBlock(mix(k4, r3, 0x00));
        const auto r5 = des.encryptBlock(mix(k1, r4, 0x80));
        const auto r6 = des.encryptBlock(mix(k2, r5, 0x40));
        const auto r7 = des.encryptBlock(mix(k3, r6, 0x20));
        const auto r8 = des.encryptBlock(mix(k4, r7, 0x10));
        return {r1, r2, r3, r4, r5, r6, r7, r8};
    }

    DealCipher::DealCipher()
        : network_(16, std::make_unique<DealKeyExpansion>(), std::make_unique<DesRoundAdapter>()) {}

    void DealCipher::setKey(const std::vector<std::uint8_t>& key) { network_.setKey(key); }
    std::size_t DealCipher::blockSize() const { return 16; }

    std::vector<std::uint8_t> DealCipher::swapHalves(const std::vector<std::uint8_t>& block)
    {
        if (block.size() != 16) throw std::invalid_argument("DEAL block must contain 16 bytes");
        std::vector<std::uint8_t> result(block.begin() + 8, block.end());
        result.insert(result.end(), block.begin(), block.begin() + 8);
        return result;
    }

    std::vector<std::uint8_t> DealCipher::encryptBlock(const std::vector<std::uint8_t>& block) const
    {
        // В DEAL первый раунд подаёт в DES левую половину.
        // Наша сеть начинает с правой половины и возвращает R_n || L_n.
        // Меняем половины на входе, чтобы получить нужный порядок при чётном числе раундов.
        return network_.encryptBlock(swapHalves(block));
    }

    std::vector<std::uint8_t> DealCipher::decryptBlock(const std::vector<std::uint8_t>& block) const
    {
        return swapHalves(network_.decryptBlock(block));
    }
}
