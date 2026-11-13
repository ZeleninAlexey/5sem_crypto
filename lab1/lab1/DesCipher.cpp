#include "DesCipher.h"
#include "DesKeyExpansion.h"
#include "DesRoundFunction.h"
#include "BitPermutation.h"
#include <stdexcept>

namespace crypto
{
    namespace
    {
        // По FIPS 46-3 считаем биты с 1, начиная со старшего.
        // https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
        const std::vector<std::size_t> IP = {
            58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
        };
        const std::vector<std::size_t> FP = {
            40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
        };
        const std::vector<std::size_t> E = {
            32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13,
            12,13,14,15,16,17, 16,17,18,19,20,21,
            20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1
        };
        const std::vector<std::size_t> P = {
            16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
            2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
        };
        const std::vector<std::size_t> PC1 = {
            57,49,41,33,25,17,9,1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,21,13,5,28,20,12,4
        };
        const std::vector<std::size_t> PC2 = {
            14,17,11,24,1,5,3,28,15,6,21,10,
            23,19,12,4,26,8,16,7,27,20,13,2,
            41,52,31,37,47,55,30,40,51,45,33,48,
            44,49,39,56,34,53,46,42,50,36,29,32
        };
        constexpr unsigned SHIFTS[] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
        constexpr std::uint8_t S[8][4][16] = {
            {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
             {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
             {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
             {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
            {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
             {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
             {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
             {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
            {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
             {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
             {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
             {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
            {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
             {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
             {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
             {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
            {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
             {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
             {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
             {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
            {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
             {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
             {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
             {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
            {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
             {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
             {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
             {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
            {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
             {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
             {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
             {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
        };

        std::uint32_t rotate28(std::uint32_t value, unsigned shift)
        {
            return ((value << shift) | (value >> (28 - shift))) & 0x0fffffffu;
        }
    }

    std::vector<std::vector<std::uint8_t>> DesKeyExpansion::expandKey(
        const std::vector<std::uint8_t>& key) const
    {
        if (key.size() != 8) throw std::invalid_argument("DES key must contain 8 bytes");
        const auto selected = permuteBits(key, PC1);
        std::uint64_t packed = 0;
        for (auto byte : selected) packed = (packed << 8) | byte;
        auto left = static_cast<std::uint32_t>(packed >> 28);
        auto right = static_cast<std::uint32_t>(packed & 0x0fffffffu);
        std::vector<std::vector<std::uint8_t>> keys;
        keys.reserve(16);
        for (auto shift : SHIFTS)
        {
            left = rotate28(left, shift);
            right = rotate28(right, shift);
            packed = (static_cast<std::uint64_t>(left) << 28) | right;
            std::vector<std::uint8_t> joined(7);
            for (std::size_t i = 0; i < joined.size(); ++i)
                joined[joined.size() - 1 - i] = static_cast<std::uint8_t>(packed >> (8 * i));
            keys.push_back(permuteBits(joined, PC2));
        }
        return keys;
    }

    std::vector<std::uint8_t> DesRoundFunction::transform(
        const std::vector<std::uint8_t>& block,
        const std::vector<std::uint8_t>& roundKey) const
    {
        if (block.size() != 4 || roundKey.size() != 6)
            throw std::invalid_argument("DES round requires 4 data bytes and 6 key bytes");
        auto expanded = permuteBits(block, E);
        std::uint64_t mixed = 0;
        for (std::size_t i = 0; i < expanded.size(); ++i)
            mixed = (mixed << 8) | (expanded[i] ^ roundKey[i]);
        std::vector<std::uint8_t> substituted(4, 0);
        for (std::size_t i = 0; i < 8; ++i)
        {
            const auto sixBits = static_cast<unsigned>((mixed >> (42 - 6 * i)) & 0x3fu);
            const auto row = ((sixBits & 0x20u) >> 4) | (sixBits & 1u);
            const auto column = (sixBits >> 1) & 0x0fu;
            substituted[i / 2] |= static_cast<std::uint8_t>(S[i][row][column] << (i % 2 == 0 ? 4 : 0));
        }
        return permuteBits(substituted, P);
    }

    DesCipher::DesCipher()
        : network_(8, std::make_unique<DesKeyExpansion>(), std::make_unique<DesRoundFunction>()) {}

    void DesCipher::setKey(const std::vector<std::uint8_t>& key)
    {
        network_.setKey(key);
    }

    std::size_t DesCipher::blockSize() const { return 8; }

    std::vector<std::uint8_t> DesCipher::encryptBlock(const std::vector<std::uint8_t>& block) const
    {
        return processBlock(block, false);
    }

    std::vector<std::uint8_t> DesCipher::decryptBlock(const std::vector<std::uint8_t>& block) const
    {
        return processBlock(block, true);
    }

    std::vector<std::uint8_t> DesCipher::processBlock(
        const std::vector<std::uint8_t>& block, bool decrypt) const
    {
        if (block.size() != blockSize())
            throw std::invalid_argument("DES block must contain 8 bytes");
        const auto initial = permuteBits(block, IP);
        const auto result = decrypt ? network_.decryptBlock(initial) : network_.encryptBlock(initial);
        return permuteBits(result, FP);
    }
}
