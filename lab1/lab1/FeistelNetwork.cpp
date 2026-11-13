#include "FeistelNetwork.h"
#include <stdexcept>
#include <utility>

namespace crypto
{
    FeistelNetwork::FeistelNetwork(std::size_t blockSize,
        std::unique_ptr<IKeyExpansion> keyExpansion,
        std::unique_ptr<IRoundFunction> roundFunction)
        : blockSize_(blockSize), keyExpansion_(std::move(keyExpansion)),
          roundFunction_(std::move(roundFunction))
    {
        if (blockSize_ == 0 || blockSize_ % 2 != 0)
            throw std::invalid_argument("Feistel block size must be positive and even");
        if (!keyExpansion_ || !roundFunction_)
            throw std::invalid_argument("Feistel components must not be null");
    }

    void FeistelNetwork::setKey(const std::vector<std::uint8_t>& key)
    {
        auto keys = keyExpansion_->expandKey(key);
        if (keys.empty())
            throw std::invalid_argument("Key expansion must return at least one round key");
        // При ошибке оставляем старые раундовые ключи.
        roundKeys_.swap(keys);
    }

    std::size_t FeistelNetwork::blockSize() const
    {
        return blockSize_;
    }

    std::vector<std::uint8_t> FeistelNetwork::encryptBlock(
        const std::vector<std::uint8_t>& block) const
    {
        return processBlock(block, false);
    }

    std::vector<std::uint8_t> FeistelNetwork::decryptBlock(
        const std::vector<std::uint8_t>& block) const
    {
        return processBlock(block, true);
    }

    std::vector<std::uint8_t> FeistelNetwork::processBlock(
        const std::vector<std::uint8_t>& block, bool decrypt) const
    {
        if (roundKeys_.empty())
            throw std::logic_error("Set the key before processing a block");
        if (block.size() != blockSize_)
            throw std::invalid_argument("Invalid Feistel input block size");

        const auto half = blockSize_ / 2;
        std::vector<std::uint8_t> left(block.begin(), block.begin() + half);
        std::vector<std::uint8_t> right(block.begin() + half, block.end());
        for (std::size_t round = 0; round < roundKeys_.size(); ++round)
        {
            const auto index = decrypt ? roundKeys_.size() - 1 - round : round;
            auto transformed = roundFunction_->transform(right, roundKeys_[index]);
            if (transformed.size() != half)
                throw std::runtime_error("Round function must return one half-block");
            for (std::size_t i = 0; i < half; ++i)
                left[i] ^= transformed[i];
            left.swap(right);
        }
        // Возвращаем R_n || L_n, для дешифрования идём по ключам в обратном порядке.
        right.insert(right.end(), left.begin(), left.end());
        return right;
    }
}
