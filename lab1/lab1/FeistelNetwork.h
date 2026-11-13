#pragma once
#include "IBlockCipher.h"
#include "IKeyExpansion.h"
#include "IRoundFunction.h"
#include <memory>

namespace crypto
{
    class FeistelNetwork : public IBlockCipher
    {
    public:
        FeistelNetwork(std::size_t blockSize,
            std::unique_ptr<IKeyExpansion> keyExpansion,
            std::unique_ptr<IRoundFunction> roundFunction);

        // Нельзя менять ключ во время шифрования или дешифрования.
        void setKey(const std::vector<std::uint8_t>& key) override;
        std::size_t blockSize() const override;
        std::vector<std::uint8_t> encryptBlock(
            const std::vector<std::uint8_t>& block) const override;
        std::vector<std::uint8_t> decryptBlock(
            const std::vector<std::uint8_t>& block) const override;

    private:
        std::size_t blockSize_;
        std::unique_ptr<IKeyExpansion> keyExpansion_;
        std::unique_ptr<IRoundFunction> roundFunction_;
        std::vector<std::vector<std::uint8_t>> roundKeys_;

        std::vector<std::uint8_t> processBlock(
            const std::vector<std::uint8_t>& block, bool decrypt) const;
    };
}
