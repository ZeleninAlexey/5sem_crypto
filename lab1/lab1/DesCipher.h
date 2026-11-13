#pragma once
#include "FeistelNetwork.h"
namespace crypto
{
    class DesCipher final : public IBlockCipher
    {
    public:
        DesCipher();
        void setKey(const std::vector<std::uint8_t>& key) override;
        std::size_t blockSize() const override;
        std::vector<std::uint8_t> encryptBlock(
            const std::vector<std::uint8_t>& block) const override;
        std::vector<std::uint8_t> decryptBlock(
            const std::vector<std::uint8_t>& block) const override;
    private:
        FeistelNetwork network_;
        std::vector<std::uint8_t> processBlock(
            const std::vector<std::uint8_t>& block, bool decrypt) const;
    };
}
