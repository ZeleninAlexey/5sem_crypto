#pragma once
#include "FeistelNetwork.h"
namespace crypto
{
    class DealCipher final : public IBlockCipher
    {
    public:
        DealCipher();
        // Ключ 16, 24 или 32 байта — соответственно 6, 6 или 8 раундов.
        void setKey(const std::vector<std::uint8_t>& key) override;
        std::size_t blockSize() const override;
        std::vector<std::uint8_t> encryptBlock(
            const std::vector<std::uint8_t>& block) const override;
        std::vector<std::uint8_t> decryptBlock(
            const std::vector<std::uint8_t>& block) const override;
    private:
        FeistelNetwork network_;
        static std::vector<std::uint8_t> swapHalves(const std::vector<std::uint8_t>& block);
    };
}
