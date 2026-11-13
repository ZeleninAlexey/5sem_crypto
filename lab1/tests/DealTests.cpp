#include "../lab1/DealCipher.h"
#include "../lab1/DealKeyExpansion.h"
#include "../lab1/DesRoundAdapter.h"
#include "../lab1/DesCipher.h"
#include "../lab1/CryptoContext.h"
#include <algorithm>
#include <iostream>
#include <random>
#include <stdexcept>
using namespace crypto;

void require(bool value) { if (!value) throw std::runtime_error("DEAL check failed"); }
template<class F> void rejects(F action)
{
    bool failed = false;
    try { action(); } catch (const std::exception&) { failed = true; }
    require(failed);
}
Bytes exclusiveOr(Bytes a, const Bytes& b)
{
    for (std::size_t i = 0; i < a.size(); ++i) a[i] ^= b[i];
    return a;
}

// Проверяем расписание ключей по отдельно записанным формулам.
std::vector<Bytes> referenceKeys(const Bytes& key)
{
    DesCipher des;
    des.setKey({0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF});
    auto part = [&](std::size_t i) { return Bytes(key.begin() + 8 * i, key.begin() + 8 * (i + 1)); };
    auto e = [&](Bytes data, unsigned constant) {
        data[0] ^= static_cast<std::uint8_t>(constant);
        return des.encryptBlock(data);
    };
    const auto k0 = part(0), k1 = part(1);
    const auto r0 = e(k0, 0);
    const auto r1 = e(exclusiveOr(k1, r0), 0);
    if (key.size() == 16)
    {
        const auto r2 = e(exclusiveOr(k0, r1), 0x80);
        const auto r3 = e(exclusiveOr(k1, r2), 0x40);
        const auto r4 = e(exclusiveOr(k0, r3), 0x20);
        const auto r5 = e(exclusiveOr(k1, r4), 0x10);
        return {r0,r1,r2,r3,r4,r5};
    }
    const auto k2 = part(2);
    const auto r2 = e(exclusiveOr(k2, r1), 0);
    if (key.size() == 24)
    {
        const auto r3 = e(exclusiveOr(k0, r2), 0x80);
        const auto r4 = e(exclusiveOr(k1, r3), 0x40);
        const auto r5 = e(exclusiveOr(k2, r4), 0x20);
        return {r0,r1,r2,r3,r4,r5};
    }
    const auto k3 = part(3);
    const auto r3 = e(exclusiveOr(k3, r2), 0);
    const auto r4 = e(exclusiveOr(k0, r3), 0x80);
    const auto r5 = e(exclusiveOr(k1, r4), 0x40);
    const auto r6 = e(exclusiveOr(k2, r5), 0x20);
    const auto r7 = e(exclusiveOr(k3, r6), 0x10);
    return {r0,r1,r2,r3,r4,r5,r6,r7};
}

// По очереди меняем левую и правую половины, без сети Фейстеля и адаптера.
Bytes referenceEncrypt(const Bytes& input, const std::vector<Bytes>& keys)
{
    Bytes left(input.begin(), input.begin() + 8), right(input.begin() + 8, input.end());
    for (std::size_t round = 0; round < keys.size(); ++round)
    {
        DesCipher des;
        des.setKey(keys[round]);
        if (round % 2 == 0) right = exclusiveOr(right, des.encryptBlock(left));
        else left = exclusiveOr(left, des.encryptBlock(right));
    }
    left.insert(left.end(), right.begin(), right.end());
    return left;
}

int main()
{
    try
    {
        DesRoundAdapter adapter;
        const Bytes desKey = {0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1};
        require(adapter.transform({0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF}, desKey)
            == Bytes({0x85,0xE8,0x13,0x54,0x0F,0x0A,0xB4,0x05}));
        rejects([&] { adapter.transform(Bytes(7), Bytes(8)); });
        rejects([&] { adapter.transform(Bytes(8), Bytes(7)); });
        DealKeyExpansion expansion;
        for (auto size : {0u,8u,15u,17u,23u,25u,31u,33u})
            rejects([&] { expansion.expandKey(Bytes(size)); });
        DealCipher unconfigured;
        require(unconfigured.blockSize() == 16);
        rejects([&] { unconfigured.encryptBlock(Bytes(16)); });
        rejects([&] { unconfigured.decryptBlock(Bytes(16)); });
        std::mt19937 random(12345);
        std::size_t references = 0, combinations = 0;
        for (auto size : {16u,24u,32u})
        {
            for (unsigned sample = 0; sample < 16; ++sample)
            {
                Bytes key(size), plain(16);
                for (auto& byte : key) byte = static_cast<std::uint8_t>(random());
                for (auto& byte : plain) byte = static_cast<std::uint8_t>(random());
                if (sample == 0) { key.assign(size, 0); plain.assign(16, 0); }
                const auto keys = expansion.expandKey(key);
                require(keys.size() == (size == 32 ? 8u : 6u));
                require(keys == referenceKeys(key));
                DealCipher deal;
                deal.setKey(key);
                const auto expected = referenceEncrypt(plain, referenceKeys(key));
                require(deal.encryptBlock(plain) == expected);
                require(deal.decryptBlock(expected) == plain);
                rejects([&] { deal.setKey(Bytes(8)); });
                require(deal.encryptBlock(plain) == expected);
                rejects([&] { deal.encryptBlock(Bytes(15)); });
                rejects([&] { deal.decryptBlock(Bytes(17)); });
                ++references;
            }
            Bytes key(size);
            for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i);
            for (auto mode : {CipherMode::ECB,CipherMode::CBC,CipherMode::PCBC,CipherMode::CFB,
                CipherMode::OFB,CipherMode::CTR,CipherMode::RandomDelta})
            for (auto padding : {PaddingMode::Zeros,PaddingMode::AnsiX923,PaddingMode::PKCS7,PaddingMode::Iso10126})
            for (auto length : {0u,1u,15u,16u,17u})
            {
                Bytes data(length);
                for (auto& byte : data) byte = static_cast<std::uint8_t>(random());
                if (length) data.back() = 0;
                const auto iv = mode == CipherMode::ECB ? Bytes{} : Bytes(16, 7);
                auto make = [&]() -> CryptoContext {
                    if (mode == CipherMode::RandomDelta)
                        return CryptoContext(key, mode, padding, std::make_unique<DealCipher>(), iv,
                            OriginalSize{length}, Delta{Bytes(16,3)}, WorkerCount{4});
                    return CryptoContext(key, mode, padding, std::make_unique<DealCipher>(), iv,
                        OriginalSize{length}, WorkerCount{4});
                };
                auto context = make();
                require(context.decryptAsync(context.encryptAsync(data).get()).get() == data);
                ++combinations;
            }
            // Проверяем несколько порций и одновременные вызовы одного шифра.
            CryptoContext context(key, CipherMode::CTR, PaddingMode::PKCS7,
                std::make_unique<DealCipher>(), Bytes(16, 7), WorkerCount{4});
            const Bytes large(16401, 0xAB);
            auto first = context.encryptAsync(large), second = context.encryptAsync(large);
            const auto cipher = first.get();
            require(cipher == second.get());
            require(context.decryptAsync(cipher).get() == large);
        }
        std::cout << references << " equation reference cases, " << combinations
            << " context combinations, adapter, errors and concurrency passed\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
