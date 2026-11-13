#include "../lab1/FeistelNetwork.h"
#include "../lab1/CryptoContext.h"
#include <iostream>
#include <stdexcept>
using namespace crypto;
class Keys final : public IKeyExpansion
{
public:
    std::vector<Bytes> expandKey(const Bytes& key) const override
    {
        std::vector<Bytes> result;
        for (auto byte : key) result.push_back({byte});
        return result;
    }
};
class Round final : public IRoundFunction
{
public:
    Bytes transform(const Bytes& block, const Bytes& key) const override
    {
        auto result = block;
        for (auto& byte : result) byte = static_cast<std::uint8_t>(byte + key.at(0));
        return result;
    }
};
class BadRound final : public IRoundFunction
{
public:
    Bytes transform(const Bytes&, const Bytes&) const override { return {}; }
};
void require(bool value) { if (!value) throw std::runtime_error("Feistel check failed"); }
template<class F> void rejects(F f)
{
    bool failed = false;
    try { f(); } catch (const std::exception&) { failed = true; }
    require(failed);
}
std::unique_ptr<FeistelNetwork> makeNetwork(std::size_t size)
{
    return std::make_unique<FeistelNetwork>(size, std::make_unique<Keys>(), std::make_unique<Round>());
}
int main()
{
    try
    {
        auto network = makeNetwork(2);
        rejects([&] { network->encryptBlock({1,2}); });
        rejects([&] { network->decryptBlock({1,2}); });
        network->setKey({3,5});
        require(network->encryptBlock({1,2}) == Bytes({11,4}));
        require(network->decryptBlock({11,4}) == Bytes({1,2}));
        rejects([&] { network->setKey({}); });
        require(network->encryptBlock({1,2}) == Bytes({11,4}));
        rejects([&] { network->encryptBlock({1}); });
        rejects([&] { network->decryptBlock({1,2,3}); });
        network->setKey({3});
        require(network->encryptBlock({1,2}) == Bytes({4,2}));
        network->setKey({3,5,7});
        require(network->encryptBlock({1,2}) == Bytes({22,11}));
        require(network->decryptBlock({22,11}) == Bytes({1,2}));
        for (auto size : {2u, 8u, 16u})
        for (auto rounds : {1u, 2u, 3u, 16u})
        {
            auto n = makeNetwork(size);
            Bytes key(rounds);
            for (unsigned i = 0; i < rounds; ++i) key[i] = static_cast<std::uint8_t>(i * 37);
            n->setKey(key);
            for (unsigned sample = 0; sample < 256; ++sample)
            {
                Bytes plain(size);
                for (unsigned i = 0; i < size; ++i) plain[i] = static_cast<std::uint8_t>(sample + i * 19);
                require(n->decryptBlock(n->encryptBlock(plain)) == plain);
            }
        }
        rejects([] { auto n = makeNetwork(0); });
        rejects([] { auto n = makeNetwork(3); });
        rejects([] { FeistelNetwork n(8, nullptr, std::make_unique<Round>()); });
        rejects([] { FeistelNetwork n(8, std::make_unique<Keys>(), nullptr); });
        FeistelNetwork broken(8, std::make_unique<Keys>(), std::make_unique<BadRound>());
        broken.setKey({1});
        rejects([&] { broken.encryptBlock(Bytes(8)); });
        rejects([&] { broken.decryptBlock(Bytes(8)); });
        // Проверяем работу контекста с одновременными вызовами одной сети.
        CryptoContext context({3,5,7}, CipherMode::ECB, PaddingMode::PKCS7,
            makeNetwork(8), Bytes{}, WorkerCount{4});
        Bytes data(10001, 42);
        auto first = context.encryptAsync(data);
        auto second = context.encryptAsync(data);
        auto encrypted = first.get();
        require(encrypted == second.get());
        require(context.decryptAsync(encrypted).get() == data);
        std::cout << "3072 round trips, fixed vectors, validation and async integration passed\n";
        return 0;
    }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
