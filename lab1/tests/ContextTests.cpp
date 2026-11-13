#include "../lab1/CryptoContext.h"
#include "../lab1/IRoundFunction.h"
#include "../lab1/IKeyExpansion.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <type_traits>

using namespace crypto;
static_assert(std::is_abstract_v<IKeyExpansion>);
static_assert(std::is_abstract_v<IRoundFunction>);
static_assert(std::is_abstract_v<IBlockCipher>);

// Простое преобразование для тестов, повторное применение не возвращает исходные данные.
class TestCipher final : public IBlockCipher
{
    std::uint8_t key_ = 0;
public:
    void setKey(const Bytes& key) override
    {
        if (key.size() != 1) throw std::invalid_argument("Test key must be one byte");
        key_ = key[0];
    }
    std::size_t blockSize() const override { return 2; }
    Bytes encryptBlock(const Bytes& b) const override
    { return { static_cast<std::uint8_t>(b.at(1) + 3), static_cast<std::uint8_t>(b.at(0) + key_) }; }
    Bytes decryptBlock(const Bytes& b) const override
    { return { static_cast<std::uint8_t>(b.at(1) - key_), static_cast<std::uint8_t>(b.at(0) - 3) }; }
};

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}
template<class F> void rejects(F action)
{
    bool failed = false;
    try { action(); } catch (const std::exception&) { failed = true; }
    require(failed, "Expected an exception");
}

CryptoContext context(CipherMode mode, PaddingMode padding, std::size_t length,
    std::size_t workers = 4)
{
    auto iv = mode == CipherMode::ECB ? Bytes{} : Bytes{5, 6};
    if (mode == CipherMode::RandomDelta)
        return CryptoContext({1}, mode, padding, std::make_unique<TestCipher>(), iv,
            OriginalSize{length}, WorkerCount{workers}, Delta{{0, 3}});
    return CryptoContext({1}, mode, padding, std::make_unique<TestCipher>(), iv,
        OriginalSize{length}, WorkerCount{workers});
}

void write(const std::filesystem::path& path, const Bytes& data)
{
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    require(static_cast<bool>(f), "Test file write failed");
}
Bytes read(const std::filesystem::path& path)
{
    std::ifstream f(path, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(f), {});
}

int main(int argc, char** argv)
{
    try
    {
        const CipherMode modes[] = {CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC,
            CipherMode::CFB, CipherMode::OFB, CipherMode::CTR, CipherMode::RandomDelta};
        // Результаты посчитаны вручную, включая набивку PKCS7 {2, 2}.
        const Bytes expected[] = {{5,2,7,4,5,3}, {7,5,4,5,10,7}, {7,5,6,6,3,8},
            {8,4,4,13,18,7}, {8,4,10,14,15,8}, {8,4,9,2,9,4}, {7,5,16,7,17,8}};
        for (std::size_t i = 0; i < 7; ++i)
        {
            auto c = context(modes[i], PaddingMode::PKCS7, 4);
            require(c.encryptAsync(Bytes{1,2,3,4}).get() == expected[i], "Mode vector mismatch");
            require(c.decryptAsync(expected[i]).get() == Bytes({1,2,3,4}), "Mode decryption mismatch");
        }
        const auto folder = std::filesystem::path(argc > 1 ? argv[1] : ".") / "context-test-files";
        std::filesystem::create_directories(folder);
        const auto source = folder / "source.bin", encrypted = folder / "encrypted.bin",
            restored = folder / "restored.bin";
        std::size_t cases = 0;
        for (auto mode : modes)
        for (auto padding : {PaddingMode::Zeros, PaddingMode::AnsiX923,
            PaddingMode::PKCS7, PaddingMode::Iso10126})
        for (std::size_t length : {0u, 1u, 2u, 3u, 17u, 2047u, 2048u, 2049u, 8197u})
        {
            Bytes plain(length);
            for (std::size_t i = 0; i < length; ++i) plain[i] = static_cast<std::uint8_t>(i * 29 + 7);
            if (length) plain.back() = 0; // Проверяем, что нули исходных данных в конце сохраняются.
            auto c = context(mode, padding, length);
            auto cipher = c.encryptAsync(plain).get();
            require(c.decryptAsync(cipher).get() == plain, "Round trip failed");
            Bytes output;
            c.encryptAsync(plain, output).get();
            c.decryptAsync(output, output).get();
            require(output == plain, "Output reference overload failed");
            if (padding != PaddingMode::Iso10126)
                require(context(mode, padding, length, 1).encryptAsync(plain).get() == cipher,
                    "Parallel output differs from sequential output");
            write(source, plain);
            c.encryptAsync(source, encrypted).get();
            c.decryptAsync(encrypted, restored).get();
            require(read(restored) == plain, "File round trip failed");
            require(c.decryptAsync(read(encrypted)).get() == plain, "File/array formats differ");
            if (padding != PaddingMode::Iso10126)
                require(read(encrypted) == cipher, "File encryption differs from array encryption");
            ++cases;
        }
        auto ecb = context(CipherMode::ECB, PaddingMode::PKCS7, 0);
        rejects([&] { ecb.decryptAsync(Bytes{}).get(); });
        rejects([&] { ecb.decryptAsync(Bytes{1}).get(); });
        // Проверяем PKCS7 с нулевой длиной набивки и с разными байтами набивки.
        rejects([&] { ecb.decryptAsync(Bytes{3,4}).get(); });
        rejects([&] { ecb.decryptAsync(Bytes{5,2}).get(); });
        auto ansi = context(CipherMode::ECB, PaddingMode::AnsiX923, 0);
        rejects([&] { ansi.decryptAsync(Bytes{5,2}).get(); });
        auto zeros = context(CipherMode::ECB, PaddingMode::Zeros, 0);
        rejects([&] { zeros.decryptAsync(Bytes{3,2}).get(); });
        rejects([] { CryptoContext c({1}, CipherMode::CBC, PaddingMode::PKCS7,
            std::make_unique<TestCipher>()); });
        rejects([] { CryptoContext c({1}, CipherMode::ECB, PaddingMode::PKCS7,
            std::make_unique<TestCipher>(), Bytes{0,0}); });
        rejects([] { CryptoContext c({1}, CipherMode::RandomDelta, PaddingMode::PKCS7,
            std::make_unique<TestCipher>(), Bytes{0,0}, Delta{{0,2}}); });
        rejects([] { CryptoContext c({1}, CipherMode::ECB, PaddingMode::PKCS7,
            std::make_unique<TestCipher>(), Bytes{}, WorkerCount{0}); });
        CryptoContext noLength({1}, CipherMode::ECB, PaddingMode::Zeros,
            std::make_unique<TestCipher>());
        rejects([&] { noLength.decryptAsync(Bytes{}).get(); });
        auto before = read(source);
        rejects([&] { ecb.encryptAsync(source, source).get(); });
        require(read(source) == before, "Same-file guard damaged input");
        // Задача хранит настройки и может работать после удаления контекста.
        auto future = context(CipherMode::ECB, PaddingMode::PKCS7, 4)
            .encryptAsync(Bytes{1,2,3,4});
        require(future.get() == expected[0], "Asynchronous lifetime failed");
        std::cout << cases << " mode/padding/size cases, fixed vectors and error checks passed\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
