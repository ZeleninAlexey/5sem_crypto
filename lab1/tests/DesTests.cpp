#include "../lab1/DesCipher.h"
#include "../lab1/DesKeyExpansion.h"
#include "../lab1/DesRoundFunction.h"
#include "../lab1/CryptoContext.h"
#include <iostream>
#include <stdexcept>
#include <string>
using namespace crypto;
Bytes hex(const std::string& text)
{
    Bytes result;
    for (std::size_t i = 0; i < text.size(); i += 2)
        result.push_back(static_cast<std::uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    return result;
}
void require(bool value) { if (!value) throw std::runtime_error("DES check failed"); }
template<class F> void rejects(F f)
{
    bool failed = false;
    try { f(); } catch (const std::exception&) { failed = true; }
    require(failed);
}
int main()
{
    try
    {
        const char* vectors[][3] = {
            {"133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"},
            {"0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"},
            {"FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"},
            {"3000000000000000", "1000000000000001", "958E6E627A05557B"},
            {"0E329232EA6D0D73", "8787878787878787", "0000000000000000"}
        };
        DesCipher des;
        require(des.blockSize() == 8);
        rejects([&] { des.encryptBlock(Bytes(8)); });
        rejects([&] { des.decryptBlock(Bytes(8)); });
        for (const auto& vector : vectors)
        {
            const auto key = hex(vector[0]), plain = hex(vector[1]), cipher = hex(vector[2]);
            des.setKey(key);
            require(des.encryptBlock(plain) == cipher);
            require(des.decryptBlock(cipher) == plain);
            auto parity = key;
            for (auto& byte : parity) byte ^= 1u;
            des.setKey(parity);
            require(des.encryptBlock(plain) == cipher);
        }
        const auto key = hex("133457799BBCDFF1");
        DesKeyExpansion expansion;
        const auto keys = expansion.expandKey(key);
        require(keys.size() == 16);
        for (const auto& roundKey : keys) require(roundKey.size() == 6);
        require(keys.front() == hex("1B02EFFC7072"));
        require(keys.back() == hex("CB3D8B0E17F5"));
        DesRoundFunction round;
        require(round.transform(hex("F0AAF0AA"), keys.front()) == hex("234AA9BB"));
        rejects([&] { round.transform(Bytes(3), Bytes(6)); });
        rejects([&] { round.transform(Bytes(4), Bytes(5)); });
        rejects([&] { expansion.expandKey(Bytes(7)); });
        rejects([&] { expansion.expandKey(Bytes(9)); });
        des.setKey(key);
        rejects([&] { des.setKey(Bytes(7)); });
        require(des.encryptBlock(hex(vectors[0][1])) == hex(vectors[0][2]));
        rejects([&] { des.encryptBlock(Bytes(7)); });
        rejects([&] { des.decryptBlock(Bytes(9)); });
        for (unsigned sample = 0; sample < 256; ++sample)
        {
            Bytes data(8), sampleKey(8);
            for (unsigned i = 0; i < 8; ++i)
            {
                data[i] = static_cast<std::uint8_t>(sample + i * 17);
                sampleKey[i] = static_cast<std::uint8_t>(sample * 3 + i * 29);
            }
            des.setKey(sampleKey);
            require(des.decryptBlock(des.encryptBlock(data)) == data);
        }
        // Без исходной длины Zeros не может отличить данные от набивки.
        CryptoContext missingSize(key, CipherMode::CBC, PaddingMode::Zeros,
            std::make_unique<DesCipher>(), Bytes(8, 17));
        const auto zeroCipher = missingSize.encryptAsync(Bytes(8, 0)).get();
        bool needsSize = false;
        try { missingSize.decryptAsync(zeroCipher).get(); }
        catch (const std::invalid_argument& e)
        {
            needsSize = std::string(e.what()) == "Zeros requires OriginalSize for decryption";
        }
        require(needsSize);
        // Проверяем один нулевой байт, полные блоки и границу порции.
        for (std::size_t size : {0u, 1u, 7u, 8u, 9u, 16u, 8192u, 8193u})
        {
            const Bytes zeros(size, 0);
            CryptoContext zeroContext(key, CipherMode::CBC, PaddingMode::Zeros,
                std::make_unique<DesCipher>(), Bytes(8, 17), OriginalSize{size});
            const auto encrypted = zeroContext.encryptAsync(zeros).get();
            require(zeroContext.decryptAsync(encrypted).get() == zeros);
        }
        std::size_t cases = 0;
        for (auto mode : {CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC,
            CipherMode::CFB, CipherMode::OFB, CipherMode::CTR, CipherMode::RandomDelta})
        for (auto padding : {PaddingMode::Zeros, PaddingMode::AnsiX923,
            PaddingMode::PKCS7, PaddingMode::Iso10126})
        for (std::size_t size : {0u, 1u, 7u, 8u, 9u, 40u, 8201u})
        {
            Bytes data(size);
            for (std::size_t i = 0; i < size; ++i) data[i] = static_cast<std::uint8_t>(i * 19);
            if (size) data.back() = 0;
            const auto iv = mode == CipherMode::ECB ? Bytes{} : Bytes(8, 17);
            auto make = [&]() -> CryptoContext {
                if (mode == CipherMode::RandomDelta)
                    return CryptoContext(key, mode, padding, std::make_unique<DesCipher>(), iv,
                        Delta{{0,0,0,0,0,0,0,3}}, OriginalSize{size}, WorkerCount{4});
                return CryptoContext(key, mode, padding, std::make_unique<DesCipher>(), iv,
                    OriginalSize{size}, WorkerCount{4});
            };
            auto context = make();
            require(context.decryptAsync(context.encryptAsync(data).get()).get() == data);
            ++cases;
        }
        std::cout << "5 known vectors, key schedule, round function, parity, 256 blocks and "
            << cases << " context combinations and CBC/Zeros regression passed\n";
        return 0;
    }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
