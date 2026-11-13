#pragma once
#include "IBlockCipher.h"
#include <filesystem>
#include <future>
#include <initializer_list>
#include <istream>
#include <ostream>
#include <utility>
#include <memory>
#include <optional>
#include <variant>

namespace crypto
{
    using Bytes = std::vector<std::uint8_t>;
    enum class CipherMode { ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta };
    enum class PaddingMode { Zeros, AnsiX923, PKCS7, Iso10126 };

    struct Delta { Bytes value; };
    struct OriginalSize { std::uintmax_t value; };
    struct WorkerCount { std::size_t value; };
    using ContextArgument = std::variant<Delta, OriginalSize, WorkerCount>;

    class CryptoContext
    {
    public:
        // Передаём алгоритм контексту, чтобы ключ не меняли извне.
        // IV имеет размер блока, для ECB оставляем его пустым.
        // Для RandomDelta нужна нечётная Delta размером в блок, старший байт идёт первым.
        // Для удаления Zeros нужна исходная длина данных.
        template<class... Args>
        CryptoContext(const Bytes& key, CipherMode mode, PaddingMode padding,
            std::unique_ptr<IBlockCipher> cipher, Bytes iv = {}, Args... args)
            : CryptoContext(key, mode, padding, std::move(cipher), std::move(iv),
                std::initializer_list<ContextArgument>{ContextArgument{std::move(args)}...})
        {
        }

        std::future<Bytes> encryptAsync(Bytes input) const;
        std::future<Bytes> decryptAsync(Bytes input) const;

        // Пока задача работает, output нельзя удалять, читать или менять.
        std::future<void> encryptAsync(Bytes input, Bytes& output) const;
        std::future<void> decryptAsync(Bytes input, Bytes& output) const;
        std::future<void> encryptAsync(std::filesystem::path input,
            std::filesystem::path output) const;
        std::future<void> decryptAsync(std::filesystem::path input,
            std::filesystem::path output) const;

    private:
        struct Settings;
        std::shared_ptr<const Settings> settings_;
        CryptoContext(const Bytes& key, CipherMode mode, PaddingMode padding,
            std::unique_ptr<IBlockCipher> cipher, Bytes iv,
            std::initializer_list<ContextArgument> args);
        static Bytes process(const Settings& settings, const Bytes& input, bool encrypt);
        static void processStream(const Settings& settings,
            std::istream& input, std::ostream& output, bool encrypt);
        std::future<void> processFile(std::filesystem::path input,
            std::filesystem::path output, bool encrypt) const;
    };
}
