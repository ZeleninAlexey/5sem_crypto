#include "CryptoContext.h"
#include "DesCipher.h"
#include "DealCipher.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>

void printBytes(const char* label, const crypto::Bytes& bytes)
{
    std::cout << label << " (" << bytes.size() << " bytes): ";
    for (auto byte : bytes)
        std::cout << std::hex << std::uppercase << std::setfill('0')
                  << std::setw(2) << static_cast<unsigned>(byte) << ' ';
    std::cout << std::dec << '\n';
}

void demonstrateSimpleArray()
{
        // Нули исходных данных сохраняем по их исходной длине.
        //const crypto::Bytes input = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const crypto::Bytes input = { 0x00 };
        const crypto::Bytes key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
        // Для примера берём фиксированный IV.
        const crypto::Bytes iv = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

        crypto::CryptoContext context(key, crypto::CipherMode::CBC,
            crypto::PaddingMode::Zeros, std::make_unique<crypto::DesCipher>(), iv,
            crypto::OriginalSize{input.size()});

        // get() ждёт завершения задачи и возвращает результат.
        const auto encrypted = context.encryptAsync(input).get();
        const auto decrypted = context.decryptAsync(encrypted).get();

        printBytes("Input", input);
        printBytes("Encrypted", encrypted);
        printBytes("Decrypted", decrypted);

        const bool restored = input == decrypted;
        std::cout << "Data restored: " << (restored ? "yes" : "no") << '\n';
        if (!restored) throw std::runtime_error("Simple DES example failed");
}
namespace
{
    struct ModeExample { crypto::CipherMode value; const char* name; };
    struct PaddingExample { crypto::PaddingMode value; const char* name; };
    constexpr ModeExample modes[] = {
        {crypto::CipherMode::ECB, "ECB"}, {crypto::CipherMode::CBC, "CBC"},
        {crypto::CipherMode::PCBC, "PCBC"}, {crypto::CipherMode::CFB, "CFB"},
        {crypto::CipherMode::OFB, "OFB"}, {crypto::CipherMode::CTR, "CTR"},
        {crypto::CipherMode::RandomDelta, "RandomDelta"}
    };
    constexpr PaddingExample paddings[] = {
        {crypto::PaddingMode::Zeros, "Zeros"}, {crypto::PaddingMode::AnsiX923, "AnsiX923"},
        {crypto::PaddingMode::PKCS7, "PKCS7"}, {crypto::PaddingMode::Iso10126, "Iso10126"}
    };

    crypto::Bytes randomBytes(std::size_t size, std::mt19937& random)
    {
        crypto::Bytes result(size);
        std::uniform_int_distribution<unsigned> byte(0, 255);
        for (auto& value : result) value = static_cast<std::uint8_t>(byte(random));
        return result;
    }

    void writeFile(const std::filesystem::path& path, const crypto::Bytes& data)
    {
        std::ofstream file(path, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot create demonstration file");
        file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        file.close();
        if (!file) throw std::runtime_error("Cannot write demonstration file");
    }

    bool equalFiles(const std::filesystem::path& left, const std::filesystem::path& right)
    {
        if (std::filesystem::file_size(left) != std::filesystem::file_size(right)) return false;
        std::ifstream a(left, std::ios::binary), b(right, std::ios::binary);
        if (!a || !b) throw std::runtime_error("Cannot open files for comparison");
        std::array<char, 4096> x{}, y{};
        do
        {
            a.read(x.data(), static_cast<std::streamsize>(x.size()));
            b.read(y.data(), static_cast<std::streamsize>(y.size()));
            if (a.bad() || b.bad()) throw std::runtime_error("Cannot compare files");
            if (a.gcount() != b.gcount() || !std::equal(x.begin(), x.begin() + a.gcount(), y.begin()))
                return false;
        } while (a.gcount() != 0);
        return true;
    }

    void appendText(crypto::Bytes& data, const std::string& text)
    {
        data.insert(data.end(), text.begin(), text.end());
    }
    void appendLittle(crypto::Bytes& data, std::uint32_t value, unsigned bytes)
    {
        for (unsigned i = 0; i < bytes; ++i)
            data.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    }

    std::vector<std::filesystem::path> createExampleFiles(const std::filesystem::path& root)
    {
        std::filesystem::create_directories(root);
        std::vector<std::filesystem::path> files;
        auto save = [&](const char* name, const crypto::Bytes& data) {
            auto path = root / name;
            writeFile(path, data);
            files.push_back(path);
        };
        const std::string text = "Cryptography lab 1: DES and DEAL.\n";
        save("text.txt", crypto::Bytes(text.begin(), text.end()));
        const std::string source = "int square(int x) { return x * x; }\n";
        save("source.cpp", crypto::Bytes(source.begin(), source.end()));
        crypto::Bytes image;
        appendText(image, "P6\n8 8\n255\n");
        for (unsigned i = 0; i < 64; ++i)
        {
            image.push_back(static_cast<std::uint8_t>(i * 4));
            image.push_back(static_cast<std::uint8_t>(255 - i * 4));
            image.push_back(128);
        }
        save("image.ppm", image);
        // Создаём короткий звук в WAV: один канал, 8 бит на отсчёт.
        crypto::Bytes audio;
        constexpr unsigned samples = 512;
        appendText(audio, "RIFF"); appendLittle(audio, 36 + samples, 4);
        appendText(audio, "WAVEfmt "); appendLittle(audio, 16, 4);
        appendLittle(audio, 1, 2); appendLittle(audio, 1, 2);
        appendLittle(audio, 8000, 4); appendLittle(audio, 8000, 4);
        appendLittle(audio, 1, 2); appendLittle(audio, 8, 2);
        appendText(audio, "data"); appendLittle(audio, samples, 4);
        for (unsigned i = 0; i < samples; ++i) audio.push_back(i % 20 < 10 ? 96 : 160);
        save("audio.wav", audio);
        // Создаём видео Y4M из двух кадров 4 на 4 в YUV420.
        crypto::Bytes video;
        appendText(video, "YUV4MPEG2 W4 H4 F1:1 Ip A1:1 C420jpeg\n");
        for (unsigned frame = 0; frame < 2; ++frame)
        {
            appendText(video, "FRAME\n");
            video.insert(video.end(), 16, frame == 0 ? 64 : 192);
            video.insert(video.end(), 8, 128);
        }
        save("video.y4m", video);
        std::mt19937 random(20261030u);
        save("random.bin", randomBytes(1031, random));
        return files;
    }

    template<class Cipher>
    crypto::CryptoContext makeContext(const crypto::Bytes& key, crypto::CipherMode mode,
        crypto::PaddingMode padding, std::uintmax_t size, std::mt19937& random)
    {
        const auto blockSize = Cipher{}.blockSize();
        auto iv = mode == crypto::CipherMode::ECB ? crypto::Bytes{} : randomBytes(blockSize, random);
        if (mode == crypto::CipherMode::RandomDelta)
        {
            auto delta = randomBytes(blockSize, random);
            delta.back() |= 1u;
            return crypto::CryptoContext(key, mode, padding, std::make_unique<Cipher>(), iv,
                crypto::Delta{delta}, crypto::OriginalSize{size}, crypto::WorkerCount{4});
        }
        return crypto::CryptoContext(key, mode, padding, std::make_unique<Cipher>(), iv,
            crypto::OriginalSize{size}, crypto::WorkerCount{4});
    }

    template<class Cipher>
    void demonstrateCipher(const char* name, const crypto::Bytes& key,
        const std::filesystem::path& output, const std::vector<std::filesystem::path>& files)
    {
        std::random_device seed;
        std::mt19937 random(seed());
        std::mt19937 dataRandom(123456u);
        auto data = randomBytes(257, dataRandom);
        std::cout << "\n" << name << ": " << key.size() * 8 << " key bits\n";
        for (const auto& mode : modes)
        for (const auto& padding : paddings)
        {
            auto context = makeContext<Cipher>(key, mode.value, padding.value, data.size(), random);
            const auto encrypted = context.encryptAsync(data).get();
            if (context.decryptAsync(encrypted).get() != data)
                throw std::runtime_error("Demonstration array was not restored");
            const auto folder = output / mode.name / padding.name;
            std::filesystem::create_directories(folder);
            for (std::size_t i = 0; i < files.size(); ++i)
            {
                const auto& input = files[i];
                auto fileContext = makeContext<Cipher>(key, mode.value, padding.value,
                    std::filesystem::file_size(input), random);
                const auto prefix = std::to_string(i) + "_" + input.filename().string();
                const auto cipherFile = folder / (prefix + ".enc");
                const auto restoredFile = folder / prefix;
                fileContext.encryptAsync(input, cipherFile).get();
                fileContext.decryptAsync(cipherFile, restoredFile).get();
                if (!equalFiles(input, restoredFile))
                    throw std::runtime_error("Demonstration file was not restored");
            }
            std::cout << "  " << mode.name << " / " << padding.name
                      << ": array " << data.size() << " -> " << encrypted.size()
                      << " bytes, " << files.size() << " files restored: OK\n";
        }
    }
}

// Пункт 5: шифруем и восстанавливаем массив и файлы с помощью DES.
void demonstrateDes(const std::filesystem::path& output,
    const std::vector<std::filesystem::path>& files)
{
    demonstrateCipher<crypto::DesCipher>("DES", {0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1},
        output / "DES", files);
}

// Пункт 7: проверяем DEAL с тремя размерами ключа.
void demonstrateDeal(const std::filesystem::path& output,
    const std::vector<std::filesystem::path>& files)
{
    for (std::size_t keySize : {16u, 24u, 32u})
    {
        crypto::Bytes key(keySize);
        for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i);
        const auto name = std::string("DEAL-") + std::to_string(keySize * 8);
        demonstrateCipher<crypto::DealCipher>(name.c_str(), key, output / name, files);
    }
}

// Шифруем один файл с помощью DES и проверяем, что он восстановился.
void demonstrateSingleFile(const std::filesystem::path& input,
    const std::filesystem::path& encrypted, const std::filesystem::path& decrypted,
    crypto::CipherMode mode = crypto::CipherMode::CBC,
    crypto::PaddingMode padding = crypto::PaddingMode::PKCS7)
{
    if (!std::filesystem::is_regular_file(input))
        throw std::invalid_argument("Input must be an existing file");

    // Все три пути должны вести к разным файлам.
    const auto sameFile = [](const std::filesystem::path& a, const std::filesystem::path& b)
    {
        return std::filesystem::absolute(a).lexically_normal()
                == std::filesystem::absolute(b).lexically_normal()
            || (std::filesystem::exists(a) && std::filesystem::exists(b)
                && std::filesystem::equivalent(a, b));
    };
    if (sameFile(input, encrypted) || sameFile(input, decrypted) || sameFile(encrypted, decrypted))
        throw std::invalid_argument("Input, encrypted and decrypted files must be different");

    const crypto::Bytes key = {0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1};
    std::random_device seed;
    std::mt19937 random(seed());
    const auto originalSize = std::filesystem::file_size(input);
    // Передаём исходную длину, чтобы Zeros сохранял нули в конце файла.
    auto context = makeContext<crypto::DesCipher>(key, mode, padding, originalSize, random);
    if (!encrypted.parent_path().empty())
        std::filesystem::create_directories(encrypted.parent_path());
    if (!decrypted.parent_path().empty())
        std::filesystem::create_directories(decrypted.parent_path());

    context.encryptAsync(input, encrypted).get();
    context.decryptAsync(encrypted, decrypted).get();
    const bool restored = equalFiles(input, decrypted);

    std::cout << "Input: " << input << " (" << originalSize << " bytes)\n"
              << "Encrypted: " << encrypted << " ("
              << std::filesystem::file_size(encrypted) << " bytes)\n"
              << "Decrypted: " << decrypted << " ("
              << std::filesystem::file_size(decrypted) << " bytes)\n"
              << "File restored: " << (restored ? "yes" : "no") << '\n';
    if (!restored) throw std::runtime_error("Single file was not restored");
}

int main(int argc, char* argv[])
{
    try
    {
        demonstrateSimpleArray();

        // Создаём пустой файл в отдельной папке и проверяем его восстановление.
        const auto stamp = std::chrono::system_clock::now().time_since_epoch().count();
        const auto folder = std::filesystem::path("demo-output")
            / ("empty-file-" + std::to_string(stamp));
        if (!std::filesystem::create_directories(folder))
            throw std::runtime_error("Test folder already exists");
        writeFile(folder / "empty.txt", {});
        demonstrateSingleFile(folder / "empty.txt", folder / "empty.enc", folder / "restored.txt");
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
    /*try
    {
        demonstrateSimpleArray();
        const auto stamp = std::chrono::system_clock::now().time_since_epoch().count();
        std::filesystem::path output;
        for (unsigned attempt = 0; ; ++attempt)
        {
            output = std::filesystem::path("demo-output")
                / (std::to_string(stamp) + "-" + std::to_string(attempt));
            std::filesystem::create_directories(output.parent_path());
            if (std::filesystem::create_directory(output)) break;
        }
        auto files = createExampleFiles(output / "input");
        for (int i = 1; i < argc; ++i)
        {
            const std::filesystem::path input(argv[i]);
            if (!std::filesystem::is_regular_file(input))
                throw std::invalid_argument("Each argument must be an existing file path");
            files.push_back(input);
        }
        demonstrateDes(output, files);
        demonstrateDeal(output, files);
        std::cout << "\nAll demonstrations passed. Files: "
                  << std::filesystem::absolute(output) << '\n';
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }*/
}
