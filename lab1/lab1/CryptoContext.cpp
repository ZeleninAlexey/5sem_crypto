#include "CryptoContext.h"
#include <algorithm>
#include <fstream>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace crypto
{
    namespace
    {
        Bytes xorBytes(Bytes left, const Bytes& right)
        {
            if (left.size() != right.size())
                throw std::invalid_argument("XOR operands must have equal sizes");
            for (std::size_t i = 0; i < left.size(); ++i) left[i] ^= right[i];
            return left;
        }

        // Складываем с конца массива с переносом, лишний перенос отбрасываем.
        void add(Bytes& value, const Bytes& delta)
        {
            unsigned carry = 0;
            for (std::size_t i = value.size(); i-- > 0;)
            {
                const unsigned sum = value[i] + delta[i] + carry;
                value[i] = static_cast<std::uint8_t>(sum);
                carry = sum >> 8;
            }
        }
    }

    struct CryptoContext::Settings
    {
        std::unique_ptr<IBlockCipher> cipher;
        CipherMode mode;
        PaddingMode padding;
        Bytes iv, delta;
        std::optional<std::uintmax_t> originalSize;
        std::size_t blockSize = 0;
        std::size_t workers = 1;

        Bytes block(const Bytes& input, bool encrypt) const
        {
            auto result = encrypt ? cipher->encryptBlock(input) : cipher->decryptBlock(input);
            if (result.size() != blockSize)
                throw std::runtime_error("Cipher returned an invalid block size");
            return result;
        }

        void pad(Bytes& data) const
        {
            const auto count = blockSize - data.size() % blockSize;
            // Если блок уже полный, Zeros ничего не добавляет.
            if (padding == PaddingMode::Zeros && count == blockSize) return;
            const auto oldSize = data.size();
            data.resize(oldSize + count, 0);
            if (padding == PaddingMode::PKCS7)
                std::fill(data.begin() + oldSize, data.end(), static_cast<std::uint8_t>(count));
            else if (padding == PaddingMode::Iso10126)
            {
                std::random_device random;
                std::uniform_int_distribution<unsigned> byte(0, 255);
                for (std::size_t i = oldSize; i + 1 < data.size(); ++i)
                    data[i] = static_cast<std::uint8_t>(byte(random));
            }
            if (padding != PaddingMode::Zeros) data.back() = static_cast<std::uint8_t>(count);
        }

        void unpad(Bytes& data, std::uintmax_t previous) const
        {
            std::size_t count = 0;
            if (padding == PaddingMode::Zeros)
            {
                if (!originalSize) throw std::invalid_argument("Zeros requires OriginalSize for decryption");
                if (*originalSize < previous || *originalSize - previous > data.size())
                    throw std::invalid_argument("OriginalSize does not match decrypted data");
                count = data.size() - static_cast<std::size_t>(*originalSize - previous);
                if (count >= blockSize)
                    throw std::invalid_argument("Invalid zero padding length");
            }
            else
            {
                if (data.empty()) throw std::invalid_argument("Missing padding block");
                count = data.back();
                if (count == 0 || count > blockSize || count > data.size())
                    throw std::invalid_argument("Invalid padding length");
            }
            for (std::size_t i = data.size() - count; i < data.size(); ++i)
            {
                if ((padding == PaddingMode::Zeros || padding == PaddingMode::AnsiX923)
                    && (padding == PaddingMode::Zeros || i + 1 < data.size()) && data[i] != 0)
                    throw std::invalid_argument("Invalid zero padding byte");
                if (padding == PaddingMode::PKCS7 && data[i] != count)
                    throw std::invalid_argument("Invalid PKCS7 padding byte");
            }
            data.resize(data.size() - count);
        }

        struct Session
        {
            const Settings& s;
            Bytes feedback, counter;
            explicit Session(const Settings& settings)
                : s(settings), feedback(s.iv), counter(s.iv) {}

            Bytes transform(const Bytes& input, bool encrypt)
            {
                const auto count = input.size() / s.blockSize;
                Bytes output(input.size());
                auto getBlock = [&](std::size_t index) {
                    const auto begin = input.begin() + index * s.blockSize;
                    return Bytes(begin, begin + s.blockSize);
                };
                const bool independent = s.mode == CipherMode::ECB || s.mode == CipherMode::CTR
                    || s.mode == CipherMode::RandomDelta
                    || (!encrypt && (s.mode == CipherMode::CBC || s.mode == CipherMode::CFB));
                std::vector<Bytes> counters;
                if (s.mode == CipherMode::CTR || s.mode == CipherMode::RandomDelta)
                {
                    counters.reserve(count);
                    for (std::size_t i = 0; i < count; ++i)
                    {
                        counters.push_back(counter);
                        add(counter, s.delta);
                    }
                }
                auto transformOne = [&](std::size_t i) {
                    auto current = getBlock(i);
                    switch (s.mode)
                    {
                    case CipherMode::ECB:
                        return s.block(current, encrypt);
                    case CipherMode::CBC:
                        return xorBytes(s.block(current, false), i == 0 ? feedback : getBlock(i - 1));
                    case CipherMode::CFB:
                        return xorBytes(current, s.block(i == 0 ? feedback : getBlock(i - 1), true));
                    case CipherMode::CTR:
                        return xorBytes(current, s.block(counters[i], true));
                    case CipherMode::RandomDelta:
                        // В RandomDelta шифруем блок после XOR с маской IV + i * Delta.
                        return encrypt ? s.block(xorBytes(current, counters[i]), true)
                            : xorBytes(s.block(current, false), counters[i]);
                    default:
                        throw std::logic_error("Mode does not support independent blocks");
                    }
                };
                if (independent)
                {
                    auto range = [&](std::size_t first, std::size_t last) {
                        for (std::size_t i = first; i < last; ++i)
                        {
                            auto result = transformOne(i);
                            std::copy(result.begin(), result.end(), output.begin() + i * s.blockSize);
                        }
                    };
                    const auto workerCount = std::min(s.workers, count);
                    if (workerCount <= 1) range(0, count);
                    else
                    {
                        std::vector<std::future<void>> tasks;
                        // Сначала ждём завершения задач, потом удаляем данные, с которыми они работают.
                        for (std::size_t w = 0; w < workerCount; ++w)
                            tasks.push_back(std::async(std::launch::async, range,
                                count * w / workerCount, count * (w + 1) / workerCount));
                        for (auto& task : tasks) task.get();
                    }
                    if (count && (s.mode == CipherMode::CBC || s.mode == CipherMode::CFB))
                        feedback = getBlock(count - 1);
                }
                else
                {
                    for (std::size_t i = 0; i < count; ++i)
                    {
                        auto current = getBlock(i);
                        Bytes result;
                        switch (s.mode)
                        {
                        case CipherMode::CBC:
                            result = s.block(xorBytes(current, feedback), true);
                            feedback = result;
                            break;
                        case CipherMode::PCBC:
                            result = encrypt ? s.block(xorBytes(current, feedback), true)
                                : xorBytes(s.block(current, false), feedback);
                            feedback = xorBytes(current, result);
                            break;
                        case CipherMode::CFB:
                            result = xorBytes(current, s.block(feedback, true));
                            feedback = result;
                            break;
                        case CipherMode::OFB:
                            feedback = s.block(feedback, true);
                            result = xorBytes(current, feedback);
                            break;
                        default:
                            throw std::logic_error("Unexpected sequential mode");
                        }
                        std::copy(result.begin(), result.end(), output.begin() + i * s.blockSize);
                    }
                }
                return output;
            }
        };
    };

    CryptoContext::CryptoContext(const Bytes& key, CipherMode mode, PaddingMode padding,
        std::unique_ptr<IBlockCipher> cipher, Bytes iv,
        std::initializer_list<ContextArgument> args)
    {
        auto s = std::make_shared<Settings>();
        if (!cipher) throw std::invalid_argument("Cipher must not be null");
        switch (mode)
        {
        case CipherMode::ECB: case CipherMode::CBC: case CipherMode::PCBC:
        case CipherMode::CFB: case CipherMode::OFB: case CipherMode::CTR:
        case CipherMode::RandomDelta: break;
        default: throw std::invalid_argument("Unknown cipher mode");
        }
        switch (padding)
        {
        case PaddingMode::Zeros: case PaddingMode::AnsiX923:
        case PaddingMode::PKCS7: case PaddingMode::Iso10126: break;
        default: throw std::invalid_argument("Unknown padding mode");
        }
        cipher->setKey(key);
        s->blockSize = cipher->blockSize();
        if (s->blockSize == 0 || s->blockSize > 255)
            throw std::invalid_argument("Block size must be between 1 and 255 bytes");
        if ((mode == CipherMode::ECB && !iv.empty())
            || (mode != CipherMode::ECB && iv.size() != s->blockSize))
            throw std::invalid_argument("Invalid IV size for the selected mode");
        s->cipher = std::move(cipher);
        s->mode = mode;
        s->padding = padding;
        s->iv = std::move(iv);
        s->workers = std::max(1u, std::min(8u, std::thread::hardware_concurrency()));
        bool seen[3] = {};
        for (const auto& arg : args)
        {
            if (seen[arg.index()]) throw std::invalid_argument("Duplicate context argument");
            seen[arg.index()] = true;
            if (auto delta = std::get_if<Delta>(&arg)) s->delta = delta->value;
            else if (auto size = std::get_if<OriginalSize>(&arg)) s->originalSize = size->value;
            else s->workers = std::get<WorkerCount>(arg).value;
        }
        if (s->workers == 0 || s->workers > 64)
            throw std::invalid_argument("Worker count must be between 1 and 64");
        if (mode == CipherMode::RandomDelta)
        {
            if (s->delta.size() != s->blockSize || !(s->delta.back() & 1u))
                throw std::invalid_argument("RandomDelta requires a block-sized odd Delta");
        }
        else
        {
            if (seen[0]) throw std::invalid_argument("Delta is only used by RandomDelta");
            s->delta.assign(s->blockSize, 0);
            s->delta.back() = 1;
        }
        settings_ = std::move(s);
    }

    void CryptoContext::processStream(const Settings& s,
        std::istream& input, std::ostream& output, bool encrypt)
    {
        if (!encrypt && s.padding == PaddingMode::Zeros && !s.originalSize)
            throw std::invalid_argument("Zeros requires OriginalSize for decryption");
        Settings::Session session(s);
        const auto chunkSize = s.blockSize * 1024;
        std::uintmax_t written = 0;
        while (true)
        {
            Bytes chunk(chunkSize);
            input.read(reinterpret_cast<char*>(chunk.data()), static_cast<std::streamsize>(chunkSize));
            const auto read = input.gcount();
            if (input.bad() || (input.fail() && !input.eof()))
                throw std::runtime_error("Cannot read input data");
            chunk.resize(static_cast<std::size_t>(read));
            const bool last = input.eof() || input.peek() == std::char_traits<char>::eof();
            if (encrypt && last) s.pad(chunk);
            if (!encrypt && chunk.size() % s.blockSize != 0)
                throw std::invalid_argument("Ciphertext is not block-aligned");
            auto result = session.transform(chunk, encrypt);
            if (!encrypt && last) s.unpad(result, written);
            if (!result.empty())
                output.write(reinterpret_cast<const char*>(result.data()),
                    static_cast<std::streamsize>(result.size()));
            if (!output) throw std::runtime_error("Cannot write output data");
            written += result.size();
            if (last) break;
        }
    }

    Bytes CryptoContext::process(const Settings& s, const Bytes& input, bool encrypt)
    {
        std::string text(input.begin(), input.end());
        std::istringstream source(text, std::ios::binary);
        std::ostringstream target(std::ios::binary);
        processStream(s, source, target, encrypt);
        const auto result = target.str();
        return Bytes(result.begin(), result.end());
    }

    std::future<Bytes> CryptoContext::encryptAsync(Bytes input) const
    {
        return std::async(std::launch::async, [s = settings_, input = std::move(input)] {
            return process(*s, input, true);
        });
    }

    std::future<Bytes> CryptoContext::decryptAsync(Bytes input) const
    {
        return std::async(std::launch::async, [s = settings_, input = std::move(input)] {
            return process(*s, input, false);
        });
    }

    std::future<void> CryptoContext::encryptAsync(Bytes input, Bytes& output) const
    {
        return std::async(std::launch::async, [s = settings_, input = std::move(input), &output] {
            output = process(*s, input, true);
        });
    }

    std::future<void> CryptoContext::decryptAsync(Bytes input, Bytes& output) const
    {
        return std::async(std::launch::async, [s = settings_, input = std::move(input), &output] {
            output = process(*s, input, false);
        });
    }

    std::future<void> CryptoContext::processFile(std::filesystem::path input,
        std::filesystem::path output, bool encrypt) const
    {
        return std::async(std::launch::async,
            [s = settings_, input = std::move(input), output = std::move(output), encrypt] {
                if (std::filesystem::absolute(input).lexically_normal()
                        == std::filesystem::absolute(output).lexically_normal()
                    || (std::filesystem::exists(output) && std::filesystem::equivalent(input, output)))
                    throw std::invalid_argument("Input and output must be different files");
                if (!encrypt && s->padding == PaddingMode::Zeros && !s->originalSize)
                    throw std::invalid_argument("Zeros requires OriginalSize for decryption");
                std::ifstream source(input, std::ios::binary);
                if (!source) throw std::runtime_error("Cannot open input file");
                std::ofstream target(output, std::ios::binary | std::ios::trunc);
                if (!target) throw std::runtime_error("Cannot open output file");
                processStream(*s, source, target, encrypt);
                target.flush();
                if (!target) throw std::runtime_error("Cannot flush output file");
            });
    }

    std::future<void> CryptoContext::encryptAsync(std::filesystem::path input,
        std::filesystem::path output) const
    {
        return processFile(std::move(input), std::move(output), true);
    }

    std::future<void> CryptoContext::decryptAsync(std::filesystem::path input,
        std::filesystem::path output) const
    {
        return processFile(std::move(input), std::move(output), false);
    }
}
