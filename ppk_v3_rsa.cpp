#include "ppk_v3_rsa.h"
#include "ed25519_crypto.h"
#include "third_party/argon2/include/argon2.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace
{
const size_t kMaximumPpkSize = 64 * 1024;
const size_t kMaximumLines = 1024;
const size_t kMaximumBase64Line = 4096;
const size_t kMaximumPassphraseSize = 4096;
const size_t kMaximumArgon2MemoryKiB = 256 * 1024;
const size_t kMaximumArgon2Passes = 1024;
const size_t kMaximumArgon2Parallelism = 16;
const size_t kMaximumArgon2SaltSize = 64;
const size_t kMaximumArgon2WorkKiB = 8 * 1024 * 1024;

struct ByteView
{
    const unsigned char *data = nullptr;
    size_t size = 0;
};

struct LineView
{
    const unsigned char *data = nullptr;
    size_t size = 0;
};

class AlgorithmHandle
{
  public:
    ~AlgorithmHandle()
    {
        if (handle)
            BCryptCloseAlgorithmProvider(handle, 0);
    }
    BCRYPT_ALG_HANDLE handle = nullptr;
};

class KeyHandle
{
  public:
    ~KeyHandle()
    {
        if (handle)
            BCryptDestroyKey(handle);
    }
    BCRYPT_KEY_HANDLE handle = nullptr;
};

class HashHandle
{
  public:
    ~HashHandle()
    {
        if (handle)
            BCryptDestroyHash(handle);
    }
    BCRYPT_HASH_HANDLE handle = nullptr;
};

bool NtOk(NTSTATUS status)
{
    return status >= 0;
}

void SecureWipe(std::vector<unsigned char> &bytes)
{
    if (!bytes.empty())
        SecureZeroMemory(bytes.data(), bytes.size());
}

bool ConstantTimeEqual(const unsigned char *left, const unsigned char *right, size_t size)
{
    unsigned char difference = 0;
    for (size_t i = 0; i < size; ++i)
        difference |= static_cast<unsigned char>(left[i] ^ right[i]);
    return difference == 0;
}

bool CheckedAdd(size_t left, size_t right, size_t &result)
{
    if (right > (std::numeric_limits<size_t>::max)() - left)
        return false;
    result = left + right;
    return true;
}

bool StartsWith(const LineView &line, const char *prefix)
{
    size_t length = strlen(prefix);
    return line.size >= length && memcmp(line.data, prefix, length) == 0;
}

bool HeaderValue(const LineView &line, const char *header, ByteView &value)
{
    size_t length = strlen(header);
    if (line.size < length || memcmp(line.data, header, length) != 0)
        return false;
    value.data = line.data + length;
    value.size = line.size - length;
    return true;
}

bool Equals(const ByteView &value, const char *literal)
{
    size_t length = strlen(literal);
    return value.size == length && memcmp(value.data, literal, length) == 0;
}

bool ParseDecimal(const ByteView &value, size_t maximum, size_t &result)
{
    if (value.size == 0 || value.size > 10)
        return false;
    size_t number = 0;
    for (size_t i = 0; i < value.size; ++i)
    {
        unsigned char c = value.data[i];
        if (c < '0' || c > '9')
            return false;
        size_t digit = static_cast<size_t>(c - '0');
        if (number > (maximum - digit) / 10)
            return false;
        number = number * 10 + digit;
    }
    if (number == 0 || number > maximum)
        return false;
    result = number;
    return true;
}

bool CopySafeToken(const ByteView &value, size_t maximum, std::string &result)
{
    result.clear();
    if (value.size == 0 || value.size > maximum)
        return false;
    for (size_t i = 0; i < value.size; ++i)
    {
        if (value.data[i] < 0x21 || value.data[i] > 0x7E)
            return false;
    }
    result.assign(reinterpret_cast<const char *>(value.data), value.size);
    return true;
}

struct PpkHeader
{
    ByteView algorithm;
    ByteView encryption;
};

tcputty::PpkLoadResult ParsePpkHeader(const std::vector<LineView> &lines, PpkHeader &header,
                                      tcputty::PpkKeyInfo &info, std::string &errorMessage)
{
    info = {};
    header = {};
    if (lines.empty())
    {
        errorMessage = "The PPK file is empty.";
        return tcputty::PpkLoadResult::Invalid;
    }

    ByteView firstLine;
    if (!HeaderValue(lines[0], "PuTTY-User-Key-File-", firstLine))
    {
        errorMessage = "The selected .ppk file does not contain a PuTTY private-key header.";
        return tcputty::PpkLoadResult::NotPpk;
    }

    size_t separator = firstLine.size;
    for (size_t i = 0; i + 1 < firstLine.size; ++i)
    {
        if (firstLine.data[i] == ':' && firstLine.data[i + 1] == ' ')
        {
            separator = i;
            break;
        }
    }
    if (separator == firstLine.size)
    {
        errorMessage = "The PuTTY private-key header is malformed.";
        return tcputty::PpkLoadResult::Invalid;
    }

    ByteView versionValue = {firstLine.data, separator};
    ByteView algorithmValue = {firstLine.data + separator + 2, firstLine.size - separator - 2};
    size_t version = 0;
    if (!ParseDecimal(versionValue, 99, version) || !CopySafeToken(algorithmValue, 128, info.algorithm))
    {
        errorMessage = "The PuTTY private-key version or algorithm name is invalid.";
        return tcputty::PpkLoadResult::Invalid;
    }
    info.version = static_cast<unsigned>(version);
    header.algorithm = algorithmValue;

    if (lines.size() < 2 || !HeaderValue(lines[1], "Encryption: ", header.encryption) ||
        !CopySafeToken(header.encryption, 64, info.encryption))
    {
        errorMessage = "The PPK Encryption header is missing or invalid.";
        return tcputty::PpkLoadResult::Invalid;
    }

    char message[256] = {};
    if (info.version != 3)
    {
        snprintf(message, sizeof(message),
                 "This is PuTTY PPK version %u; this release supports only PPK version 3.", info.version);
        errorMessage = message;
        return tcputty::PpkLoadResult::Unsupported;
    }
    if (info.algorithm != "ssh-rsa" && info.algorithm != "ssh-ed25519")
    {
        snprintf(message, sizeof(message),
                 "This PPK uses %s; this release currently supports only ssh-rsa and ssh-ed25519.",
                 info.algorithm.c_str());
        errorMessage = message;
        return tcputty::PpkLoadResult::Unsupported;
    }
    if (info.encryption != "none" && info.encryption != "aes256-cbc")
    {
        snprintf(message, sizeof(message), "This PPK uses unsupported encryption %s; only none and aes256-cbc are "
                                           "supported.",
                 info.encryption.c_str());
        errorMessage = message;
        return tcputty::PpkLoadResult::Unsupported;
    }

    return tcputty::PpkLoadResult::Success;
}

bool SplitLines(const tcputty::SecureBuffer &file, std::vector<LineView> &lines)
{
    lines.clear();
    size_t position = 0;
    while (position < file.Size())
    {
        if (lines.size() >= kMaximumLines)
            return false;
        size_t start = position;
        while (position < file.Size() && file.Data()[position] != '\r' && file.Data()[position] != '\n')
        {
            if (file.Data()[position] == 0)
                return false;
            ++position;
        }
        LineView line = {file.Data() + start, position - start};
        lines.push_back(line);
        if (position < file.Size())
        {
            unsigned char first = file.Data()[position++];
            if (first == '\r' && position < file.Size() && file.Data()[position] == '\n')
                ++position;
        }
    }
    return !lines.empty();
}

int Base64Value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

bool DecodeBase64(const std::vector<LineView> &lines, size_t first, size_t count, tcputty::SecureBuffer &decoded)
{
    size_t encodedSize = 0;
    for (size_t i = 0; i < count; ++i)
    {
        const LineView &line = lines[first + i];
        if (line.size == 0 || line.size > kMaximumBase64Line || !CheckedAdd(encodedSize, line.size, encodedSize) ||
            encodedSize > kMaximumPpkSize)
            return false;
    }
    if (encodedSize == 0 || encodedSize % 4 != 0)
        return false;

    tcputty::SecureBuffer encoded(encodedSize);
    size_t offset = 0;
    for (size_t i = 0; i < count; ++i)
    {
        memcpy(encoded.Data() + offset, lines[first + i].data, lines[first + i].size);
        offset += lines[first + i].size;
    }

    decoded.Clear();
    decoded.Reserve((encodedSize / 4) * 3);
    for (size_t i = 0; i < encodedSize; i += 4)
    {
        bool final = i + 4 == encodedSize;
        unsigned char a = encoded.Data()[i];
        unsigned char b = encoded.Data()[i + 1];
        unsigned char c = encoded.Data()[i + 2];
        unsigned char d = encoded.Data()[i + 3];
        int va = Base64Value(a);
        int vb = Base64Value(b);
        if (va < 0 || vb < 0)
            return false;
        if (c == '=')
        {
            if (!final || d != '=' || (vb & 0x0F) != 0)
                return false;
            decoded.PushBack(static_cast<unsigned char>((va << 2) | (vb >> 4)));
            continue;
        }
        int vc = Base64Value(c);
        if (vc < 0)
            return false;
        decoded.PushBack(static_cast<unsigned char>((va << 2) | (vb >> 4)));
        if (d == '=')
        {
            if (!final || (vc & 0x03) != 0)
                return false;
            decoded.PushBack(static_cast<unsigned char>((vb << 4) | (vc >> 2)));
            continue;
        }
        int vd = Base64Value(d);
        if (vd < 0)
            return false;
        decoded.PushBack(static_cast<unsigned char>((vb << 4) | (vc >> 2)));
        decoded.PushBack(static_cast<unsigned char>((vc << 6) | vd));
    }
    return !decoded.Empty();
}

int HexValue(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool DecodeHex(const ByteView &value, size_t maximumBytes, tcputty::SecureBuffer &decoded)
{
    decoded.Clear();
    if (value.size == 0 || (value.size & 1) != 0 || value.size / 2 > maximumBytes)
        return false;
    decoded.Resize(value.size / 2);
    for (size_t i = 0; i < decoded.Size(); ++i)
    {
        int high = HexValue(value.data[i * 2]);
        int low = HexValue(value.data[i * 2 + 1]);
        if (high < 0 || low < 0)
        {
            decoded.Clear();
            return false;
        }
        decoded.Data()[i] = static_cast<unsigned char>((high << 4) | low);
    }
    return true;
}

bool ParseHexMac(const ByteView &value, unsigned char mac[32])
{
    if (value.size != 64)
        return false;
    for (size_t i = 0; i < 32; ++i)
    {
        int high = HexValue(value.data[i * 2]);
        int low = HexValue(value.data[i * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        mac[i] = static_cast<unsigned char>((high << 4) | low);
    }
    return true;
}

bool HashData(BCRYPT_HASH_HANDLE hash, const void *data, size_t size)
{
    if (size > (std::numeric_limits<ULONG>::max)())
        return false;
    return NtOk(BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<void *>(data)), static_cast<ULONG>(size), 0));
}

bool HashSshString(BCRYPT_HASH_HANDLE hash, const ByteView &value)
{
    if (value.size > 0xFFFFFFFFu)
        return false;
    unsigned char length[4] = {
        static_cast<unsigned char>((value.size >> 24) & 0xFF), static_cast<unsigned char>((value.size >> 16) & 0xFF),
        static_cast<unsigned char>((value.size >> 8) & 0xFF), static_cast<unsigned char>(value.size & 0xFF)};
    return HashData(hash, length, sizeof(length)) && HashData(hash, value.data, value.size);
}

bool VerifyMac(const ByteView &algorithm, const ByteView &encryption, const ByteView &comment,
               const tcputty::SecureBuffer &publicBlob, const tcputty::SecureBuffer &privateBlob,
               const unsigned char expected[32], const unsigned char *macKey, size_t macKeyLength)
{
    AlgorithmHandle algorithmHandle;
    if (!NtOk(BCryptOpenAlgorithmProvider(&algorithmHandle.handle, BCRYPT_SHA256_ALGORITHM, nullptr,
                                          BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        return false;
    DWORD objectLength = 0;
    DWORD returned = 0;
    if (!NtOk(BCryptGetProperty(algorithmHandle.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength),
                                sizeof(objectLength), &returned, 0)) ||
        returned != sizeof(objectLength) || objectLength > 64 * 1024)
        return false;
    tcputty::SecureBuffer hashObject(objectLength);
    HashHandle hash;
    if (macKeyLength > (std::numeric_limits<ULONG>::max)() ||
        !NtOk(BCryptCreateHash(algorithmHandle.handle, &hash.handle, hashObject.Data(), objectLength,
                               const_cast<PUCHAR>(macKey), static_cast<ULONG>(macKeyLength), 0)))
        return false;
    ByteView publicView = {publicBlob.Data(), publicBlob.Size()};
    ByteView privateView = {privateBlob.Data(), privateBlob.Size()};
    if (!HashSshString(hash.handle, algorithm) || !HashSshString(hash.handle, encryption) ||
        !HashSshString(hash.handle, comment) || !HashSshString(hash.handle, publicView) ||
        !HashSshString(hash.handle, privateView))
        return false;
    unsigned char computed[32] = {};
    if (!NtOk(BCryptFinishHash(hash.handle, computed, sizeof(computed), 0)))
        return false;
    unsigned char difference = 0;
    for (size_t i = 0; i < sizeof(computed); ++i)
        difference |= computed[i] ^ expected[i];
    SecureZeroMemory(computed, sizeof(computed));
    return difference == 0;
}

bool DerivePpkKeys(argon2_type type, uint32_t memoryKiB, uint32_t passes, uint32_t parallelism,
                   const tcputty::SecureBuffer &salt, const unsigned char *passphrase, size_t passphraseLength,
                   tcputty::SecureBuffer &derived)
{
    derived.Clear();
    if (!passphrase || passphraseLength > kMaximumPassphraseSize || salt.Empty() || salt.Size() > UINT32_MAX)
        return false;
    derived.Resize(80);
    int result = argon2_hash(passes, memoryKiB, parallelism, passphrase, passphraseLength, salt.Data(), salt.Size(),
                             derived.Data(), derived.Size(), nullptr, 0, type, ARGON2_VERSION_13);
    if (result != ARGON2_OK)
    {
        derived.Clear();
        return false;
    }
    return true;
}

bool DecryptAes256Cbc(const tcputty::SecureBuffer &ciphertext, const unsigned char key[32],
                      const unsigned char initialVector[16], tcputty::SecureBuffer &plaintext)
{
    plaintext.Clear();
    if (ciphertext.Empty() || (ciphertext.Size() & 15) != 0 || ciphertext.Size() > ULONG_MAX)
        return false;

    AlgorithmHandle algorithm;
    if (!NtOk(BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return false;
    const wchar_t chainingMode[] = BCRYPT_CHAIN_MODE_CBC;
    if (!NtOk(BCryptSetProperty(algorithm.handle, BCRYPT_CHAINING_MODE,
                                reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(chainingMode)),
                                static_cast<ULONG>(sizeof(chainingMode)), 0)))
        return false;

    DWORD objectLength = 0;
    DWORD returned = 0;
    if (!NtOk(BCryptGetProperty(algorithm.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength),
                                sizeof(objectLength), &returned, 0)) ||
        returned != sizeof(objectLength) || objectLength == 0 || objectLength > 64 * 1024)
        return false;
    tcputty::SecureBuffer keyObject(objectLength);
    KeyHandle keyHandle;
    if (!NtOk(BCryptGenerateSymmetricKey(algorithm.handle, &keyHandle.handle, keyObject.Data(), objectLength,
                                         const_cast<PUCHAR>(key), 32, 0)))
        return false;

    tcputty::SecureBuffer iv(16);
    memcpy(iv.Data(), initialVector, iv.Size());
    plaintext.Resize(ciphertext.Size());
    ULONG plaintextLength = 0;
    if (!NtOk(BCryptDecrypt(keyHandle.handle, const_cast<PUCHAR>(ciphertext.Data()),
                            static_cast<ULONG>(ciphertext.Size()), nullptr, iv.Data(), static_cast<ULONG>(iv.Size()),
                            plaintext.Data(), static_cast<ULONG>(plaintext.Size()), &plaintextLength, 0)) ||
        plaintextLength != plaintext.Size())
    {
        plaintext.Clear();
        return false;
    }
    return true;
}

uint32_t ReadUint32(const unsigned char *data)
{
    return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
}

class SshReader
{
  public:
    explicit SshReader(const tcputty::SecureBuffer &buffer) : data_(buffer.Data()), size_(buffer.Size())
    {
    }

    bool ReadString(ByteView &value)
    {
        if (position_ > size_ || size_ - position_ < 4)
            return false;
        uint32_t length = ReadUint32(data_ + position_);
        position_ += 4;
        if (length > size_ - position_)
            return false;
        value.data = data_ + position_;
        value.size = length;
        position_ += length;
        return true;
    }

    bool ReadPositiveMpint(ByteView &value)
    {
        ByteView encoded;
        if (!ReadString(encoded) || encoded.size == 0 || (encoded.data[0] & 0x80) != 0)
            return false;
        if (encoded.size > 1 && encoded.data[0] == 0 && (encoded.data[1] & 0x80) == 0)
            return false;
        if (encoded.size == 1 && encoded.data[0] == 0)
            return false;
        if (encoded.data[0] == 0)
        {
            ++encoded.data;
            --encoded.size;
        }
        value = encoded;
        return true;
    }

    bool AtEnd() const
    {
        return position_ == size_;
    }

    size_t Remaining() const
    {
        return position_ <= size_ ? size_ - position_ : 0;
    }

  private:
    const unsigned char *data_ = nullptr;
    size_t size_ = 0;
    size_t position_ = 0;
};

bool EqualInteger(const ByteView &input, const unsigned char *encoded, size_t encodedSize)
{
    while (encodedSize > 0 && *encoded == 0)
    {
        ++encoded;
        --encodedSize;
    }
    return input.size == encodedSize && memcmp(input.data, encoded, encodedSize) == 0;
}

unsigned BitLength(const ByteView &integer)
{
    if (integer.size == 0)
        return 0;
    unsigned topBits = 8;
    unsigned char top = integer.data[0];
    while ((top & 0x80) == 0)
    {
        top <<= 1;
        --topBits;
    }
    size_t bits = (integer.size - 1) * 8 + topBits;
    return bits <= (std::numeric_limits<unsigned>::max)() ? static_cast<unsigned>(bits) : 0;
}

bool AppendBlobPart(tcputty::SecureBuffer &blob, const ByteView &part)
{
    if (part.size > (std::numeric_limits<ULONG>::max)())
        return false;
    blob.Append(part.data, part.size);
    return true;
}

bool ValidateRsaKey(BCRYPT_KEY_HANDLE key)
{
    unsigned char digest[32] = {};
    for (size_t i = 0; i < sizeof(digest); ++i)
        digest[i] = static_cast<unsigned char>(i);
    BCRYPT_PKCS1_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM};
    ULONG signatureLength = 0;
    if (!NtOk(BCryptSignHash(key, &padding, digest, sizeof(digest), nullptr, 0, &signatureLength, BCRYPT_PAD_PKCS1)) ||
        signatureLength == 0 || signatureLength > 16 * 1024)
        return false;
    tcputty::SecureBuffer signature(signatureLength);
    if (!NtOk(BCryptSignHash(key, &padding, digest, sizeof(digest), signature.Data(), signatureLength, &signatureLength,
                             BCRYPT_PAD_PKCS1)))
        return false;
    return NtOk(BCryptVerifySignature(key, &padding, digest, sizeof(digest), signature.Data(), signatureLength,
                                      BCRYPT_PAD_PKCS1));
}

bool ExportPrivatePem(const ByteView &exponent, const ByteView &modulus, const ByteView &privateExponent,
                      const ByteView &prime1, const ByteView &prime2, const ByteView &coefficient,
                      tcputty::SecureBuffer &pem)
{
    unsigned bits = BitLength(modulus);
    if (bits < 2048 || bits > 8192 || exponent.size == 0 || exponent.size > 8 || prime1.size == 0 || prime2.size == 0)
        return false;

    size_t total = sizeof(BCRYPT_RSAKEY_BLOB);
    if (!CheckedAdd(total, exponent.size, total) || !CheckedAdd(total, modulus.size, total) ||
        !CheckedAdd(total, prime1.size, total) || !CheckedAdd(total, prime2.size, total) || total > 64 * 1024)
        return false;
    tcputty::SecureBuffer importBlob(total);
    BCRYPT_RSAKEY_BLOB header = {};
    header.Magic = BCRYPT_RSAPRIVATE_MAGIC;
    header.BitLength = bits;
    header.cbPublicExp = static_cast<ULONG>(exponent.size);
    header.cbModulus = static_cast<ULONG>(modulus.size);
    header.cbPrime1 = static_cast<ULONG>(prime1.size);
    header.cbPrime2 = static_cast<ULONG>(prime2.size);
    memcpy(importBlob.Data(), &header, sizeof(header));
    size_t offset = sizeof(header);
    memcpy(importBlob.Data() + offset, exponent.data, exponent.size);
    offset += exponent.size;
    memcpy(importBlob.Data() + offset, modulus.data, modulus.size);
    offset += modulus.size;
    memcpy(importBlob.Data() + offset, prime1.data, prime1.size);
    offset += prime1.size;
    memcpy(importBlob.Data() + offset, prime2.data, prime2.size);

    AlgorithmHandle rsa;
    if (!NtOk(BCryptOpenAlgorithmProvider(&rsa.handle, BCRYPT_RSA_ALGORITHM, nullptr, 0)))
        return false;
    KeyHandle key;
    if (!NtOk(BCryptImportKeyPair(rsa.handle, nullptr, BCRYPT_RSAPRIVATE_BLOB, &key.handle, importBlob.Data(),
                                  static_cast<ULONG>(importBlob.Size()), 0)) ||
        !ValidateRsaKey(key.handle))
        return false;

    ULONG fullSize = 0;
    if (!NtOk(BCryptExportKey(key.handle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &fullSize, 0)) ||
        fullSize < sizeof(BCRYPT_RSAKEY_BLOB) || fullSize > 64 * 1024)
        return false;
    tcputty::SecureBuffer fullBlob(fullSize);
    if (!NtOk(
            BCryptExportKey(key.handle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, fullBlob.Data(), fullSize, &fullSize, 0)))
        return false;
    fullBlob.Resize(fullSize);

    const BCRYPT_RSAKEY_BLOB *fullHeader = reinterpret_cast<const BCRYPT_RSAKEY_BLOB *>(fullBlob.Data());
    if (fullHeader->Magic != BCRYPT_RSAFULLPRIVATE_MAGIC)
        return false;
    size_t required = sizeof(BCRYPT_RSAKEY_BLOB);
    size_t fields[] = {fullHeader->cbPublicExp, fullHeader->cbModulus, fullHeader->cbPrime1, fullHeader->cbPrime2,
                       fullHeader->cbPrime1,    fullHeader->cbPrime2,  fullHeader->cbPrime1, fullHeader->cbModulus};
    for (size_t field : fields)
        if (!CheckedAdd(required, field, required))
            return false;
    if (required != fullBlob.Size())
        return false;

    const unsigned char *cursor = fullBlob.Data() + sizeof(BCRYPT_RSAKEY_BLOB);
    const unsigned char *exportExponent = cursor;
    cursor += fullHeader->cbPublicExp;
    const unsigned char *exportModulus = cursor;
    cursor += fullHeader->cbModulus;
    const unsigned char *exportPrime1 = cursor;
    cursor += fullHeader->cbPrime1;
    const unsigned char *exportPrime2 = cursor;
    cursor += fullHeader->cbPrime2;
    cursor += fullHeader->cbPrime1; // exponent1
    cursor += fullHeader->cbPrime2; // exponent2
    const unsigned char *exportCoefficient = cursor;
    cursor += fullHeader->cbPrime1;
    const unsigned char *exportPrivateExponent = cursor;

    if (!EqualInteger(exponent, exportExponent, fullHeader->cbPublicExp) ||
        !EqualInteger(modulus, exportModulus, fullHeader->cbModulus) ||
        !EqualInteger(prime1, exportPrime1, fullHeader->cbPrime1) ||
        !EqualInteger(prime2, exportPrime2, fullHeader->cbPrime2) ||
        !EqualInteger(coefficient, exportCoefficient, fullHeader->cbPrime1))
        return false;

    // d may have an equivalent representation modulo lcm(p-1,q-1), so it is
    // deliberately validated by sign+verify above instead of byte equality.
    (void)privateExponent;
    (void)exportPrivateExponent;

    DWORD derSize = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PRIVATE_KEY_BLOB, fullBlob.Data(), 0, nullptr, nullptr,
                             &derSize) ||
        derSize == 0 || derSize > 64 * 1024)
        return false;
    tcputty::SecureBuffer der(derSize);
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PRIVATE_KEY_BLOB, fullBlob.Data(), 0, nullptr, der.Data(),
                             &derSize))
        return false;
    der.Resize(derSize);

    static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char begin[] = "-----BEGIN RSA PRIVATE KEY-----\n";
    static const char end[] = "-----END RSA PRIVATE KEY-----\n";
    pem.Clear();
    pem.Reserve(sizeof(begin) + sizeof(end) + ((der.Size() + 2) / 3) * 4 + der.Size() / 48 + 8);
    pem.Append(begin, sizeof(begin) - 1);
    size_t column = 0;
    for (size_t i = 0; i < der.Size(); i += 3)
    {
        unsigned value = static_cast<unsigned>(der.Data()[i]) << 16;
        bool haveSecond = i + 1 < der.Size();
        bool haveThird = i + 2 < der.Size();
        if (haveSecond)
            value |= static_cast<unsigned>(der.Data()[i + 1]) << 8;
        if (haveThird)
            value |= der.Data()[i + 2];
        unsigned char out[4] = {static_cast<unsigned char>(base64[(value >> 18) & 63]),
                                static_cast<unsigned char>(base64[(value >> 12) & 63]),
                                static_cast<unsigned char>(haveSecond ? base64[(value >> 6) & 63] : '='),
                                static_cast<unsigned char>(haveThird ? base64[value & 63] : '=')};
        pem.Append(out, sizeof(out));
        column += 4;
        if (column == 64)
        {
            pem.PushBack('\n');
            column = 0;
        }
    }
    if (column != 0)
        pem.PushBack('\n');
    pem.Append(end, sizeof(end) - 1);
    return true;
}

std::string Base64Public(const tcputty::SecureBuffer &data)
{
    static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((data.Size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.Size(); i += 3)
    {
        unsigned value = static_cast<unsigned>(data.Data()[i]) << 16;
        bool haveSecond = i + 1 < data.Size();
        bool haveThird = i + 2 < data.Size();
        if (haveSecond)
            value |= static_cast<unsigned>(data.Data()[i + 1]) << 8;
        if (haveThird)
            value |= data.Data()[i + 2];
        encoded.push_back(base64[(value >> 18) & 63]);
        encoded.push_back(base64[(value >> 12) & 63]);
        encoded.push_back(haveSecond ? base64[(value >> 6) & 63] : '=');
        encoded.push_back(haveThird ? base64[value & 63] : '=');
    }
    return encoded;
}

bool ReadFileSecure(const char *path, tcputty::SecureBuffer &file, std::string &errorMessage)
{
    file.Clear();
    if (!path || !*path)
    {
        errorMessage = "The PPK path is empty.";
        return false;
    }
    int wideLength = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, path, -1, nullptr, 0);
    if (wideLength <= 0 || wideLength > 32768)
    {
        errorMessage = "The PPK path is empty or cannot be represented safely.";
        return false;
    }
    std::vector<wchar_t> widePath(static_cast<size_t>(wideLength), L'\0');
    if (MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, path, -1, widePath.data(), wideLength) == 0)
    {
        errorMessage = "The PPK path cannot be converted to Unicode.";
        return false;
    }
    HANDLE handle = CreateFileW(widePath.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        errorMessage = "The PPK file does not exist or cannot be opened.";
        return false;
    }
    LARGE_INTEGER size = {};
    bool sizeKnown = GetFileSizeEx(handle, &size) != FALSE;
    bool ok = sizeKnown && size.QuadPart > 0 && size.QuadPart <= kMaximumPpkSize;
    if (!sizeKnown)
        errorMessage = "Windows could not determine the PPK file size.";
    else if (size.QuadPart == 0)
        errorMessage = "The PPK file is empty.";
    else if (size.QuadPart > kMaximumPpkSize)
        errorMessage = "The PPK file exceeds the 64 KiB safety limit.";
    if (ok)
    {
        file.Resize(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        ok = ReadFile(handle, file.Data(), static_cast<DWORD>(file.Size()), &read, nullptr) && read == file.Size();
        if (!ok)
            errorMessage = "The PPK file could not be read completely.";
    }
    CloseHandle(handle);
    if (!ok)
        file.Clear();
    return ok;
}

struct ParsedPpk
{
    ByteView algorithm;
    ByteView encryption;
    ByteView comment;
    ByteView macValue;
    ByteView saltHex;
    size_t publicFirst = 0;
    size_t publicCount = 0;
    size_t privateFirst = 0;
    size_t privateCount = 0;
    bool encrypted = false;
    argon2_type argonType = Argon2_id;
    uint32_t argonMemoryKiB = 0;
    uint32_t argonPasses = 0;
    uint32_t argonParallelism = 0;
};

tcputty::PpkLoadResult ParseOuterPpk(const std::vector<LineView> &lines, ParsedPpk &parsed,
                                     tcputty::PpkKeyInfo &info, std::string &errorMessage)
{
    parsed = {};
    PpkHeader header;
    tcputty::PpkLoadResult headerResult = ParsePpkHeader(lines, header, info, errorMessage);
    if (headerResult != tcputty::PpkLoadResult::Success)
        return headerResult;
    parsed.algorithm = header.algorithm;
    parsed.encryption = header.encryption;
    parsed.encrypted = info.encryption == "aes256-cbc";

    if (lines.size() < 7)
    {
        errorMessage = "The PPK file is truncated.";
        return tcputty::PpkLoadResult::Invalid;
    }

    ByteView publicCountValue;
    if (!HeaderValue(lines[2], "Comment: ", parsed.comment) ||
        !HeaderValue(lines[3], "Public-Lines: ", publicCountValue))
    {
        errorMessage = "The PPK headers are missing or out of order.";
        return tcputty::PpkLoadResult::Invalid;
    }
    if (!ParseDecimal(publicCountValue, kMaximumLines, parsed.publicCount) ||
        parsed.publicCount > lines.size() - 4)
    {
        errorMessage = "Public-Lines is invalid.";
        return tcputty::PpkLoadResult::Invalid;
    }
    parsed.publicFirst = 4;
    size_t cursor = parsed.publicFirst + parsed.publicCount;

    if (parsed.encrypted)
    {
        if (cursor > lines.size() || lines.size() - cursor < 6)
        {
            errorMessage = "The encrypted PPK key-derivation headers are truncated.";
            return tcputty::PpkLoadResult::Invalid;
        }
        ByteView derivation;
        ByteView memoryValue;
        ByteView passesValue;
        ByteView parallelismValue;
        if (!HeaderValue(lines[cursor], "Key-Derivation: ", derivation) ||
            !HeaderValue(lines[cursor + 1], "Argon2-Memory: ", memoryValue) ||
            !HeaderValue(lines[cursor + 2], "Argon2-Passes: ", passesValue) ||
            !HeaderValue(lines[cursor + 3], "Argon2-Parallelism: ", parallelismValue) ||
            !HeaderValue(lines[cursor + 4], "Argon2-Salt: ", parsed.saltHex))
        {
            errorMessage = "The encrypted PPK key-derivation headers are missing or out of order.";
            return tcputty::PpkLoadResult::Invalid;
        }
        std::string derivationName;
        if (!CopySafeToken(derivation, 32, derivationName))
        {
            errorMessage = "The PPK key-derivation algorithm name is invalid.";
            return tcputty::PpkLoadResult::Invalid;
        }
        if (derivationName == "Argon2d")
            parsed.argonType = Argon2_d;
        else if (derivationName == "Argon2i")
            parsed.argonType = Argon2_i;
        else if (derivationName == "Argon2id")
            parsed.argonType = Argon2_id;
        else
        {
            errorMessage = "The encrypted PPK uses an unsupported key-derivation algorithm.";
            return tcputty::PpkLoadResult::Unsupported;
        }

        size_t memoryKiB = 0;
        size_t passes = 0;
        size_t parallelism = 0;
        if (!ParseDecimal(memoryValue, kMaximumArgon2MemoryKiB, memoryKiB) ||
            !ParseDecimal(passesValue, kMaximumArgon2Passes, passes) ||
            !ParseDecimal(parallelismValue, kMaximumArgon2Parallelism, parallelism) ||
            memoryKiB < 8 * parallelism || memoryKiB > kMaximumArgon2WorkKiB / passes)
        {
            errorMessage = "The PPK Argon2 parameters are invalid or exceed the safety limits (256 MiB, 1024 passes, "
                           "16 lanes, and 8 GiB of aggregate memory work).";
            return tcputty::PpkLoadResult::Invalid;
        }
        tcputty::SecureBuffer salt;
        if (!DecodeHex(parsed.saltHex, kMaximumArgon2SaltSize, salt) || salt.Size() < 8)
        {
            errorMessage = "The PPK Argon2 salt must contain 8 to 64 bytes of hexadecimal data.";
            return tcputty::PpkLoadResult::Invalid;
        }
        parsed.argonMemoryKiB = static_cast<uint32_t>(memoryKiB);
        parsed.argonPasses = static_cast<uint32_t>(passes);
        parsed.argonParallelism = static_cast<uint32_t>(parallelism);
        cursor += 5;
    }

    ByteView privateCountValue;
    if (cursor >= lines.size() || !HeaderValue(lines[cursor], "Private-Lines: ", privateCountValue))
    {
        errorMessage = "Private-Lines is missing or out of order.";
        return tcputty::PpkLoadResult::Invalid;
    }
    if (!ParseDecimal(privateCountValue, kMaximumLines, parsed.privateCount) ||
        parsed.privateCount > lines.size() - cursor - 1)
    {
        errorMessage = "Private-Lines is invalid.";
        return tcputty::PpkLoadResult::Invalid;
    }
    parsed.privateFirst = cursor + 1;
    size_t macIndex = parsed.privateFirst + parsed.privateCount;
    if (macIndex >= lines.size() || macIndex + 1 != lines.size())
    {
        errorMessage = "The PPK private data is truncated or has trailing fields.";
        return tcputty::PpkLoadResult::Invalid;
    }
    if (!HeaderValue(lines[macIndex], "Private-MAC: ", parsed.macValue))
    {
        errorMessage = "Private-MAC is missing.";
        return tcputty::PpkLoadResult::Invalid;
    }
    unsigned char expectedMac[32] = {};
    bool validMac = ParseHexMac(parsed.macValue, expectedMac);
    SecureZeroMemory(expectedMac, sizeof(expectedMac));
    if (!validMac)
    {
        errorMessage = "Private-MAC must contain exactly 32 bytes of hexadecimal data.";
        return tcputty::PpkLoadResult::Invalid;
    }
    return tcputty::PpkLoadResult::Success;
}
} // namespace

namespace tcputty
{
SecureBuffer::SecureBuffer(size_t size) : bytes_(size)
{
}

SecureBuffer::~SecureBuffer()
{
    Clear();
}

SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept : bytes_(std::move(other.bytes_))
{
}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept
{
    if (this != &other)
    {
        Clear();
        bytes_ = std::move(other.bytes_);
    }
    return *this;
}

unsigned char *SecureBuffer::Data()
{
    return bytes_.empty() ? nullptr : bytes_.data();
}

const unsigned char *SecureBuffer::Data() const
{
    return bytes_.empty() ? nullptr : bytes_.data();
}

size_t SecureBuffer::Size() const
{
    return bytes_.size();
}

bool SecureBuffer::Empty() const
{
    return bytes_.empty();
}

void SecureBuffer::Resize(size_t size)
{
    if (size < bytes_.size())
        SecureZeroMemory(bytes_.data() + size, bytes_.size() - size);
    bytes_.resize(size);
}

void SecureBuffer::Reserve(size_t size)
{
    bytes_.reserve(size);
}

void SecureBuffer::PushBack(unsigned char value)
{
    bytes_.push_back(value);
}

void SecureBuffer::Append(const void *data, size_t size)
{
    if (size == 0)
        return;
    size_t original = bytes_.size();
    bytes_.resize(original + size);
    memcpy(bytes_.data() + original, data, size);
}

void SecureBuffer::Clear()
{
    SecureWipe(bytes_);
    bytes_.clear();
}

bool HasPpkExtension(const char *path)
{
    if (!path)
        return false;
    const char *extension = strrchr(path, '.');
    return extension && _stricmp(extension, ".ppk") == 0;
}

PpkLoadResult InspectPpkFile(const char *path, PpkKeyInfo &info, std::string &errorMessage)
{
    info = {};
    errorMessage.clear();
    SecureBuffer file;
    if (!path || !*path || !ReadFileSecure(path, file, errorMessage))
    {
        if (errorMessage.empty())
            errorMessage = "The PPK path is empty.";
        return PpkLoadResult::IoError;
    }
    std::vector<LineView> lines;
    if (!SplitLines(file, lines))
    {
        errorMessage = "The PPK text structure is invalid.";
        return PpkLoadResult::Invalid;
    }
    ParsedPpk parsed;
    return ParseOuterPpk(lines, parsed, info, errorMessage);
}

PpkLoadResult LoadPpkV3Key(const char *path, const unsigned char *passphrase, size_t passphraseLength, MemoryKey &key,
                           std::string &errorMessage)
{
    key.algorithm = MemoryKey::Algorithm::Rsa;
    key.publicKeyFile.clear();
    key.publicKeyBlob.Clear();
    key.publicKeyPoint.Clear();
    key.privateKeyPem.Clear();
    key.privateKeySeed.Clear();
    errorMessage.clear();

    SecureBuffer file;
    if (!path || !*path || !ReadFileSecure(path, file, errorMessage))
    {
        if (errorMessage.empty())
            errorMessage = "The PPK path is empty.";
        return PpkLoadResult::IoError;
    }
    std::vector<LineView> lines;
    if (!SplitLines(file, lines))
    {
        errorMessage = "The PPK text structure is invalid.";
        return PpkLoadResult::Invalid;
    }

    ParsedPpk parsed;
    PpkKeyInfo info;
    PpkLoadResult parseResult = ParseOuterPpk(lines, parsed, info, errorMessage);
    if (parseResult != PpkLoadResult::Success)
        return parseResult;

    SecureBuffer publicBlob;
    SecureBuffer storedPrivateBlob;
    if (!DecodeBase64(lines, parsed.publicFirst, parsed.publicCount, publicBlob) ||
        !DecodeBase64(lines, parsed.privateFirst, parsed.privateCount, storedPrivateBlob))
    {
        errorMessage = "The PPK contains invalid or non-canonical base64 data.";
        return PpkLoadResult::Invalid;
    }

    SecureBuffer privateBlob;
    SecureBuffer derived;
    if (parsed.encrypted)
    {
        if (!passphrase)
        {
            errorMessage = "This PPK is encrypted and requires its key passphrase.";
            return PpkLoadResult::PassphraseRequired;
        }
        if (passphraseLength > kMaximumPassphraseSize)
        {
            errorMessage = "The PPK passphrase exceeds the 4096-byte safety limit.";
            return PpkLoadResult::Invalid;
        }
        if ((storedPrivateBlob.Size() & 15) != 0)
        {
            errorMessage = "The encrypted PPK private data is not a whole number of AES blocks.";
            return PpkLoadResult::Invalid;
        }
        SecureBuffer salt;
        if (!DecodeHex(parsed.saltHex, kMaximumArgon2SaltSize, salt) ||
            !DerivePpkKeys(parsed.argonType, parsed.argonMemoryKiB, parsed.argonPasses, parsed.argonParallelism, salt,
                           passphrase, passphraseLength, derived))
        {
            errorMessage = "The encrypted PPK key derivation failed within the configured safety limits.";
            return PpkLoadResult::Invalid;
        }
        if (!DecryptAes256Cbc(storedPrivateBlob, derived.Data(), derived.Data() + 32, privateBlob))
        {
            errorMessage = "Windows could not decrypt the PPK private data safely in memory.";
            return PpkLoadResult::Invalid;
        }
    }
    else
    {
        privateBlob = std::move(storedPrivateBlob);
    }

    unsigned char expectedMac[32] = {};
    const unsigned char *macKey = parsed.encrypted ? derived.Data() + 48 : nullptr;
    size_t macKeyLength = parsed.encrypted ? 32 : 0;
    if (!ParseHexMac(parsed.macValue, expectedMac) ||
        !VerifyMac(parsed.algorithm, parsed.encryption, parsed.comment, publicBlob, privateBlob, expectedMac, macKey,
                   macKeyLength))
    {
        SecureZeroMemory(expectedMac, sizeof(expectedMac));
        if (parsed.encrypted)
        {
            errorMessage = "The PPK passphrase is incorrect or the encrypted key file is damaged.";
            return PpkLoadResult::BadPassphrase;
        }
        errorMessage = "The PPK integrity check failed.";
        return PpkLoadResult::Invalid;
    }
    SecureZeroMemory(expectedMac, sizeof(expectedMac));

    if (info.algorithm == "ssh-ed25519")
    {
        SshReader publicReader(publicBlob);
        ByteView publicAlgorithm;
        ByteView publicPoint;
        if (!publicReader.ReadString(publicAlgorithm) || !Equals(publicAlgorithm, "ssh-ed25519") ||
            !publicReader.ReadString(publicPoint) || publicPoint.size != 32 || !publicReader.AtEnd())
        {
            errorMessage = "The PPK public Ed25519 blob is invalid.";
            return PpkLoadResult::Invalid;
        }
        SshReader privateReader(privateBlob);
        ByteView privateSeed;
        if (!privateReader.ReadString(privateSeed) || privateSeed.size != 32 ||
            (parsed.encrypted ? privateReader.Remaining() > 15 : !privateReader.AtEnd()))
        {
            errorMessage = "The PPK private Ed25519 blob is invalid.";
            return PpkLoadResult::Invalid;
        }
        unsigned char derivedPublic[32] = {};
        bool pairMatches = Ed25519DerivePublic(privateSeed.data, derivedPublic) &&
                           ConstantTimeEqual(derivedPublic, publicPoint.data, sizeof(derivedPublic));
        SecureZeroMemory(derivedPublic, sizeof(derivedPublic));
        if (!pairMatches)
        {
            errorMessage = "The PPK Ed25519 public and private keys do not match.";
            return PpkLoadResult::Invalid;
        }
        key.algorithm = MemoryKey::Algorithm::Ed25519;
        key.publicKeyBlob.Append(publicBlob.Data(), publicBlob.Size());
        key.publicKeyPoint.Append(publicPoint.data, publicPoint.size);
        key.privateKeySeed.Append(privateSeed.data, privateSeed.size);
        key.publicKeyFile = "ssh-ed25519 " + Base64Public(publicBlob) + "\n";
        return PpkLoadResult::Success;
    }

    SshReader publicReader(publicBlob);
    ByteView publicAlgorithm;
    ByteView exponent;
    ByteView modulus;
    if (!publicReader.ReadString(publicAlgorithm) || !Equals(publicAlgorithm, "ssh-rsa") ||
        !publicReader.ReadPositiveMpint(exponent) || !publicReader.ReadPositiveMpint(modulus) || !publicReader.AtEnd())
    {
        errorMessage = "The PPK public RSA blob is invalid.";
        return PpkLoadResult::Invalid;
    }

    SshReader privateReader(privateBlob);
    ByteView privateExponent;
    ByteView prime1;
    ByteView prime2;
    ByteView coefficient;
    if (!privateReader.ReadPositiveMpint(privateExponent) || !privateReader.ReadPositiveMpint(prime1) ||
        !privateReader.ReadPositiveMpint(prime2) || !privateReader.ReadPositiveMpint(coefficient) ||
        (parsed.encrypted ? privateReader.Remaining() > 15 : !privateReader.AtEnd()))
    {
        errorMessage = "The PPK private RSA blob is invalid.";
        return PpkLoadResult::Invalid;
    }

    if (!ExportPrivatePem(exponent, modulus, privateExponent, prime1, prime2, coefficient, key.privateKeyPem))
    {
        errorMessage = "Windows rejected the RSA key or could not convert it safely in memory.";
        key.privateKeyPem.Clear();
        return PpkLoadResult::Invalid;
    }
    key.publicKeyFile = "ssh-rsa " + Base64Public(publicBlob) + "\n";
    return PpkLoadResult::Success;
}

PpkLoadResult LoadPpkV3Key(const char *path, MemoryKey &key, std::string &errorMessage)
{
    return LoadPpkV3Key(path, nullptr, 0, key, errorMessage);
}

} // namespace tcputty
