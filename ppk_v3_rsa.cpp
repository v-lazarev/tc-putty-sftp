#include "ppk_v3_rsa.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace
{
const size_t kMaximumPpkSize = 64 * 1024;
const size_t kMaximumLines = 1024;
const size_t kMaximumBase64Line = 4096;

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

bool ParseHexMac(const ByteView &value, unsigned char mac[32])
{
    if (value.size != 64)
        return false;
    for (size_t i = 0; i < 32; ++i)
    {
        auto hex = [](unsigned char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };
        int high = hex(value.data[i * 2]);
        int low = hex(value.data[i * 2 + 1]);
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
               const unsigned char expected[32])
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
    if (!NtOk(BCryptCreateHash(algorithmHandle.handle, &hash.handle, hashObject.Data(), objectLength, nullptr, 0, 0)))
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

bool ReadFileSecure(const char *path, tcputty::SecureBuffer &file)
{
    int wideLength = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, path, -1, nullptr, 0);
    if (wideLength <= 0 || wideLength > 32768)
        return false;
    std::vector<wchar_t> widePath(static_cast<size_t>(wideLength), L'\0');
    if (MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, path, -1, widePath.data(), wideLength) == 0)
        return false;
    HANDLE handle = CreateFileW(widePath.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER size = {};
    bool ok = GetFileSizeEx(handle, &size) && size.QuadPart > 0 && size.QuadPart <= kMaximumPpkSize;
    if (ok)
    {
        file.Resize(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        ok = ReadFile(handle, file.Data(), static_cast<DWORD>(file.Size()), &read, nullptr) && read == file.Size();
    }
    CloseHandle(handle);
    if (!ok)
        file.Clear();
    return ok;
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

PpkLoadResult LoadPpkV3Rsa(const char *path, MemoryKey &key, std::string &errorMessage)
{
    key.publicKeyFile.clear();
    key.privateKeyPem.Clear();
    errorMessage.clear();

    SecureBuffer file;
    if (!path || !ReadFileSecure(path, file))
    {
        errorMessage = "Unable to read the PPK file (maximum supported size is 64 KiB).";
        return PpkLoadResult::IoError;
    }
    std::vector<LineView> lines;
    if (!SplitLines(file, lines))
    {
        errorMessage = "The PPK text structure is invalid.";
        return PpkLoadResult::Invalid;
    }

    ByteView algorithm;
    if (!HeaderValue(lines[0], "PuTTY-User-Key-File-", algorithm))
        return PpkLoadResult::NotPpk;
    ByteView versionAndAlgorithm = algorithm;
    const char versionPrefix[] = "3: ";
    if (versionAndAlgorithm.size < sizeof(versionPrefix) - 1 ||
        memcmp(versionAndAlgorithm.data, versionPrefix, sizeof(versionPrefix) - 1) != 0)
    {
        errorMessage = "Only PuTTY PPK version 3 is supported by this MVP.";
        return PpkLoadResult::Unsupported;
    }
    algorithm.data += sizeof(versionPrefix) - 1;
    algorithm.size -= sizeof(versionPrefix) - 1;
    if (!Equals(algorithm, "ssh-rsa"))
    {
        errorMessage = "Only ssh-rsa PPK keys are supported by this MVP.";
        return PpkLoadResult::Unsupported;
    }
    if (lines.size() < 7)
    {
        errorMessage = "The PPK file is truncated.";
        return PpkLoadResult::Invalid;
    }

    ByteView encryption;
    ByteView comment;
    ByteView publicCountValue;
    if (!HeaderValue(lines[1], "Encryption: ", encryption) || !HeaderValue(lines[2], "Comment: ", comment) ||
        !HeaderValue(lines[3], "Public-Lines: ", publicCountValue))
    {
        errorMessage = "The PPK headers are missing or out of order.";
        return PpkLoadResult::Invalid;
    }
    if (!Equals(encryption, "none"))
    {
        errorMessage = "Encrypted PPK v3 files are not supported yet.";
        return PpkLoadResult::Unsupported;
    }
    size_t publicLineCount = 0;
    if (!ParseDecimal(publicCountValue, kMaximumLines, publicLineCount) || publicLineCount > lines.size() - 4)
    {
        errorMessage = "Public-Lines is invalid.";
        return PpkLoadResult::Invalid;
    }
    size_t privateHeaderIndex = 4 + publicLineCount;
    if (privateHeaderIndex >= lines.size())
    {
        errorMessage = "The public key data is truncated.";
        return PpkLoadResult::Invalid;
    }
    ByteView privateCountValue;
    if (!HeaderValue(lines[privateHeaderIndex], "Private-Lines: ", privateCountValue))
    {
        errorMessage = "Private-Lines is missing or out of order.";
        return PpkLoadResult::Invalid;
    }
    size_t privateLineCount = 0;
    if (!ParseDecimal(privateCountValue, kMaximumLines, privateLineCount) ||
        privateLineCount > lines.size() - privateHeaderIndex - 1)
    {
        errorMessage = "Private-Lines is invalid.";
        return PpkLoadResult::Invalid;
    }
    size_t macIndex = privateHeaderIndex + 1 + privateLineCount;
    if (macIndex >= lines.size() || macIndex + 1 != lines.size())
    {
        errorMessage = "The PPK private data is truncated or has trailing fields.";
        return PpkLoadResult::Invalid;
    }
    ByteView macValue;
    if (!HeaderValue(lines[macIndex], "Private-MAC: ", macValue))
    {
        errorMessage = "Private-MAC is missing.";
        return PpkLoadResult::Invalid;
    }

    SecureBuffer publicBlob;
    SecureBuffer privateBlob;
    if (!DecodeBase64(lines, 4, publicLineCount, publicBlob) ||
        !DecodeBase64(lines, privateHeaderIndex + 1, privateLineCount, privateBlob))
    {
        errorMessage = "The PPK contains invalid or non-canonical base64 data.";
        return PpkLoadResult::Invalid;
    }
    unsigned char expectedMac[32] = {};
    if (!ParseHexMac(macValue, expectedMac) ||
        !VerifyMac(algorithm, encryption, comment, publicBlob, privateBlob, expectedMac))
    {
        SecureZeroMemory(expectedMac, sizeof(expectedMac));
        errorMessage = "The PPK integrity check failed.";
        return PpkLoadResult::Invalid;
    }
    SecureZeroMemory(expectedMac, sizeof(expectedMac));

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
        !privateReader.AtEnd())
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
} // namespace tcputty
