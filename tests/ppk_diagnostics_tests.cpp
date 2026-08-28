#include "../ppk_v3_rsa.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace
{
class AlgorithmHandle
{
  public:
    ~AlgorithmHandle()
    {
        if (value)
            BCryptCloseAlgorithmProvider(value, 0);
    }
    BCRYPT_ALG_HANDLE value = nullptr;
};

class KeyHandle
{
  public:
    ~KeyHandle()
    {
        if (value)
            BCryptDestroyKey(value);
    }
    BCRYPT_KEY_HANDLE value = nullptr;
};

class HashHandle
{
  public:
    ~HashHandle()
    {
        if (value)
            BCryptDestroyHash(value);
    }
    BCRYPT_HASH_HANDLE value = nullptr;
};

class TemporaryFile
{
  public:
    ~TemporaryFile()
    {
        if (!path.empty())
            DeleteFileA(path.c_str());
    }
    std::string path;
};

bool NtOk(NTSTATUS status)
{
    return status >= 0;
}

void AppendUint32(std::vector<unsigned char> &output, size_t value)
{
    output.push_back(static_cast<unsigned char>((value >> 24) & 0xFF));
    output.push_back(static_cast<unsigned char>((value >> 16) & 0xFF));
    output.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
    output.push_back(static_cast<unsigned char>(value & 0xFF));
}

void AppendString(std::vector<unsigned char> &output, const unsigned char *data, size_t size)
{
    AppendUint32(output, size);
    output.insert(output.end(), data, data + size);
}

void AppendString(std::vector<unsigned char> &output, const std::string &value)
{
    AppendString(output, reinterpret_cast<const unsigned char *>(value.data()), value.size());
}

void AppendMpint(std::vector<unsigned char> &output, const unsigned char *data, size_t size)
{
    while (size > 1 && *data == 0)
    {
        ++data;
        --size;
    }
    bool prefixZero = size > 0 && (data[0] & 0x80) != 0;
    AppendUint32(output, size + (prefixZero ? 1 : 0));
    if (prefixZero)
        output.push_back(0);
    output.insert(output.end(), data, data + size);
}

std::string Base64(const std::vector<unsigned char> &data)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3)
    {
        unsigned value = static_cast<unsigned>(data[i]) << 16;
        bool second = i + 1 < data.size();
        bool third = i + 2 < data.size();
        if (second)
            value |= static_cast<unsigned>(data[i + 1]) << 8;
        if (third)
            value |= data[i + 2];
        output.push_back(alphabet[(value >> 18) & 63]);
        output.push_back(alphabet[(value >> 12) & 63]);
        output.push_back(second ? alphabet[(value >> 6) & 63] : '=');
        output.push_back(third ? alphabet[value & 63] : '=');
    }
    return output;
}

std::vector<std::string> WrapBase64(const std::vector<unsigned char> &data)
{
    std::string encoded = Base64(data);
    std::vector<std::string> lines;
    for (size_t position = 0; position < encoded.size(); position += 64)
        lines.push_back(encoded.substr(position, 64));
    return lines;
}

bool HmacSha256(const std::vector<unsigned char> &data, unsigned char output[32])
{
    AlgorithmHandle algorithm;
    if (!NtOk(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr,
                                          BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        return false;
    DWORD objectSize = 0;
    DWORD returned = 0;
    if (!NtOk(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
                                sizeof(objectSize), &returned, 0)) ||
        objectSize == 0 || objectSize > 64 * 1024)
        return false;
    std::vector<unsigned char> object(objectSize);
    HashHandle hash;
    if (!NtOk(BCryptCreateHash(algorithm.value, &hash.value, object.data(), objectSize, nullptr, 0, 0)) ||
        !NtOk(BCryptHashData(hash.value, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0)) ||
        !NtOk(BCryptFinishHash(hash.value, output, 32, 0)))
        return false;
    SecureZeroMemory(object.data(), object.size());
    return true;
}

bool GenerateTestPpk(std::string &text)
{
    AlgorithmHandle algorithm;
    KeyHandle key;
    if (!NtOk(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_RSA_ALGORITHM, nullptr, 0)) ||
        !NtOk(BCryptGenerateKeyPair(algorithm.value, &key.value, 2048, 0)) ||
        !NtOk(BCryptFinalizeKeyPair(key.value, 0)))
        return false;

    ULONG blobSize = 0;
    if (!NtOk(BCryptExportKey(key.value, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &blobSize, 0)) ||
        blobSize < sizeof(BCRYPT_RSAKEY_BLOB) || blobSize > 64 * 1024)
        return false;
    std::vector<unsigned char> blob(blobSize);
    if (!NtOk(BCryptExportKey(key.value, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, blob.data(), blobSize, &blobSize, 0)))
        return false;
    blob.resize(blobSize);

    const BCRYPT_RSAKEY_BLOB *header = reinterpret_cast<const BCRYPT_RSAKEY_BLOB *>(blob.data());
    if (header->Magic != BCRYPT_RSAFULLPRIVATE_MAGIC)
        return false;
    size_t required = sizeof(*header) + header->cbPublicExp + header->cbModulus + header->cbPrime1 +
                      header->cbPrime2 + header->cbPrime1 + header->cbPrime2 + header->cbPrime1 +
                      header->cbModulus;
    if (required != blob.size())
        return false;

    const unsigned char *cursor = blob.data() + sizeof(*header);
    const unsigned char *exponent = cursor;
    cursor += header->cbPublicExp;
    const unsigned char *modulus = cursor;
    cursor += header->cbModulus;
    const unsigned char *prime1 = cursor;
    cursor += header->cbPrime1;
    const unsigned char *prime2 = cursor;
    cursor += header->cbPrime2;
    cursor += header->cbPrime1;
    cursor += header->cbPrime2;
    const unsigned char *coefficient = cursor;
    cursor += header->cbPrime1;
    const unsigned char *privateExponent = cursor;

    const std::string algorithmName = "ssh-rsa";
    const std::string encryption = "none";
    const std::string comment = "TEST-ONLY ephemeral generated RSA key";
    std::vector<unsigned char> publicBlob;
    AppendString(publicBlob, algorithmName);
    AppendMpint(publicBlob, exponent, header->cbPublicExp);
    AppendMpint(publicBlob, modulus, header->cbModulus);
    std::vector<unsigned char> privateBlob;
    AppendMpint(privateBlob, privateExponent, header->cbModulus);
    AppendMpint(privateBlob, prime1, header->cbPrime1);
    AppendMpint(privateBlob, prime2, header->cbPrime2);
    AppendMpint(privateBlob, coefficient, header->cbPrime1);

    std::vector<unsigned char> macInput;
    AppendString(macInput, algorithmName);
    AppendString(macInput, encryption);
    AppendString(macInput, comment);
    AppendString(macInput, publicBlob.data(), publicBlob.size());
    AppendString(macInput, privateBlob.data(), privateBlob.size());
    unsigned char mac[32] = {};
    if (!HmacSha256(macInput, mac))
        return false;

    std::vector<std::string> publicLines = WrapBase64(publicBlob);
    std::vector<std::string> privateLines = WrapBase64(privateBlob);
    text = "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: " + comment + "\nPublic-Lines: " +
           std::to_string(publicLines.size()) + "\n";
    for (const std::string &line : publicLines)
        text += line + "\n";
    text += "Private-Lines: " + std::to_string(privateLines.size()) + "\n";
    for (const std::string &line : privateLines)
        text += line + "\n";
    static const char hex[] = "0123456789abcdef";
    text += "Private-MAC: ";
    for (unsigned char value : mac)
    {
        text.push_back(hex[value >> 4]);
        text.push_back(hex[value & 15]);
    }
    text.push_back('\n');

    SecureZeroMemory(mac, sizeof(mac));
    SecureZeroMemory(blob.data(), blob.size());
    SecureZeroMemory(privateBlob.data(), privateBlob.size());
    SecureZeroMemory(macInput.data(), macInput.size());
    return true;
}

bool WriteText(const std::string &path, const std::string &text)
{
    HANDLE file = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    bool ok = text.size() <= MAXDWORD &&
              WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) != FALSE &&
              written == text.size();
    CloseHandle(file);
    return ok;
}

bool ReplaceFirst(std::string &text, const std::string &before, const std::string &after)
{
    size_t position = text.find(before);
    if (position == std::string::npos)
        return false;
    text.replace(position, before.size(), after);
    return true;
}

std::string WithLineEndings(const std::string &text, const char *ending)
{
    std::string result;
    for (char value : text)
    {
        if (value == '\n')
            result.append(ending);
        else
            result.push_back(value);
    }
    return result;
}

bool Contains(const std::string &text, const char *needle)
{
    return text.find(needle) != std::string::npos;
}
} // namespace

int main()
{
    TemporaryFile temporary;
    char directory[MAX_PATH] = {};
    char fileName[MAX_PATH] = {};
    if (!GetTempPathA(MAX_PATH, directory) || !GetTempFileNameA(directory, "tpk", 0, fileName))
    {
        fprintf(stderr, "Unable to allocate the PPK diagnostic test file.\n");
        return 1;
    }
    temporary.path = fileName;

    std::string valid;
    if (!GenerateTestPpk(valid))
    {
        fprintf(stderr, "Unable to generate the TEST-ONLY RSA PPK.\n");
        return 2;
    }

    int failures = 0;
    auto expectInspect = [&](const std::string &text, tcputty::PpkLoadResult expected, unsigned version,
                             const char *algorithm, const char *encryption, const char *messagePart) {
        if (!WriteText(temporary.path, text))
        {
            ++failures;
            return;
        }
        tcputty::PpkKeyInfo info;
        std::string error;
        tcputty::PpkLoadResult actual = tcputty::InspectPpkFile(temporary.path.c_str(), info, error);
        if (actual != expected || info.version != version || info.algorithm != algorithm || info.encryption != encryption ||
            (messagePart && !Contains(error, messagePart)))
        {
            fprintf(stderr, "Inspect mismatch: result=%d version=%u algorithm=%s encryption=%s error=%s\n",
                    static_cast<int>(actual), info.version, info.algorithm.c_str(), info.encryption.c_str(),
                    error.c_str());
            ++failures;
        }
    };
    auto expectLoad = [&](const std::string &text, tcputty::PpkLoadResult expected, const char *messagePart) {
        if (!WriteText(temporary.path, text))
        {
            ++failures;
            return;
        }
        tcputty::MemoryKey key;
        std::string error;
        tcputty::PpkLoadResult actual = tcputty::LoadPpkV3Rsa(temporary.path.c_str(), key, error);
        if (actual != expected || (messagePart && !Contains(error, messagePart)))
        {
            fprintf(stderr, "Load mismatch: result=%d error=%s\n", static_cast<int>(actual), error.c_str());
            ++failures;
        }
        if (expected == tcputty::PpkLoadResult::Success &&
            (key.publicKeyFile.find("ssh-rsa ") != 0 || key.privateKeyPem.Empty()))
        {
            fprintf(stderr, "A valid TEST-ONLY PPK did not produce an in-memory RSA key.\n");
            ++failures;
        }
    };

    expectInspect(valid, tcputty::PpkLoadResult::Success, 3, "ssh-rsa", "none", nullptr);
    expectLoad(valid, tcputty::PpkLoadResult::Success, nullptr);
    expectLoad(WithLineEndings(valid, "\r\n"), tcputty::PpkLoadResult::Success, nullptr);
    expectLoad(WithLineEndings(valid, "\r"), tcputty::PpkLoadResult::Success, nullptr);

    std::string version2 = valid;
    ReplaceFirst(version2, "PuTTY-User-Key-File-3:", "PuTTY-User-Key-File-2:");
    expectInspect(version2, tcputty::PpkLoadResult::Unsupported, 2, "ssh-rsa", "none", "version 2");

    std::string encrypted = valid;
    ReplaceFirst(encrypted, "Encryption: none", "Encryption: aes256-cbc");
    expectInspect(encrypted, tcputty::PpkLoadResult::Unsupported, 3, "ssh-rsa", "aes256-cbc", "encrypted");

    std::string ed25519 = valid;
    ReplaceFirst(ed25519, "PuTTY-User-Key-File-3: ssh-rsa", "PuTTY-User-Key-File-3: ssh-ed25519");
    expectInspect(ed25519, tcputty::PpkLoadResult::Unsupported, 3, "ssh-ed25519", "none", "ssh-ed25519");

    expectInspect("not a private key\n", tcputty::PpkLoadResult::NotPpk, 0, "", "", "does not contain");
    expectLoad("PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\n", tcputty::PpkLoadResult::Invalid,
               "truncated");

    std::string badMac = valid;
    size_t macPosition = badMac.rfind('\n', badMac.size() - 2);
    if (macPosition == std::string::npos || macPosition == 0)
        ++failures;
    else
    {
        size_t digit = badMac.size() - 2;
        badMac[digit] = badMac[digit] == '0' ? '1' : '0';
        expectLoad(badMac, tcputty::PpkLoadResult::Invalid, "integrity");
    }

    std::string badBase64 = valid;
    size_t publicHeader = badBase64.find("Public-Lines: ");
    size_t publicData = publicHeader == std::string::npos ? std::string::npos : badBase64.find('\n', publicHeader);
    if (publicData == std::string::npos || ++publicData >= badBase64.size())
        ++failures;
    else
    {
        badBase64[publicData] = '!';
        expectLoad(badBase64, tcputty::PpkLoadResult::Invalid, "base64");
    }

    expectLoad(valid + "Unexpected: field\n", tcputty::PpkLoadResult::Invalid, "trailing");
    std::string embeddedNul = valid;
    embeddedNul.insert(embeddedNul.begin() + static_cast<std::string::difference_type>(embeddedNul.size() / 2), '\0');
    expectLoad(embeddedNul, tcputty::PpkLoadResult::Invalid, "text structure");

    expectInspect("", tcputty::PpkLoadResult::IoError, 0, "", "", "empty");
    expectInspect(std::string(64 * 1024 + 1, 'A'), tcputty::PpkLoadResult::IoError, 0, "", "", "64 KiB");

    DeleteFileA(temporary.path.c_str());
    tcputty::PpkKeyInfo missingInfo;
    std::string missingError;
    if (tcputty::InspectPpkFile(temporary.path.c_str(), missingInfo, missingError) != tcputty::PpkLoadResult::IoError ||
        !Contains(missingError, "does not exist"))
    {
        fprintf(stderr, "Missing-file diagnostics failed: %s\n", missingError.c_str());
        ++failures;
    }

    SecureZeroMemory(valid.data(), valid.size());
    if (failures != 0)
    {
        fprintf(stderr, "PPK diagnostics failed: %d case(s).\n", failures);
        return 3;
    }
    printf("PPK diagnostics passed with a runtime-generated TEST-ONLY RSA key.\n");
    return 0;
}
