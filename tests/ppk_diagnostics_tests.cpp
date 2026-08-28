#include "../ppk_v3_rsa.h"
#include "../third_party/argon2/include/argon2.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace
{
const char kEncryptedTestPassphrase[] = "TEST-ONLY correct horse battery staple";

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

bool HmacSha256(const std::vector<unsigned char> &data, const unsigned char *key, size_t keyLength,
                unsigned char output[32])
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
    if (keyLength > ULONG_MAX ||
        !NtOk(BCryptCreateHash(algorithm.value, &hash.value, object.data(), objectSize, const_cast<PUCHAR>(key),
                               static_cast<ULONG>(keyLength), 0)) ||
        !NtOk(BCryptHashData(hash.value, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0)) ||
        !NtOk(BCryptFinishHash(hash.value, output, 32, 0)))
        return false;
    SecureZeroMemory(object.data(), object.size());
    return true;
}

bool EncryptAes256Cbc(const std::vector<unsigned char> &plaintext, const unsigned char keyBytes[32],
                      const unsigned char initialVector[16], std::vector<unsigned char> &ciphertext)
{
    AlgorithmHandle algorithm;
    if (!NtOk(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return false;
    const wchar_t mode[] = BCRYPT_CHAIN_MODE_CBC;
    if (!NtOk(BCryptSetProperty(algorithm.value, BCRYPT_CHAINING_MODE,
                                reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(mode)), sizeof(mode), 0)))
        return false;
    DWORD objectSize = 0;
    DWORD returned = 0;
    if (!NtOk(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
                                sizeof(objectSize), &returned, 0)) ||
        objectSize == 0 || objectSize > 64 * 1024)
        return false;
    std::vector<unsigned char> object(objectSize);
    KeyHandle key;
    if (!NtOk(BCryptGenerateSymmetricKey(algorithm.value, &key.value, object.data(), objectSize,
                                         const_cast<PUCHAR>(keyBytes), 32, 0)))
        return false;
    unsigned char iv[16] = {};
    memcpy(iv, initialVector, sizeof(iv));
    ciphertext.resize(plaintext.size());
    ULONG outputLength = 0;
    bool ok = plaintext.size() <= ULONG_MAX &&
              NtOk(BCryptEncrypt(key.value, const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
                                 nullptr, iv, sizeof(iv), ciphertext.data(), static_cast<ULONG>(ciphertext.size()),
                                 &outputLength, 0)) &&
              outputLength == ciphertext.size();
    SecureZeroMemory(iv, sizeof(iv));
    SecureZeroMemory(object.data(), object.size());
    if (!ok)
    {
        SecureZeroMemory(ciphertext.data(), ciphertext.size());
        ciphertext.clear();
    }
    return ok;
}

bool GenerateTestPpk(std::string &text, const char *passphrase = nullptr, argon2_type type = Argon2_id)
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
    const bool encrypted = passphrase != nullptr;
    const std::string encryption = encrypted ? "aes256-cbc" : "none";
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

    const uint32_t memoryKiB = 32;
    const uint32_t passes = 2;
    const uint32_t parallelism = 2;
    const unsigned char salt[] = {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
                                  0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F};
    std::vector<unsigned char> derived;
    std::vector<unsigned char> storedPrivate;
    const unsigned char *macKey = nullptr;
    size_t macKeyLength = 0;
    if (encrypted)
    {
        while ((privateBlob.size() & 15) != 0)
            privateBlob.push_back(static_cast<unsigned char>(0xA0 + (privateBlob.size() & 15)));
        derived.resize(80);
        if (argon2_hash(passes, memoryKiB, parallelism, passphrase, strlen(passphrase), salt, sizeof(salt),
                        derived.data(), derived.size(), nullptr, 0, type, ARGON2_VERSION_13) != ARGON2_OK ||
            !EncryptAes256Cbc(privateBlob, derived.data(), derived.data() + 32, storedPrivate))
            return false;
        macKey = derived.data() + 48;
        macKeyLength = 32;
    }
    else
    {
        storedPrivate = privateBlob;
    }

    std::vector<unsigned char> macInput;
    AppendString(macInput, algorithmName);
    AppendString(macInput, encryption);
    AppendString(macInput, comment);
    AppendString(macInput, publicBlob.data(), publicBlob.size());
    AppendString(macInput, privateBlob.data(), privateBlob.size());
    unsigned char mac[32] = {};
    if (!HmacSha256(macInput, macKey, macKeyLength, mac))
        return false;

    std::vector<std::string> publicLines = WrapBase64(publicBlob);
    std::vector<std::string> privateLines = WrapBase64(storedPrivate);
    text = "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: " + encryption + "\nComment: " + comment +
           "\nPublic-Lines: " +
           std::to_string(publicLines.size()) + "\n";
    for (const std::string &line : publicLines)
        text += line + "\n";
    if (encrypted)
    {
        const char *derivationName = type == Argon2_d ? "Argon2d" : (type == Argon2_i ? "Argon2i" : "Argon2id");
        text += "Key-Derivation: " + std::string(derivationName) + "\nArgon2-Memory: " +
                std::to_string(memoryKiB) + "\nArgon2-Passes: " + std::to_string(passes) +
                "\nArgon2-Parallelism: " + std::to_string(parallelism) + "\nArgon2-Salt: ";
        static const char saltHex[] = "0123456789abcdef";
        for (unsigned char value : salt)
        {
            text.push_back(saltHex[value >> 4]);
            text.push_back(saltHex[value & 15]);
        }
        text.push_back('\n');
    }
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
    SecureZeroMemory(storedPrivate.data(), storedPrivate.size());
    SecureZeroMemory(derived.data(), derived.size());
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

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--write-encrypted-interop") == 0)
    {
        std::string interopKey;
        if (!GenerateTestPpk(interopKey, kEncryptedTestPassphrase, Argon2_id) || !WriteText(argv[2], interopKey))
        {
            SecureZeroMemory(interopKey.data(), interopKey.size());
            fprintf(stderr, "Unable to write the TEST-ONLY encrypted PPK.\n");
            return 4;
        }
        SecureZeroMemory(interopKey.data(), interopKey.size());
        printf("Wrote an encrypted TEST-ONLY PPK for manual PuTTY interoperability testing.\n");
        return 0;
    }
    if (argc != 1)
    {
        fprintf(stderr, "Usage: ppk-diagnostics [--write-encrypted-interop <path>]\n");
        return 4;
    }

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

    std::string encryptedId;
    std::string encryptedI;
    std::string encryptedD;
    std::string encryptedEmpty;
    if (!GenerateTestPpk(encryptedId, kEncryptedTestPassphrase, Argon2_id) ||
        !GenerateTestPpk(encryptedI, kEncryptedTestPassphrase, Argon2_i) ||
        !GenerateTestPpk(encryptedD, kEncryptedTestPassphrase, Argon2_d) ||
        !GenerateTestPpk(encryptedEmpty, "", Argon2_id))
    {
        fprintf(stderr, "Unable to generate encrypted TEST-ONLY RSA PPK variants.\n");
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
    auto expectLoadWithPassphrase = [&](const std::string &text, const char *passphrase,
                                        tcputty::PpkLoadResult expected, const char *messagePart) {
        if (!WriteText(temporary.path, text))
        {
            ++failures;
            return;
        }
        tcputty::MemoryKey key;
        std::string error;
        tcputty::PpkLoadResult actual = tcputty::LoadPpkV3Rsa(
            temporary.path.c_str(), reinterpret_cast<const unsigned char *>(passphrase), strlen(passphrase), key, error);
        if (actual != expected || (messagePart && !Contains(error, messagePart)))
        {
            fprintf(stderr, "Encrypted load mismatch: result=%d error=%s\n", static_cast<int>(actual), error.c_str());
            ++failures;
        }
        if (expected == tcputty::PpkLoadResult::Success &&
            (key.publicKeyFile.find("ssh-rsa ") != 0 || key.privateKeyPem.Empty()))
        {
            fprintf(stderr, "A valid encrypted TEST-ONLY PPK did not produce an in-memory RSA key.\n");
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

    expectInspect(encryptedId, tcputty::PpkLoadResult::Success, 3, "ssh-rsa", "aes256-cbc", nullptr);
    expectLoad(encryptedId, tcputty::PpkLoadResult::PassphraseRequired, "requires");
    expectLoadWithPassphrase(encryptedId, kEncryptedTestPassphrase, tcputty::PpkLoadResult::Success, nullptr);
    expectLoadWithPassphrase(encryptedI, kEncryptedTestPassphrase, tcputty::PpkLoadResult::Success, nullptr);
    expectLoadWithPassphrase(encryptedD, kEncryptedTestPassphrase, tcputty::PpkLoadResult::Success, nullptr);
    expectLoadWithPassphrase(encryptedEmpty, "", tcputty::PpkLoadResult::Success, nullptr);
    expectLoadWithPassphrase(encryptedId, "TEST-ONLY wrong passphrase", tcputty::PpkLoadResult::BadPassphrase,
                             "incorrect");

    std::string unsupportedEncryption = valid;
    ReplaceFirst(unsupportedEncryption, "Encryption: none", "Encryption: chacha20-poly1305");
    expectInspect(unsupportedEncryption, tcputty::PpkLoadResult::Unsupported, 3, "ssh-rsa",
                  "chacha20-poly1305", "unsupported encryption");

    std::string unsupportedKdf = encryptedId;
    ReplaceFirst(unsupportedKdf, "Key-Derivation: Argon2id", "Key-Derivation: scrypt");
    expectInspect(unsupportedKdf, tcputty::PpkLoadResult::Unsupported, 3, "ssh-rsa", "aes256-cbc",
                  "unsupported key-derivation");

    std::string excessiveMemory = encryptedId;
    ReplaceFirst(excessiveMemory, "Argon2-Memory: 32", "Argon2-Memory: 524289");
    expectInspect(excessiveMemory, tcputty::PpkLoadResult::Invalid, 3, "ssh-rsa", "aes256-cbc", "safety limits");

    std::string insufficientMemory = encryptedId;
    ReplaceFirst(insufficientMemory, "Argon2-Memory: 32", "Argon2-Memory: 8");
    expectInspect(insufficientMemory, tcputty::PpkLoadResult::Invalid, 3, "ssh-rsa", "aes256-cbc", "safety limits");

    std::string excessiveWork = encryptedId;
    ReplaceFirst(excessiveWork, "Argon2-Memory: 32", "Argon2-Memory: 262144");
    ReplaceFirst(excessiveWork, "Argon2-Passes: 2", "Argon2-Passes: 64");
    expectInspect(excessiveWork, tcputty::PpkLoadResult::Invalid, 3, "ssh-rsa", "aes256-cbc", "aggregate");

    std::string excessivePasses = encryptedId;
    ReplaceFirst(excessivePasses, "Argon2-Passes: 2", "Argon2-Passes: 1025");
    expectInspect(excessivePasses, tcputty::PpkLoadResult::Invalid, 3, "ssh-rsa", "aes256-cbc", "safety limits");

    std::string excessiveParallelism = encryptedId;
    ReplaceFirst(excessiveParallelism, "Argon2-Parallelism: 2", "Argon2-Parallelism: 17");
    expectInspect(excessiveParallelism, tcputty::PpkLoadResult::Invalid, 3, "ssh-rsa", "aes256-cbc",
                  "safety limits");

    std::string invalidSalt = encryptedId;
    size_t saltHeader = invalidSalt.find("Argon2-Salt: ");
    if (saltHeader == std::string::npos)
        ++failures;
    else
    {
        size_t saltEnd = invalidSalt.find('\n', saltHeader);
        invalidSalt.replace(saltHeader, saltEnd - saltHeader, "Argon2-Salt: 00");
        expectInspect(invalidSalt, tcputty::PpkLoadResult::Invalid, 3, "ssh-rsa", "aes256-cbc", "8 to 64");
    }

    std::string shortCiphertext = encryptedId;
    size_t macHeader = shortCiphertext.find("Private-MAC: ");
    size_t ciphertextEnd = macHeader == std::string::npos ? std::string::npos : shortCiphertext.rfind('\n', macHeader - 1);
    if (ciphertextEnd == std::string::npos || ciphertextEnd < 4)
        ++failures;
    else
    {
        shortCiphertext.erase(ciphertextEnd - 4, 4);
        expectLoadWithPassphrase(shortCiphertext, kEncryptedTestPassphrase, tcputty::PpkLoadResult::Invalid,
                                 "whole number");
    }

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

    std::string badEncryptedMac = encryptedId;
    if (badEncryptedMac.size() < 2)
        ++failures;
    else
    {
        size_t digit = badEncryptedMac.size() - 2;
        badEncryptedMac[digit] = badEncryptedMac[digit] == '0' ? '1' : '0';
        expectLoadWithPassphrase(badEncryptedMac, kEncryptedTestPassphrase, tcputty::PpkLoadResult::BadPassphrase,
                                 "damaged");
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

    static const unsigned char aesKey[32] = {
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
        0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4};
    static const unsigned char aesIv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    static const unsigned char aesPlaintext[16] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
                                                    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A};
    static const unsigned char aesCiphertext[16] = {0xF5, 0x8C, 0x4C, 0x04, 0xD6, 0xE5, 0xF1, 0xBA,
                                                     0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB, 0xD6};
    std::vector<unsigned char> aesActual;
    if (!EncryptAes256Cbc(std::vector<unsigned char>(aesPlaintext, aesPlaintext + sizeof(aesPlaintext)), aesKey,
                          aesIv, aesActual) ||
        aesActual.size() != sizeof(aesCiphertext) || memcmp(aesActual.data(), aesCiphertext, sizeof(aesCiphertext)) != 0)
    {
        fprintf(stderr, "The NIST AES-256-CBC reference vector did not match.\n");
        ++failures;
    }
    SecureZeroMemory(aesActual.data(), aesActual.size());

    static const unsigned char expectedArgon2i[24] = {0x45, 0xD7, 0xAC, 0x72, 0xE7, 0x6F, 0x24, 0x2B,
                                                       0x20, 0xB7, 0x7B, 0x9B, 0xF9, 0xBF, 0x9D, 0x59,
                                                       0x15, 0x89, 0x4E, 0x66, 0x9A, 0x24, 0xE6, 0xC6};
    unsigned char actualArgon2i[sizeof(expectedArgon2i)] = {};
    if (argon2i_hash_raw(2, 65536, 4, "password", 8, "somesalt", 8, actualArgon2i, sizeof(actualArgon2i)) !=
            ARGON2_OK ||
        memcmp(actualArgon2i, expectedArgon2i, sizeof(expectedArgon2i)) != 0)
    {
        fprintf(stderr, "The official Argon2i reference vector did not match: ");
        for (unsigned char value : actualArgon2i)
            fprintf(stderr, "%02x", value);
        fprintf(stderr, "\n");
        ++failures;
    }
    SecureZeroMemory(actualArgon2i, sizeof(actualArgon2i));

    SecureZeroMemory(valid.data(), valid.size());
    SecureZeroMemory(encryptedId.data(), encryptedId.size());
    SecureZeroMemory(encryptedI.data(), encryptedI.size());
    SecureZeroMemory(encryptedD.data(), encryptedD.size());
    SecureZeroMemory(encryptedEmpty.data(), encryptedEmpty.size());
    if (failures != 0)
    {
        fprintf(stderr, "PPK diagnostics failed: %d case(s).\n", failures);
        return 3;
    }
    printf("PPK diagnostics passed with runtime-generated TEST-ONLY unencrypted and encrypted RSA keys.\n");
    return 0;
}
