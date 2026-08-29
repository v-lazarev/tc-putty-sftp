#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace tcputty
{
class SecureBuffer
{
  public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t size);
    ~SecureBuffer();
    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;
    SecureBuffer(SecureBuffer &&other) noexcept;
    SecureBuffer &operator=(SecureBuffer &&other) noexcept;

    unsigned char *Data();
    const unsigned char *Data() const;
    size_t Size() const;
    bool Empty() const;
    void Resize(size_t size);
    void Reserve(size_t size);
    void PushBack(unsigned char value);
    void Append(const void *data, size_t size);
    void Clear();

  private:
    std::vector<unsigned char> bytes_;
};

struct MemoryKey
{
    enum class Algorithm
    {
        Rsa,
        Ed25519
    };

    Algorithm algorithm = Algorithm::Rsa;
    std::string publicKeyFile;
    SecureBuffer publicKeyBlob;
    SecureBuffer publicKeyPoint;
    SecureBuffer privateKeyPem;
    SecureBuffer privateKeySeed;
};

struct PpkKeyInfo
{
    unsigned version = 0;
    std::string algorithm;
    std::string encryption;
};

enum class PpkLoadResult
{
    Success,
    PassphraseRequired,
    BadPassphrase,
    NotPpk,
    Unsupported,
    Invalid,
    IoError
};

bool HasPpkExtension(const char *path);

// Reads and classifies only bounded PPK metadata. The comment and all key
// material are deliberately omitted from PpkKeyInfo and error messages.
// Success means the header is supported by LoadPpkV3Key, not that the complete
// private key has already passed its integrity and key-pair validation.
PpkLoadResult InspectPpkFile(const char *path, PpkKeyInfo &info, std::string &errorMessage);

// Supports PuTTY-User-Key-File-3 ssh-rsa and ssh-ed25519 keys using
// Encryption: none or aes256-cbc. A null passphrase means that no passphrase
// was supplied; a non-null pointer with length zero represents an explicitly
// supplied empty passphrase. The caller retains ownership of the passphrase
// and must clear it; all private working buffers owned by this loader are
// cleared in memory.
PpkLoadResult LoadPpkV3Key(const char *path, const unsigned char *passphrase, size_t passphraseLength, MemoryKey &key,
                           std::string &errorMessage);

// Compatibility overload for unencrypted keys. Encrypted keys return
// PassphraseRequired.
PpkLoadResult LoadPpkV3Key(const char *path, MemoryKey &key, std::string &errorMessage);
} // namespace tcputty
