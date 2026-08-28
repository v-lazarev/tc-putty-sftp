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
    std::string publicKeyFile;
    SecureBuffer privateKeyPem;
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
    NotPpk,
    Unsupported,
    Invalid,
    IoError
};

bool HasPpkExtension(const char *path);

// Reads and classifies only bounded PPK metadata. The comment and all key
// material are deliberately omitted from PpkKeyInfo and error messages.
// Success means the header is supported by LoadPpkV3Rsa, not that the complete
// private key has already passed its integrity and CNG validation.
PpkLoadResult InspectPpkFile(const char *path, PpkKeyInfo &info, std::string &errorMessage);

// Supports only the deliberately narrow MVP format:
// PuTTY-User-Key-File-3, ssh-rsa, Encryption: none.
PpkLoadResult LoadPpkV3Rsa(const char *path, MemoryKey &key, std::string &errorMessage);
} // namespace tcputty
