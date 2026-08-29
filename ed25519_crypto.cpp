#include "ed25519_crypto.h"
#include "third_party/monocypher/monocypher-ed25519.h"

#include <windows.h>

#include <cstring>

namespace
{
bool ConstantTimeEqual(const unsigned char *left, const unsigned char *right, size_t size)
{
    unsigned char difference = 0;
    for (size_t i = 0; i < size; ++i)
        difference |= static_cast<unsigned char>(left[i] ^ right[i]);
    return difference == 0;
}
} // namespace

namespace tcputty
{
bool Ed25519DerivePublic(const unsigned char seed[32], unsigned char publicKey[32])
{
    if (!seed || !publicKey)
        return false;
    unsigned char seedCopy[32] = {};
    unsigned char secretKey[64] = {};
    memcpy(seedCopy, seed, sizeof(seedCopy));
    crypto_ed25519_key_pair(secretKey, publicKey, seedCopy);
    SecureZeroMemory(seedCopy, sizeof(seedCopy));
    SecureZeroMemory(secretKey, sizeof(secretKey));
    return true;
}

bool Ed25519Sign(const unsigned char seed[32], const unsigned char expectedPublicKey[32],
                 const unsigned char *message, size_t messageSize, unsigned char signature[64])
{
    if (!seed || !expectedPublicKey || (!message && messageSize != 0) || !signature)
        return false;
    unsigned char seedCopy[32] = {};
    unsigned char publicKey[32] = {};
    unsigned char secretKey[64] = {};
    memcpy(seedCopy, seed, sizeof(seedCopy));
    crypto_ed25519_key_pair(secretKey, publicKey, seedCopy);
    bool matches = ConstantTimeEqual(publicKey, expectedPublicKey, sizeof(publicKey));
    if (matches)
        crypto_ed25519_sign(signature, secretKey, message, messageSize);
    else
        SecureZeroMemory(signature, 64);
    SecureZeroMemory(seedCopy, sizeof(seedCopy));
    SecureZeroMemory(publicKey, sizeof(publicKey));
    SecureZeroMemory(secretKey, sizeof(secretKey));
    return matches;
}

bool Ed25519Verify(const unsigned char publicKey[32], const unsigned char *message, size_t messageSize,
                   const unsigned char signature[64])
{
    return publicKey && signature && (message || messageSize == 0) &&
           crypto_ed25519_check(signature, publicKey, message, messageSize) == 0;
}
} // namespace tcputty
