#pragma once

#include <cstddef>

namespace tcputty
{
bool Ed25519DerivePublic(const unsigned char seed[32], unsigned char publicKey[32]);
bool Ed25519Sign(const unsigned char seed[32], const unsigned char expectedPublicKey[32],
                 const unsigned char *message, size_t messageSize, unsigned char signature[64]);
bool Ed25519Verify(const unsigned char publicKey[32], const unsigned char *message, size_t messageSize,
                   const unsigned char signature[64]);
} // namespace tcputty
