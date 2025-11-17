#pragma once

#include <vector>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cryptoTools/Common/Defines.h>

using namespace oc;

/**
 * @class Encryption
 * @brief Encryption utility class for encrypting values using keys
 */
class Encryption
{
public:
    /**
     * @brief Generate a random encryption key (32 bytes for AES-256)
     * @return A 32-byte encryption key
     */
    static std::vector<unsigned char> generateEncryptionKey()
    {
        std::vector<unsigned char> key(32);
        if (RAND_bytes(key.data(), key.size()) != 1) {
            throw std::runtime_error("Failed to generate random encryption key");
        }
        return key;
    }

    /**
     * @brief Derive an AES key from a block (key)
     * @param blockKey The block key to derive from
     * @return A 32-byte AES key
     */
    static std::vector<unsigned char> deriveKeyFromBlock(const block& blockKey)
    {
        std::vector<unsigned char> key(32);
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;
        
        // Use EVP for SHA-1 (part 1)
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha1(), nullptr);
        EVP_DigestUpdate(mdctx, blockKey.data(), 16);
        EVP_DigestFinal_ex(mdctx, hash, &hash_len);
        
        std::memcpy(key.data(), hash, 16);
        
        // Generate second part
        EVP_DigestInit_ex(mdctx, EVP_sha1(), nullptr);
        EVP_DigestUpdate(mdctx, blockKey.data(), 16);
        EVP_DigestUpdate(mdctx, (const unsigned char*)"_extension", 10);
        EVP_DigestFinal_ex(mdctx, hash, &hash_len);
        
        std::memcpy(key.data() + 16, hash, 16);
        EVP_MD_CTX_free(mdctx);
        
        return key;
    }

    /**
     * @brief Encrypt a value using AES-256-CBC with master key
     * @param plaintext The plaintext to encrypt
     * @param masterKey The master encryption key (32 bytes)
     * @param derivedKey Optional per-key derived key for additional security
     * @return Encrypted ciphertext with IV prepended (16 bytes IV + ciphertext)
     */
    static std::vector<unsigned char> encryptValue(
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& masterKey,
        const std::vector<unsigned char>& derivedKey = {})
    {
        if (masterKey.size() != 32) {
            throw std::runtime_error("Master key must be 32 bytes for AES-256");
        }

        // Generate random IV
        unsigned char iv[16];
        if (RAND_bytes(iv, 16) != 1) {
            throw std::runtime_error("Failed to generate random IV");
        }

        // Combine keys if derivedKey is provided
        std::vector<unsigned char> effectiveKey = masterKey;
        if (!derivedKey.empty()) {
            for (size_t i = 0; i < 32; ++i) {
                effectiveKey[i] ^= derivedKey[i % derivedKey.size()];
            }
        }

        // Create cipher context using EVP
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        // Initialize encryption
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, effectiveKey.data(), iv)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }

        // Allocate output buffer (IV + ciphertext)
        std::vector<unsigned char> ciphertext(16 + plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        std::memcpy(ciphertext.data(), iv, 16);

        int len = 0;
        int ciphertext_len = 0;

        // Encrypt data
        if (1 != EVP_EncryptUpdate(ctx, ciphertext.data() + 16, &len, plaintext.data(), plaintext.size())) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed");
        }
        ciphertext_len = len;

        // Finalize
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + 16 + len, &len)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption finalization failed");
        }
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        // Resize to actual size
        ciphertext.resize(16 + ciphertext_len);
        return ciphertext;
    }

    /**
     * @brief Decrypt a value using AES-256-CBC with master key
     * @param ciphertext The ciphertext with IV prepended (16 bytes IV + encrypted data)
     * @param masterKey The master decryption key (32 bytes)
     * @param derivedKey Optional per-key derived key (must match encryption)
     * @return Decrypted plaintext
     */
    static std::vector<unsigned char> decryptValue(
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& masterKey,
        const std::vector<unsigned char>& derivedKey = {})
    {
        if (ciphertext.size() < 16) {
            throw std::runtime_error("Ciphertext too short");
        }
        if (masterKey.size() != 32) {
            throw std::runtime_error("Master key must be 32 bytes for AES-256");
        }

        // Extract IV
        unsigned char iv[16];
        std::memcpy(iv, ciphertext.data(), 16);

        // Combine keys if derivedKey is provided
        std::vector<unsigned char> effectiveKey = masterKey;
        if (!derivedKey.empty()) {
            for (size_t i = 0; i < 32; ++i) {
                effectiveKey[i] ^= derivedKey[i % derivedKey.size()];
            }
        }

        // Create cipher context using EVP
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        // Initialize decryption
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, effectiveKey.data(), iv)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }

        // Allocate output buffer
        std::vector<unsigned char> plaintext(ciphertext.size());
        int len = 0;
        int plaintext_len = 0;

        // Decrypt data
        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data() + 16, ciphertext.size() - 16)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed");
        }
        plaintext_len = len;

        // Finalize
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption finalization failed");
        }
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        // Resize to actual size
        plaintext.resize(plaintext_len);
        return plaintext;
    }

    /**
     * @brief Encrypt a block value and return as bytes
     * @param value The block value to encrypt
     * @param masterKey The master encryption key
     * @param key The key used to derive per-key encryption material
     * @return Encrypted block as bytes
     */
    static std::vector<unsigned char> encryptBlock(
        const block& value,
        const std::vector<unsigned char>& masterKey,
        const block& key)
    {
        std::vector<unsigned char> plaintext(16);
        std::memcpy(plaintext.data(), value.data(), 16);

        auto derivedKey = deriveKeyFromBlock(key);
        return encryptValue(plaintext, masterKey, derivedKey);
    }

    /**
     * @brief Decrypt a block value from encrypted bytes
     * @param ciphertext The encrypted block bytes
     * @param masterKey The master decryption key
     * @param key The key used to derive per-key decryption material
     * @return Decrypted block
     */
    static block decryptBlock(
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& masterKey,
        const block& key)
    {
        auto derivedKey = deriveKeyFromBlock(key);
        auto plaintext = decryptValue(ciphertext, masterKey, derivedKey);

        block result;
        if (plaintext.size() >= 16) {
            std::memcpy(result.data(), plaintext.data(), 16);
        }
        return result;
    }
};
