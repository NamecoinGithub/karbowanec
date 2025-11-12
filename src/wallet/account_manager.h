#pragma once
// Minimal prototype Account Manager for on-chain encrypted account records.
// Uses libsodium for KDF (Argon2id via crypto_pwhash) and AEAD (XChaCha20-Poly1305).
//
// This is a prototype intended to be integrated into the Karbowanec wallet subsystem.
// It is intentionally compact and omits integration with the rest of the project.
// TODO: integrate with the project's logging, wallet seed storage, and transaction builder.
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace karbo {
namespace wallet {

struct KDFParams {
    uint64_t opslimit;    // libsodium opslimit (time cost)
    size_t memlimit;      // libsodium memlimit (bytes)
    std::vector<uint8_t> salt; // 16..32 bytes
};

struct AccountRecord {
    std::string username;
    std::vector<uint8_t> username_hash; // 32 bytes
    std::vector<uint8_t> owner_pub_spend; // serialized pubkey bytes (placeholder)
    std::vector<uint8_t> owner_pub_view;
    KDFParams kdf;
    std::vector<uint8_t> encrypted_payload; // AEAD ciphertext
    uint32_t version = 1;
    uint64_t timestamp = 0;
};

// A small helper class that provides create/login/change-password
class AccountManager {
public:
    // Generate a new wallet seed (32 bytes), create an AccountRecord and return serialized blob to embed in tx.extra.
    // password and pin are combined internally for KDF.
    static std::optional<std::vector<uint8_t>> create_account_blob(
        const std::string& username,
        const std::string& password,
        const std::string& pin,
        const KDFParams& params,
        std::vector<uint8_t>& out_seed // returns clear seed on success (32 bytes)
    );

    // Given an AccountRecord blob (deserialized), attempt to decrypt and return the clear seed (32 bytes) on success.
    static std::optional<std::vector<uint8_t>> decrypt_account_seed(
        const AccountRecord& record,
        const std::string& password,
        const std::string& pin
    );

    // Compose a canonical serialized AccountRecord blob:
    // marker + version + username_hash + owner_pub_spend_len + owner_pub_spend + owner_pub_view_len + owner_pub_view +
    // kdf_salt_len + kdf_salt + kdf_opslimit + kdf_memlimit + encrypted_payload_len + encrypted_payload
    // The serialized blob is suitable for embedding into tx.extra and for scanning by clients.
    static std::vector<uint8_t> serialize_account_record(const AccountRecord& rec);

    // Parse the serialized blob into AccountRecord (returns nullopt on parse error).
    static std::optional<AccountRecord> parse_account_record_blob(const std::vector<uint8_t>& blob);

private:
    // compute username hash (SHA-256)
    static std::vector<uint8_t> compute_username_hash(const std::string& username);

    // derive key via Argon2id (libsodium crypto_pwhash) -> returns 32 byte key
    static bool derive_key_argon2id(const std::string& password,
                                    const std::string& pin,
                                    const std::string& username,
                                    const KDFParams& params,
                                    std::vector<uint8_t>& out_key);

    // AEAD using XChaCha20-Poly1305 (libsodium)
    static bool aead_encrypt_xchacha20poly1305(const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& plaintext,
                                               const std::vector<uint8_t>& aad,
                                               std::vector<uint8_t>& out_ciphertext);

    static bool aead_decrypt_xchacha20poly1305(const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& ciphertext,
                                               const std::vector<uint8_t>& aad,
                                               std::vector<uint8_t>& out_plaintext);

    // helper: pack uint32/uint64 little-endian
    static void append_u32(std::vector<uint8_t>& v, uint32_t x);
    static void append_u64(std::vector<uint8_t>& v, uint64_t x);
    static bool read_u32(const std::vector<uint8_t>& v, size_t& off, uint32_t& out);
    static bool read_u64(const std::vector<uint8_t>& v, size_t& off, uint64_t& out);
};

} // namespace wallet
} // namespace karbo
