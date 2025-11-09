// openssl_integration/toruscsidh_kem.c
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include "toruscsidh.h"
#include "toruscsidh_kem.h"

/* Constants for hybrid KEM */
#define HYBRID_SECRET_SIZE 64  // Combined secret size (32 + 32)
#define P256_SECRET_SIZE 32    // P-256 shared secret size
#define TORUSCSIDH_SECRET_SIZE 32  // TorusCSIDH shared secret size
#define INFO_STRING "TorusCSIDH-Hybrid-KEM"

/* Structure for hybrid KEM context */
struct HYBRID_KEM_CTX {
    toruscsidh_params_t* params;     // TorusCSIDH parameters
    toruscsidh_key_exchange_t* protocol;  // TorusCSIDH protocol instance
    EVP_PKEY_CTX* p256_ctx;          // P-256 key derivation context
    int* toruscsidh_private_key;     // TorusCSIDH private key
    int initialized;                // Context initialization state
};

/* Hybrid public key structure for serialization */
typedef struct {
    uint16_t toruscsidh_len;        // Length of TorusCSIDH public key
    uint16_t p256_len;              // Length of P-256 public key
    uint8_t data[];                 // Combined public key data
} hybrid_public_key_t;

/* Initialize hybrid KEM context */
HYBRID_KEM_CTX* HYBRID_KEM_new(int security_level) {
    HYBRID_KEM_CTX* ctx = OPENSSL_zalloc(sizeof(HYBRID_KEM_CTX));
    if (!ctx) {
        return NULL;
    }
    
    /* Initialize TorusCSIDH context */
    switch (security_level) {
        case 1:  // NIST Level 1 (128-bit security)
            ctx->params = toruscsidh_params_nist_level1();
            break;
        case 3:  // NIST Level 3 (192-bit security)
            ctx->params = toruscsidh_params_nist_level3();
            break;
        case 5:  // NIST Level 5 (256-bit security)
            ctx->params = toruscsidh_params_nist_level5();
            break;
        default:
            OPENSSL_free(ctx);
            return NULL;
    }
    
    if (!ctx->params) {
        OPENSSL_free(ctx);
        return NULL;
    }
    
    ctx->protocol = toruscsidh_key_exchange_new(ctx->params);
    if (!ctx->protocol) {
        toruscsidh_params_free(ctx->params);
        OPENSSL_free(ctx);
        return NULL;
    }
    
    /* Initialize P-256 context */
    ctx->p256_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx->p256_ctx || EVP_PKEY_paramgen_init(ctx->p256_ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx->p256_ctx, NID_X9_62_prime256v1) <= 0) {
        toruscsidh_key_exchange_free(ctx->protocol);
        toruscsidh_params_free(ctx->params);
        if (ctx->p256_ctx) EVP_PKEY_CTX_free(ctx->p256_ctx);
        OPENSSL_free(ctx);
        return NULL;
    }
    
    ctx->initialized = 1;
    return ctx;
}

/* Free hybrid KEM context and sensitive data */
void HYBRID_KEM_free(HYBRID_KEM_CTX* ctx) {
    if (!ctx) return;
    
    if (ctx->initialized) {
        /* Securely zeroize sensitive data */
        if (ctx->toruscsidh_private_key) {
            OPENSSL_cleanse(ctx->toruscsidh_private_key, 
                          ctx->params->primes_count * sizeof(int));
            OPENSSL_free(ctx->toruscsidh_private_key);
            ctx->toruscsidh_private_key = NULL;
        }
        
        /* Free TorusCSIDH resources */
        if (ctx->protocol) {
            toruscsidh_key_exchange_free(ctx->protocol);
            ctx->protocol = NULL;
        }
        
        if (ctx->params) {
            toruscsidh_params_free(ctx->params);
            ctx->params = NULL;
        }
        
        /* Free P-256 resources */
        if (ctx->p256_ctx) {
            EVP_PKEY_CTX_free(ctx->p256_ctx);
            ctx->p256_ctx = NULL;
        }
        
        ctx->initialized = 0;
    }
    
    OPENSSL_free(ctx);
}

/* Generate hybrid key pair */
int HYBRID_KEM_keygen(HYBRID_KEM_CTX* ctx,
                     unsigned char** hybrid_public_key, 
                     size_t* hybrid_public_key_len,
                     EVP_PKEY** p256_private_key) {
    if (!ctx || !hybrid_public_key || !hybrid_public_key_len || !p256_private_key) {
        return 0;
    }
    
    /* Generate TorusCSIDH private key */
    int* private_key = toruscsidh_generate_private_key(ctx->protocol);
    if (!private_key) {
        return 0;
    }
    
    /* Generate TorusCSIDH public key */
    elliptic_curve_t* public_key = NULL;
    if (!toruscsidh_generate_public_key(ctx->protocol, private_key, &public_key)) {
        OPENSSL_free(private_key);
        return 0;
    }
    
    /* Serialize TorusCSIDH public key */
    unsigned char* toruscsidh_pub = NULL;
    size_t toruscsidh_pub_len = 0;
    if (!toruscsidh_serialize_public_key(public_key, &toruscsidh_pub, &toruscsidh_pub_len)) {
        toruscsidh_curve_free(public_key);
        OPENSSL_free(private_key);
        return 0;
    }
    
    toruscsidh_curve_free(public_key);
    
    /* Generate P-256 key pair */
    EVP_PKEY* ecc_key = NULL;
    EVP_PKEY_CTX* param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!param_ctx) {
        OPENSSL_free(private_key);
        OPENSSL_free(toruscsidh_pub);
        return 0;
    }
    
    if (EVP_PKEY_paramgen_init(param_ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(param_ctx);
        OPENSSL_free(private_key);
        OPENSSL_free(toruscsidh_pub);
        return 0;
    }
    
    if (EVP_PKEY_paramgen(param_ctx, &ecc_key) <= 0) {
        EVP_PKEY_CTX_free(param_ctx);
        OPENSSL_free(private_key);
        OPENSSL_free(toruscsidh_pub);
        return 0;
    }
    
    EVP_PKEY_CTX_free(param_ctx);
    
    EVP_PKEY_CTX* keygen_ctx = EVP_PKEY_CTX_new(ecc_key, NULL);
    if (!keygen_ctx) {
        EVP_PKEY_free(ecc_key);
        OPENSSL_free(private_key);
        OPENSSL_free(toruscsidh_pub);
        return 0;
    }
    
    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0) {
        EVP_PKEY_CTX_free(keygen_ctx);
        EVP_PKEY_free(ecc_key);
        OPENSSL_free(private_key);
        OPENSSL_free(toruscsidh_pub);
        return 0;
    }
    
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(keygen_ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(keygen_ctx);
        EVP_PKEY_free(ecc_key);
        OPENSSL_free(private_key);
        OPENSSL_free(toruscsidh_pub);
        return 0;
    }
    
    EVP_PKEY_CTX_free(keygen_ctx);
    EVP_PKEY_free(ecc_key);
    
    /* Serialize P-256 public key */
    unsigned char* p256_pub = NULL;
    size_t p256_pub_len = i2d_PUBKEY(pkey, &p256_pub);
    if (p256_pub_len <= 0 || !p256_pub) {
        EVP_PKEY_free(pkey);
        OPENSSL_free(private_key);
        OPENSSL_free(toruscsidh_pub);
        return 0;
    }
    
    /* Serialize combined public key */
    *hybrid_public_key_len = sizeof(uint16_t) * 2 + toruscsidh_pub_len + p256_pub_len;
    *hybrid_public_key = OPENSSL_malloc(*hybrid_public_key_len);
    if (!*hybrid_public_key) {
        OPENSSL_free(p256_pub);
        EVP_PKEY_free(pkey);
        OPENSSL_free(private_key);
        OPENSSL_free(toruscsidh_pub);
        return 0;
    }
    
    uint8_t* ptr = *hybrid_public_key;
    *((uint16_t*)ptr) = (uint16_t)toruscsidh_pub_len;
    ptr += sizeof(uint16_t);
    *((uint16_t*)ptr) = (uint16_t)p256_pub_len;
    ptr += sizeof(uint16_t);
    memcpy(ptr, toruscsidh_pub, toruscsidh_pub_len);
    ptr += toruscsidh_pub_len;
    memcpy(ptr, p256_pub, p256_pub_len);
    
    /* Store private keys in context */
    ctx->toruscsidh_private_key = private_key;
    
    /* Return P-256 private key */
    *p256_private_key = pkey;
    
    /* Cleanup temporary buffers */
    OPENSSL_free(toruscsidh_pub);
    OPENSSL_free(p256_pub);
    
    return 1;
}

/* Decapsulate hybrid ciphertext to obtain shared secret */
int HYBRID_KEM_decapsulate(HYBRID_KEM_CTX* ctx,
                          const unsigned char* hybrid_ciphertext, 
                          size_t hybrid_ciphertext_len,
                          EVP_PKEY* p256_private_key,
                          unsigned char* shared_secret, 
                          size_t* shared_secret_len) {
    if (!ctx || !hybrid_ciphertext || hybrid_ciphertext_len == 0 || 
        !p256_private_key || !shared_secret || !shared_secret_len || 
        !ctx->toruscsidh_private_key) {
        return 0;
    }
    
    if (*shared_secret_len < TORUSCSIDH_SECRET_SIZE + P256_SECRET_SIZE) {
        return 0;
    }
    
    /* Parse hybrid ciphertext */
    if (hybrid_ciphertext_len < sizeof(uint16_t) * 2) {
        return 0;
    }
    
    const uint8_t* ptr = hybrid_ciphertext;
    uint16_t toruscsidh_len = *((uint16_t*)ptr);
    ptr += sizeof(uint16_t);
    uint16_t p256_len = *((uint16_t*)ptr);
    ptr += sizeof(uint16_t);
    
    if (hybrid_ciphertext_len < sizeof(uint16_t) * 2 + toruscsidh_len + p256_len) {
        return 0;
    }
    
    const unsigned char* toruscsidh_ciphertext = ptr;
    const unsigned char* p256_ciphertext = ptr + toruscsidh_len;
    
    /* Deserialize TorusCSIDH partner public key */
    elliptic_curve_t* partner_curve = NULL;
    if (!toruscsidh_deserialize_public_key(ctx->params, 
                                          toruscsidh_ciphertext, 
                                          toruscsidh_len, 
                                          &partner_curve)) {
        return 0;
    }
    
    /* Compute TorusCSIDH shared secret */
    shared_secret_t* toruscsidh_secret = NULL;
    if (!toruscsidh_compute_shared_secret(ctx->protocol,
                                         ctx->toruscsidh_private_key,
                                         partner_curve,
                                         &toruscsidh_secret)) {
        toruscsidh_curve_free(partner_curve);
        return 0;
    }
    
    toruscsidh_curve_free(partner_curve);
    
    /* Deserialize P-256 partner public key */
    EVP_PKEY* p256_pubkey = d2i_PUBKEY(NULL, &p256_ciphertext, p256_len);
    if (!p256_pubkey) {
        toruscsidh_shared_secret_free(toruscsidh_secret);
        return 0;
    }
    
    /* Compute P-256 shared secret */
    EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(p256_private_key, NULL);
    if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, p256_pubkey) <= 0) {
        EVP_PKEY_free(p256_pubkey);
        EVP_PKEY_CTX_free(derive_ctx);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        return 0;
    }
    
    size_t p256_secret_len = P256_SECRET_SIZE;
    unsigned char p256_secret[P256_SECRET_SIZE];
    if (EVP_PKEY_derive(derive_ctx, p256_secret, &p256_secret_len) <= 0 ||
        p256_secret_len != P256_SECRET_SIZE) {
        EVP_PKEY_free(p256_pubkey);
        EVP_PKEY_CTX_free(derive_ctx);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        return 0;
    }
    
    EVP_PKEY_free(p256_pubkey);
    EVP_PKEY_CTX_free(derive_ctx);
    
    /* Generate combined secret using HKDF */
    unsigned char combined_secrets[HYBRID_SECRET_SIZE];
    memcpy(combined_secrets, toruscsidh_secret->derived_key, TORUSCSIDH_SECRET_SIZE);
    memcpy(combined_secrets + TORUSCSIDH_SECRET_SIZE, p256_secret, P256_SECRET_SIZE);
    
    EVP_PKEY_CTX* kdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kdf_ctx) {
        toruscsidh_shared_secret_free(toruscsidh_secret);
        return 0;
    }
    
    size_t out_len = TORUSCSIDH_SECRET_SIZE + P256_SECRET_SIZE;
    if (EVP_PKEY_derive_init(kdf_ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(kdf_ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(kdf_ctx, NULL, 0) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(kdf_ctx, combined_secrets, sizeof(combined_secrets)) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(kdf_ctx, (const unsigned char*)INFO_STRING, strlen(INFO_STRING)) <= 0 ||
        EVP_PKEY_derive(kdf_ctx, shared_secret, &out_len) <= 0) {
        EVP_PKEY_CTX_free(kdf_ctx);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        return 0;
    }
    
    EVP_PKEY_CTX_free(kdf_ctx);
    toruscsidh_shared_secret_free(toruscsidh_secret);
    
    *shared_secret_len = HYBRID_SECRET_SIZE;
    return 1;
}

/* Encapsulate message to generate shared secret and ciphertext */
int HYBRID_KEM_encapsulate(const unsigned char* hybrid_public_key, 
                          size_t hybrid_public_key_len,
                          unsigned char** hybrid_ciphertext, 
                          size_t* hybrid_ciphertext_len,
                          unsigned char* shared_secret, 
                          size_t* shared_secret_len) {
    if (!hybrid_public_key || hybrid_public_key_len == 0 || 
        !hybrid_ciphertext || !hybrid_ciphertext_len || 
        !shared_secret || !shared_secret_len) {
        return 0;
    }
    
    if (*shared_secret_len < TORUSCSIDH_SECRET_SIZE + P256_SECRET_SIZE) {
        return 0;
    }
    
    /* Parse hybrid public key */
    if (hybrid_public_key_len < sizeof(uint16_t) * 2) {
        return 0;
    }
    
    const uint8_t* ptr = hybrid_public_key;
    uint16_t toruscsidh_len = *((uint16_t*)ptr);
    ptr += sizeof(uint16_t);
    uint16_t p256_len = *((uint16_t*)ptr);
    ptr += sizeof(uint16_t);
    
    if (hybrid_public_key_len < sizeof(uint16_t) * 2 + toruscsidh_len + p256_len) {
        return 0;
    }
    
    const unsigned char* toruscsidh_pubkey = ptr;
    const unsigned char* p256_pubkey = ptr + toruscsidh_len;
    
    /* Initialize temporary TorusCSIDH context */
    toruscsidh_params_t* params = toruscsidh_params_nist_level1();
    if (!params) {
        return 0;
    }
    
    toruscsidh_key_exchange_t* protocol = toruscsidh_key_exchange_new(params);
    if (!protocol) {
        toruscsidh_params_free(params);
        return 0;
    }
    
    /* Generate ephemeral TorusCSIDH key pair */
    int* ephemeral_key = toruscsidh_generate_private_key(protocol);
    if (!ephemeral_key) {
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    /* Deserialize TorusCSIDH partner public key */
    elliptic_curve_t* partner_curve = NULL;
    if (!toruscsidh_deserialize_public_key(params,
                                          toruscsidh_pubkey,
                                          toruscsidh_len,
                                          &partner_curve)) {
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    /* Compute TorusCSIDH shared secret */
    shared_secret_t* toruscsidh_secret = NULL;
    if (!toruscsidh_compute_shared_secret(protocol,
                                         ephemeral_key,
                                         partner_curve,
                                         &toruscsidh_secret)) {
        toruscsidh_curve_free(partner_curve);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    toruscsidh_curve_free(partner_curve);
    
    /* Generate ephemeral P-256 key pair */
    EVP_PKEY_CTX* param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!param_ctx) {
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    if (EVP_PKEY_paramgen_init(param_ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(param_ctx);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    EVP_PKEY* ecc_params = NULL;
    if (EVP_PKEY_paramgen(param_ctx, &ecc_params) <= 0) {
        EVP_PKEY_CTX_free(param_ctx);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    EVP_PKEY_CTX_free(param_ctx);
    
    EVP_PKEY_CTX* keygen_ctx = EVP_PKEY_CTX_new(ecc_params, NULL);
    if (!keygen_ctx) {
        EVP_PKEY_free(ecc_params);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0) {
        EVP_PKEY_CTX_free(keygen_ctx);
        EVP_PKEY_free(ecc_params);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    EVP_PKEY* ephemeral_p256 = NULL;
    if (EVP_PKEY_keygen(keygen_ctx, &ephemeral_p256) <= 0) {
        EVP_PKEY_CTX_free(keygen_ctx);
        EVP_PKEY_free(ecc_params);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    EVP_PKEY_CTX_free(keygen_ctx);
    EVP_PKEY_free(ecc_params);
    
    /* Deserialize P-256 partner public key */
    EVP_PKEY* p256_pubkey = d2i_PUBKEY(NULL, &p256_pubkey, p256_len);
    if (!p256_pubkey) {
        EVP_PKEY_free(ephemeral_p256);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    /* Compute P-256 shared secret */
    EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(ephemeral_p256, NULL);
    if (!derive_ctx || EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, p256_pubkey) <= 0) {
        EVP_PKEY_free(ephemeral_p256);
        EVP_PKEY_free(p256_pubkey);
        EVP_PKEY_CTX_free(derive_ctx);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    size_t p256_secret_len = P256_SECRET_SIZE;
    unsigned char p256_secret[P256_SECRET_SIZE];
    if (EVP_PKEY_derive(derive_ctx, p256_secret, &p256_secret_len) <= 0 ||
        p256_secret_len != P256_SECRET_SIZE) {
        EVP_PKEY_free(ephemeral_p256);
        EVP_PKEY_free(p256_pubkey);
        EVP_PKEY_CTX_free(derive_ctx);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    EVP_PKEY_free(p256_pubkey);
    EVP_PKEY_CTX_free(derive_ctx);
    
    /* Generate combined secret using HKDF */
    unsigned char combined_secrets[HYBRID_SECRET_SIZE];
    memcpy(combined_secrets, toruscsidh_secret->derived_key, TORUSCSIDH_SECRET_SIZE);
    memcpy(combined_secrets + TORUSCSIDH_SECRET_SIZE, p256_secret, P256_SECRET_SIZE);
    
    EVP_PKEY_CTX* kdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kdf_ctx) {
        EVP_PKEY_free(ephemeral_p256);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    size_t out_len = TORUSCSIDH_SECRET_SIZE + P256_SECRET_SIZE;
    if (EVP_PKEY_derive_init(kdf_ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(kdf_ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(kdf_ctx, NULL, 0) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(kdf_ctx, combined_secrets, sizeof(combined_secrets)) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(kdf_ctx, (const unsigned char*)INFO_STRING, strlen(INFO_STRING)) <= 0 ||
        EVP_PKEY_derive(kdf_ctx, shared_secret, &out_len) <= 0) {
        EVP_PKEY_CTX_free(kdf_ctx);
        EVP_PKEY_free(ephemeral_p256);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    EVP_PKEY_CTX_free(kdf_ctx);
    
    /* Create ciphertext (TorCSIDH public key + P-256 public key) */
    unsigned char* p256_pub_bytes = NULL;
    size_t p256_pub_bytes_len = i2d_PUBKEY(ephemeral_p256, &p256_pub_bytes);
    if (p256_pub_bytes_len <= 0 || !p256_pub_bytes) {
        EVP_PKEY_free(ephemeral_p256);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    *hybrid_ciphertext_len = sizeof(uint16_t) * 2 + toruscsidh_len + p256_pub_bytes_len;
    *hybrid_ciphertext = OPENSSL_malloc(*hybrid_ciphertext_len);
    if (!*hybrid_ciphertext) {
        OPENSSL_free(p256_pub_bytes);
        EVP_PKEY_free(ephemeral_p256);
        toruscsidh_shared_secret_free(toruscsidh_secret);
        OPENSSL_free(ephemeral_key);
        toruscsidh_key_exchange_free(protocol);
        toruscsidh_params_free(params);
        return 0;
    }
    
    uint8_t* cptr = *hybrid_ciphertext;
    *((uint16_t*)cptr) = (uint16_t)toruscsidh_len;
    cptr += sizeof(uint16_t);
    *((uint16_t*)cptr) = (uint16_t)p256_pub_bytes_len;
    cptr += sizeof(uint16_t);
    memcpy(cptr, toruscsidh_pubkey, toruscsidh_len);
    cptr += toruscsidh_len;
    memcpy(cptr, p256_pub_bytes, p256_pub_bytes_len);
    
    /* Cleanup */
    OPENSSL_free(p256_pub_bytes);
    EVP_PKEY_free(ephemeral_p256);
    toruscsidh_shared_secret_free(toruscsidh_secret);
    OPENSSL_free(ephemeral_key);
    toruscsidh_key_exchange_free(protocol);
    toruscsidh_params_free(params);
    
    *shared_secret_len = HYBRID_SECRET_SIZE;
    return 1;
}

/* Test compatibility with OpenSSL EVP API */
int test_openssl_evp_compatibility(void) {
    int result = 0;
    HYBRID_KEM_CTX* ctx_alice = NULL;
    HYBRID_KEM_CTX* ctx_bob = NULL;
    unsigned char* public_key_alice = NULL;
    unsigned char* public_key_bob = NULL;
    size_t pubkey_len_alice = 0;
    size_t pubkey_len_bob = 0;
    EVP_PKEY* p256_priv_alice = NULL;
    EVP_PKEY* p256_priv_bob = NULL;
    unsigned char* ciphertext_alice = NULL;
    unsigned char* ciphertext_bob = NULL;
    size_t ciphertext_len_alice = 0;
    size_t ciphertext_len_bob = 0;
    unsigned char shared_secret_alice[HYBRID_SECRET_SIZE];
    unsigned char shared_secret_bob[HYBRID_SECRET_SIZE];
    size_t secret_len_alice = sizeof(shared_secret_alice);
    size_t secret_len_bob = sizeof(shared_secret_bob);
    
    /* Initialize contexts */
    ctx_alice = HYBRID_KEM_new(1);
    ctx_bob = HYBRID_KEM_new(1);
    if (!ctx_alice || !ctx_bob) {
        goto cleanup;
    }
    
    /* Generate key pairs */
    if (!HYBRID_KEM_keygen(ctx_alice, &public_key_alice, &pubkey_len_alice, &p256_priv_alice) ||
        !HYBRID_KEM_keygen(ctx_bob, &public_key_bob, &pubkey_len_bob, &p256_priv_bob)) {
        goto cleanup;
    }
    
    /* Test key exchange */
    if (!HYBRID_KEM_encapsulate(public_key_bob, pubkey_len_bob,
                              &ciphertext_alice, &ciphertext_len_alice,
                              shared_secret_alice, &secret_len_alice) ||
        !HYBRID_KEM_decapsulate(ctx_bob, ciphertext_alice, ciphertext_len_alice,
                              p256_priv_alice,
                              shared_secret_bob, &secret_len_bob)) {
        goto cleanup;
    }
    
    /* Verify shared secrets match */
    if (secret_len_alice != secret_len_bob ||
        CRYPTO_memcmp(shared_secret_alice, shared_secret_bob, secret_len_alice) != 0) {
        goto cleanup;
    }
    
    /* Test EVP_PKEY integration */
    EVP_PKEY* hybrid_pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, NULL, public_key_alice, pubkey_len_alice);
    if (hybrid_pkey) {
        EVP_PKEY_free(hybrid_pkey);
    }
    
    result = 1;
    
cleanup:
    if (ciphertext_alice) OPENSSL_free(ciphertext_alice);
    if (ciphertext_bob) OPENSSL_free(ciphertext_bob);
    if (public_key_alice) OPENSSL_free(public_key_alice);
    if (public_key_bob) OPENSSL_free(public_key_bob);
    if (p256_priv_alice) EVP_PKEY_free(p256_priv_alice);
    if (p256_priv_bob) EVP_PKEY_free(p256_priv_bob);
    if (ctx_alice) HYBRID_KEM_free(ctx_alice);
    if (ctx_bob) HYBRID_KEM_free(ctx_bob);
    
    return result;
}

/* Test hybrid KEM functionality */
int test_hybrid_kem_functionality(void) {
    int result = 0;
    HYBRID_KEM_CTX* ctx_alice = NULL;
    HYBRID_KEM_CTX* ctx_bob = NULL;
    unsigned char* public_key_alice = NULL;
    unsigned char* public_key_bob = NULL;
    size_t pubkey_len_alice = 0;
    size_t pubkey_len_bob = 0;
    EVP_PKEY* p256_priv_alice = NULL;
    EVP_PKEY* p256_priv_bob = NULL;
    unsigned char* ciphertext_alice = NULL;
    unsigned char* ciphertext_bob = NULL;
    size_t ciphertext_len_alice = 0;
    size_t ciphertext_len_bob = 0;
    unsigned char shared_secret_alice[HYBRID_SECRET_SIZE];
    unsigned char shared_secret_bob[HYBRID_SECRET_SIZE];
    size_t secret_len_alice = sizeof(shared_secret_alice);
    size_t secret_len_bob = sizeof(shared_secret_bob);
    
    /* Initialize contexts */
    ctx_alice = HYBRID_KEM_new(1);
    ctx_bob = HYBRID_KEM_new(1);
    if (!ctx_alice || !ctx_bob) {
        goto cleanup;
    }
    
    /* Generate key pairs */
    if (!HYBRID_KEM_keygen(ctx_alice, &public_key_alice, &pubkey_len_alice, &p256_priv_alice) ||
        !HYBRID_KEM_keygen(ctx_bob, &public_key_bob, &pubkey_len_bob, &p256_priv_bob)) {
        goto cleanup;
    }
    
    /* Test key exchange */
    if (!HYBRID_KEM_encapsulate(public_key_bob, pubkey_len_bob,
                              &ciphertext_alice, &ciphertext_len_alice,
                              shared_secret_alice, &secret_len_alice) ||
        !HYBRID_KEM_decapsulate(ctx_bob, ciphertext_alice, ciphertext_len_alice,
                              p256_priv_alice,
                              shared_secret_bob, &secret_len_bob) ||
        !HYBRID_KEM_encapsulate(public_key_alice, pubkey_len_alice,
                              &ciphertext_bob, &ciphertext_len_bob,
                              shared_secret_bob, &secret_len_bob) ||
        !HYBRID_KEM_decapsulate(ctx_alice, ciphertext_bob, ciphertext_len_bob,
                              p256_priv_bob,
                              shared_secret_alice, &secret_len_alice)) {
        goto cleanup;
    }
    
    /* Verify shared secrets match */
    if (secret_len_alice != secret_len_bob ||
        CRYPTO_memcmp(shared_secret_alice, shared_secret_bob, secret_len_alice) != 0) {
        goto cleanup;
    }
    
    result = 1;
    
cleanup:
    if (ciphertext_alice) OPENSSL_free(ciphertext_alice);
    if (ciphertext_bob) OPENSSL_free(ciphertext_bob);
    if (public_key_alice) OPENSSL_free(public_key_alice);
    if (public_key_bob) OPENSSL_free(public_key_bob);
    if (p256_priv_alice) EVP_PKEY_free(p256_priv_alice);
    if (p256_priv_bob) EVP_PKEY_free(p256_priv_bob);
    if (ctx_alice) HYBRID_KEM_free(ctx_alice);
    if (ctx_bob) HYBRID_KEM_free(ctx_bob);
    
    return result;
}
