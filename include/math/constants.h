// include/math/constants.h
#ifndef TORUS_CONSTANTS_H
#define TORUS_CONSTANTS_H

#include "torus_common.h"
#include "math/fp_types.h"
#include "math/fp_arithmetic.h"
#include "math/fp2_arithmetic.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants and Configuration
// ============================================================================

/**
 * @file constants.h
 * @brief Mathematical constants and parameters for TorusCSIDH
 * @ingroup math
 * 
 * This module defines all mathematical constants, security parameters,
 * and precomputed values used throughout the TorusCSIDH system.
 * All constants are optimized for performance and security.
 */

/**
 * @brief Maximum number of initialization attempts
 */
#define CONSTANTS_MAX_INIT_ATTEMPTS 3

/**
 * @brief Size of square roots table
 */
#define SQUARE_ROOTS_TABLE_SIZE 256

/**
 * @brief Maximum length for error messages
 */
#define CONSTANTS_MAX_ERROR_LEN 256

/**
 * @brief Maximum bytes for prime field elements
 */
#define FP_MAX_BYTES 128  // 1024 bits = 128 bytes

/**
 * @brief Security level enumeration
 */
typedef enum {
    TORUS_SECURITY_128 = 128,  ///< 128-bit security level (CSIDH-512)
    TORUS_SECURITY_192 = 192,  ///< 192-bit security level (CSIDH-768)
    TORUS_SECURITY_256 = 256,  ///< 256-bit security level (CSIDH-1024)
    TORUS_SECURITY_512 = 512   ///< 512-bit security level (future use)
} security_level_t;

/**
 * @brief Constant verification structure
 */
typedef struct {
    uint8_t hash[32];          ///< SHA-256 hash of precomputed data
    uint32_t crc32;            ///< CRC32 checksum
    uint64_t timestamp;        ///< Generation timestamp
    uint8_t signature[64];     ///< Ed25519 signature for verification
} constant_verification_t;

/**
 * @brief Security level parameters structure
 */
typedef struct {
    uint32_t level_bits;           ///< Security level in bits
    uint32_t p_bits;               ///< Prime field size in bits
    uint32_t num_primes;           ///< Number of small primes
    uint32_t max_exponent;         ///< Maximum exponent for primes
    uint32_t total_bits;           ///< Total exponent bits
    const uint64_t* primes;        ///< Array of small primes
    const int64_t* exponents;      ///< Array of exponent bounds
    const char* prime_hex;         ///< Prime modulus in hex
    uint32_t prime_hex_len;        ///< Length of prime hex string
    const char* description;       ///< Security level description
    constant_verification_t verification; ///< Verification data
} security_params_t;

/**
 * @brief Prime field constants structure
 */
typedef struct {
    fp modulus;                    ///< Prime modulus
    fp modulus_minus_one;          ///< p - 1
    fp modulus_minus_two;          ///< p - 2
    fp modulus_plus_one;           ///< p + 1
    fp modulus_plus_one_div_two;   ///< (p + 1) / 2
    fp modulus_minus_one_div_two;  ///< (p - 1) / 2
    fp montgomery_r;               ///< Montgomery R = 2^k mod p
    fp montgomery_r2;              ///< Montgomery R^2 mod p
    uint64_t montgomery_inv;       ///< Montgomery inverse
    uint32_t bits;                 ///< Number of bits in modulus
    uint32_t bytes;                ///< Number of bytes in modulus
    fp_ctx_t fp_ctx;              ///< Fp context for this prime
    uint8_t is_initialized;       ///< Initialization flag
    constant_verification_t verification; ///< Verification data
} prime_constants_t;

/**
 * @brief Base curve parameters structure
 */
typedef struct {
    fp2 A;                         ///< Curve parameter A in Montgomery form
    fp2 C;                         ///< Curve parameter C in Montgomery form
    fp2 A24;                       ///< Precomputed (A + 2C) / 4C
    fp2 C24;                       ///< Precomputed 4C
    fp2 A_plus_2C;                 ///< Precomputed A + 2C
    fp2 four_C;                    ///< Precomputed 4C
    fp cofactor;                   ///< Curve cofactor
    security_level_t security_level; ///< Security level
    fp2_ctx_t fp2_ctx;            ///< Fp2 context for this curve
    uint8_t is_initialized;       ///< Initialization flag
    constant_verification_t verification; ///< Verification data
} curve_constants_t;

/**
 * @brief Isogeny strategy parameters structure
 */
typedef struct {
    uint32_t max_degree;           ///< Maximum isogeny degree to compute directly
    uint32_t optimal_split_threshold; ///< Threshold for recursive splitting
    uint32_t window_size;          ///< Window size for scalar multiplication
    uint32_t batch_size;           ///< Optimal batch size for parallel computation
    uint32_t max_chain_length;     ///< Maximum isogeny chain length
    uint32_t kernel_search_attempts; ///< Maximum attempts to find kernel point
    double efficiency_factor;      ///< Strategy efficiency factor
    const char* strategy_name;     ///< Strategy description
} isogeny_strategy_t;

/**
 * @brief Precomputed isogeny table entry structure
 */
typedef struct {
    uint64_t prime;                ///< Small prime
    fp2 kernel_point;              ///< Precomputed kernel point
    fp2 isogeny_coeffs[4];         ///< Isogeny coefficients
    uint32_t degree;               ///< Isogeny degree
    uint8_t is_valid;              ///< Validity flag
    constant_verification_t verification; ///< Verification data
} isogeny_table_entry_t;

/**
 * @brief Validation parameters structure
 */
typedef struct {
    uint32_t max_kernel_search_attempts; ///< Maximum attempts to find kernel point
    uint32_t point_verification_samples; ///< Number of samples for point verification
    double valid_curve_threshold;        ///< Threshold for curve validation
    uint32_t max_isogeny_chain_length;   ///< Maximum isogeny chain length
    uint32_t security_margin;            ///< Security margin in bits
    double rejection_sampling_threshold; ///< Threshold for rejection sampling
    const char* validation_method;       ///< Validation method description
} validation_constants_t;

/**
 * @brief Performance optimization parameters structure
 */
typedef struct {
    uint32_t cache_line_size;      ///< CPU cache line size in bytes
    uint32_t l1_cache_size;        ///< L1 cache size in KB
    uint32_t l2_cache_size;        ///< L2 cache size in KB
    uint32_t l3_cache_size;        ///< L3 cache size in KB
    uint32_t optimal_thread_count; ///< Optimal number of threads
    uint32_t vector_size;          ///< Optimal vector size for SIMD
    uint32_t memory_alignment;     ///< Optimal memory alignment
    const char* optimization_target; ///< Target platform description
} performance_constants_t;

// ============================================================================
// Error Handling and Logging
// ============================================================================

/**
 * @brief Log levels for constants module
 */
typedef enum {
    CONSTANTS_LOG_ERROR = 0,
    CONSTANTS_LOG_WARN  = 1,
    CONSTANTS_LOG_INFO  = 2,
    CONSTANTS_LOG_DEBUG = 3
} constants_log_level_t;

/**
 * @brief Set log level for constants module
 * 
 * @param level Log level to set
 */
TORUS_API void constants_set_log_level(constants_log_level_t level);

/**
 * @brief Get current log level
 * 
 * @return constants_log_level_t Current log level
 */
TORUS_API constants_log_level_t constants_get_log_level(void);

// ============================================================================
// Security Parameters API
// ============================================================================

/**
 * @brief Get security parameters for a given security level
 * 
 * @param level Security level
 * @return const security_params_t* Security parameters structure
 */
TORUS_API const security_params_t* get_security_params(security_level_t level);

/**
 * @brief Get the number of small primes for a security level
 * 
 * @param level Security level
 * @return uint32_t Number of primes
 */
TORUS_API uint32_t get_prime_count(security_level_t level);

/**
 * @brief Get the small primes array for a security level
 * 
 * @param level Security level
 * @return const uint64_t* Array of primes
 */
TORUS_API const uint64_t* get_primes_array(security_level_t level);

/**
 * @brief Get the exponent bounds for a security level
 * 
 * @param level Security level
 * @return const int64_t* Array of exponent bounds
 */
TORUS_API const int64_t* get_exponent_bounds(security_level_t level);

/**
 * @brief Get the maximum exponent for a security level
 * 
 * @param level Security level
 * @return uint32_t Maximum exponent
 */
TORUS_API uint32_t get_max_exponent(security_level_t level);

/**
 * @brief Verify security parameters for a given level
 * 
 * @param level Security level to verify
 * @return int TORUS_SUCCESS if valid, error code otherwise
 */
TORUS_API int verify_security_params(security_level_t level);

// ============================================================================
// Prime Field Constants API
// ============================================================================

/**
 * @brief Get prime field constants for a security level
 * 
 * @param level Security level
 * @return const prime_constants_t* Prime constants structure
 */
TORUS_API const prime_constants_t* get_prime_constants(security_level_t level);

/**
 * @brief Get the prime modulus for a security level
 * 
 * @param level Security level
 * @return const fp* Prime modulus
 */
TORUS_API const fp* get_prime_modulus(security_level_t level);

/**
 * @brief Get Montgomery constant R for a security level
 * 
 * @param level Security level
 * @return const fp* Montgomery R
 */
TORUS_API const fp* get_montgomery_r(security_level_t level);

/**
 * @brief Get Montgomery constant R^2 for a security level
 * 
 * @param level Security level
 * @return const fp* Montgomery R^2
 */
TORUS_API const fp* get_montgomery_r2(security_level_t level);

/**
 * @brief Get Montgomery inverse for a security level
 * 
 * @param level Security level
 * @return uint64_t Montgomery inverse
 */
TORUS_API uint64_t get_montgomery_inv(security_level_t level);

/**
 * @brief Get Fp context for a security level
 * 
 * @param level Security level
 * @return const fp_ctx_t* Fp context
 */
TORUS_API const fp_ctx_t* get_fp_ctx(security_level_t level);

/**
 * @brief Verify prime constants for a security level
 * 
 * @param level Security level to verify
 * @return int TORUS_SUCCESS if valid, error code otherwise
 */
TORUS_API int verify_prime_constants(security_level_t level);

// ============================================================================
// Elliptic Curve Constants API
// ============================================================================

/**
 * @brief Get base curve constants for a security level
 * 
 * @param level Security level
 * @return const curve_constants_t* Curve constants structure
 */
TORUS_API const curve_constants_t* get_curve_constants(security_level_t level);

/**
 * @brief Get the base curve parameter A
 * 
 * @param level Security level
 * @return const fp2* Curve parameter A
 */
TORUS_API const fp2* get_base_curve_A(security_level_t level);

/**
 * @brief Get the base curve parameter C
 * 
 * @param level Security level
 * @return const fp2* Curve parameter C
 */
TORUS_API const fp2* get_base_curve_C(security_level_t level);

/**
 * @brief Get precomputed A24 = (A + 2C) / 4C
 * 
 * @param level Security level
 * @return const fp2* Precomputed A24
 */
TORUS_API const fp2* get_precomputed_A24(security_level_t level);

/**
 * @brief Get curve cofactor
 * 
 * @param level Security level
 * @return const fp* Curve cofactor
 */
TORUS_API const fp* get_curve_cofactor(security_level_t level);

/**
 * @brief Get Fp2 context for a security level
 * 
 * @param level Security level
 * @return const fp2_ctx_t* Fp2 context
 */
TORUS_API const fp2_ctx_t* get_fp2_ctx(security_level_t level);

/**
 * @brief Verify curve constants for a security level
 * 
 * @param level Security level to verify
 * @return int TORUS_SUCCESS if valid, error code otherwise
 */
TORUS_API int verify_curve_constants(security_level_t level);

// ============================================================================
// Isogeny Computation Constants API
// ============================================================================

/**
 * @brief Get isogeny computation strategy parameters
 * 
 * @param level Security level
 * @return const isogeny_strategy_t* Strategy parameters
 */
TORUS_API const isogeny_strategy_t* get_isogeny_strategy(security_level_t level);

/**
 * @brief Get optimal batch size for isogeny computations
 * 
 * @param level Security level
 * @return uint32_t Optimal batch size
 */
TORUS_API uint32_t get_optimal_batch_size(security_level_t level);

/**
 * @brief Get window size for scalar multiplication
 * 
 * @param level Security level
 * @return uint32_t Window size
 */
TORUS_API uint32_t get_window_size(security_level_t level);

/**
 * @brief Get maximum isogeny chain length
 * 
 * @param level Security level
 * @return uint32_t Maximum chain length
 */
TORUS_API uint32_t get_max_chain_length(security_level_t level);

// ============================================================================
// Precomputed Tables API
// ============================================================================

/**
 * @brief Get precomputed table for small prime isogenies
 * 
 * @param level Security level
 * @return const isogeny_table_entry_t* Precomputed table
 */
TORUS_API const isogeny_table_entry_t* get_precomputed_isogeny_table(security_level_t level);

/**
 * @brief Get precomputed square roots table
 * 
 * @param level Security level
 * @return const fp* Square roots table
 */
TORUS_API const fp* get_square_roots_table(security_level_t level);

/**
 * @brief Get precomputed inversion table
 * 
 * @param level Security level
 * @return const fp* Inversion table
 */
TORUS_API const fp* get_inversion_table(security_level_t level);

/**
 * @brief Get precomputed Frobenius constants
 * 
 * @param level Security level
 * @return const fp2* Frobenius constants
 */
TORUS_API const fp2* get_frobenius_constants(security_level_t level);

/**
 * @brief Verify precomputed tables for a security level
 * 
 * @param level Security level to verify
 * @return int TORUS_SUCCESS if valid, error code otherwise
 */
TORUS_API int verify_precomputed_tables(security_level_t level);

// ============================================================================
// Mathematical Constants
// ============================================================================

/**
 * @brief Fundamental mathematical constants
 */
TORUS_API extern const fp FP_ZERO;
TORUS_API extern const fp FP_ONE;
TORUS_API extern const fp FP_TWO;
TORUS_API extern const fp FP_THREE;
TORUS_API extern const fp FP_FOUR;
TORUS_API extern const fp FP_EIGHT;

/**
 * @brief Fp2 constants
 */
TORUS_API extern const fp2 FP2_ZERO;
TORUS_API extern const fp2 FP2_ONE;
TORUS_API extern const fp2 FP2_I;          ///< Imaginary unit i in Fp2
TORUS_API extern const fp2 FP2_MINUS_ONE;
TORUS_API extern const fp2 FP2_MINUS_I;    ///< -i in Fp2

/**
 * @brief Get fundamental constant as fp2 element
 * 
 * @param value The constant value (0, 1, 2, etc.)
 * @return const fp2* Constant as fp2 element
 */
TORUS_API const fp2* get_fp2_constant(uint64_t value);

// ============================================================================
// Validation and Verification Constants API
// ============================================================================

/**
 * @brief Get validation constants
 * 
 * @param level Security level
 * @return const validation_constants_t* Validation constants
 */
TORUS_API const validation_constants_t* get_validation_constants(security_level_t level);

/**
 * @brief Get maximum kernel search attempts
 * 
 * @param level Security level
 * @return uint32_t Maximum attempts
 */
TORUS_API uint32_t get_max_kernel_attempts(security_level_t level);

/**
 * @brief Get security margin
 * 
 * @param level Security level
 * @return uint32_t Security margin in bits
 */
TORUS_API uint32_t get_security_margin(security_level_t level);

// ============================================================================
// Performance Optimization Constants API
// ============================================================================

/**
 * @brief Get performance optimization constants
 * 
 * @param level Security level
 * @return const performance_constants_t* Performance constants
 */
TORUS_API const performance_constants_t* get_performance_constants(security_level_t level);

/**
 * @brief Get optimal memory alignment
 * 
 * @param level Security level
 * @return uint32_t Optimal alignment in bytes
 */
TORUS_API uint32_t get_optimal_alignment(security_level_t level);

// ============================================================================
// Integrity Verification API
// ============================================================================

/**
 * @brief Verify integrity of all constants for a security level
 * 
 * @param level Security level to verify
 * @return int TORUS_SUCCESS if integrity verified, error code otherwise
 */
TORUS_API int verify_constants_integrity(security_level_t level);

/**
 * @brief Compute verification hash for constants data
 * 
 * @param hash[out] Output hash (32 bytes)
 * @param data[in] Input data
 * @param size[in] Size of data
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int compute_constants_hash(uint8_t hash[32], const void* data, size_t size);

/**
 * @brief Verify kernel point has correct order
 * 
 * @param point[in] Kernel point to verify
 * @param prime[in] Expected prime order
 * @param ctx[in] Fp2 context
 * @return int 1 if valid, 0 otherwise
 */
TORUS_API int verify_kernel_point_order(const fp2* point, uint64_t prime, const fp2_ctx_t* ctx);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Initialize all mathematical constants
 * 
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int constants_initialize(void);

/**
 * @brief Clean up constants (free memory, etc.)
 */
TORUS_API void constants_cleanup(void);

/**
 * @brief Verify that constants are properly initialized
 * 
 * @return int 1 if initialized, 0 otherwise
 */
TORUS_API int constants_verify_initialization(void);

/**
 * @brief Get library version information
 * 
 * @return const char* Version string
 */
TORUS_API const char* get_library_version(void);

/**
 * @brief Get build configuration information
 * 
 * @return const char* Build configuration string
 */
TORUS_API const char* get_build_configuration(void);

/**
 * @brief Get detailed initialization status
 * 
 * @return const char* Initialization status string
 */
TORUS_API const char* get_initialization_status(void);

#ifdef __cplusplus
}
#endif

#endif // TORUS_CONSTANTS_H
