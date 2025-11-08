// include/math/constants.h
#ifndef TORUS_CONSTANTS_H
#define TORUS_CONSTANTS_H

#include "torus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file constants.h
 * @brief Mathematical constants and parameters for TorusCSIDH
 * @ingroup math
 * 
 * This module defines all mathematical constants, security parameters,
 * and precomputed values used throughout the TorusCSIDH system.
 */

// ============================================================================
// Security Level Constants
// ============================================================================

/**
 * @brief Security level parameters structure
 */
typedef struct {
    uint32_t level_bits;           ///< Security level in bits
    uint32_t p_bits;               ///< Prime field size in bits
    uint32_t num_primes;           ///< Number of small primes
    uint32_t max_exponent;         ///< Maximum exponent for primes
    const uint64_t* primes;        ///< Array of small primes
    const int64_t* exponents;      ///< Array of exponent bounds
} security_params_t;

/**
 * @brief Get security parameters for a given security level
 * 
 * @param level Security level (128, 192, 256, 512)
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

// ============================================================================
// Prime Field Constants
// ============================================================================

/**
 * @brief Structure for prime field parameters
 */
typedef struct {
    uint64_t p[NLIMBS];           ///< Prime modulus
    uint64_t p_minus_1[NLIMBS];   ///< p - 1
    uint64_t p_minus_2[NLIMBS];   ///< p - 2
    uint64_t p_plus_1[NLIMBS];    ///< p + 1
    uint64_t montgomery_r[NLIMBS]; ///< Montgomery R = 2^(NLIMBS*64) mod p
    uint64_t montgomery_r2[NLIMBS]; ///< Montgomery R^2 mod p
    uint64_t montgomery_inv;      ///< Montgomery inverse
} prime_constants_t;

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
 * @return const uint64_t* Prime modulus array
 */
TORUS_API const uint64_t* get_prime_modulus(security_level_t level);

/**
 * @brief Get Montgomery constant R for a security level
 * 
 * @param level Security level
 * @return const uint64_t* Montgomery R array
 */
TORUS_API const uint64_t* get_montgomery_r(security_level_t level);

/**
 * @brief Get Montgomery constant R^2 for a security level
 * 
 * @param level Security level
 * @return const uint64_t* Montgomery R^2 array
 */
TORUS_API const uint64_t* get_montgomery_r2(security_level_t level);

/**
 * @brief Get Montgomery inverse for a security level
 * 
 * @param level Security level
 * @return uint64_t Montgomery inverse
 */
TORUS_API uint64_t get_montgomery_inv(security_level_t level);

// ============================================================================
// Elliptic Curve Constants
// ============================================================================

/**
 * @brief Structure for base curve parameters
 */
typedef struct {
    fp2_t A;                      ///< Curve parameter A in Montgomery form
    fp2_t C;                      ///< Curve parameter C in Montgomery form
    fp2_t A24;                    ///< Precomputed (A + 2)/4
    fp2_t C24;                    ///< Precomputed (C + 2)/4
    uint64_t cofactor[NLIMBS];    ///< Curve cofactor
} curve_constants_t;

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
 * @return const fp2_t* Curve parameter A
 */
TORUS_API const fp2_t* get_base_curve_A(security_level_t level);

/**
 * @brief Get the base curve parameter C
 * 
 * @param level Security level
 * @return const fp2_t* Curve parameter C
 */
TORUS_API const fp2_t* get_base_curve_C(security_level_t level);

/**
 * @brief Get precomputed A24 = (A + 2)/4
 * 
 * @param level Security level
 * @return const fp2_t* Precomputed A24
 */
TORUS_API const fp2_t* get_precomputed_A24(security_level_t level);

// ============================================================================
// Isogeny Computation Constants
// ============================================================================

/**
 * @brief Structure for isogeny strategy parameters
 */
typedef struct {
    uint32_t max_degree;          ///< Maximum isogeny degree to compute directly
    uint32_t optimal_split_threshold; ///< Threshold for recursive splitting
    uint32_t window_size;         ///< Window size for scalar multiplication
    uint32_t batch_size;          ///< Optimal batch size for parallel computation
} isogeny_strategy_t;

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

// ============================================================================
// Precomputed Tables
// ============================================================================

/**
 * @brief Get precomputed table for small prime isogenies
 * 
 * @param prime The small prime
 * @param level Security level
 * @return const void* Precomputed table (NULL if not available)
 */
TORUS_API const void* get_precomputed_isogeny_table(uint64_t prime, security_level_t level);

/**
 * @brief Get precomputed square roots table
 * 
 * @param level Security level
 * @return const uint64_t* Square roots table
 */
TORUS_API const uint64_t* get_square_roots_table(security_level_t level);

/**
 * @brief Get precomputed inversion table
 * 
 * @param level Security level
 * @return const uint64_t* Inversion table
 */
TORUS_API const uint64_t* get_inversion_table(security_level_t level);

// ============================================================================
// Mathematical Constants
// ============================================================================

/**
 * @brief Fundamental mathematical constants
 */
extern const uint64_t TORUS_ZERO[NLIMBS];
extern const uint64_t TORUS_ONE[NLIMBS];
extern const uint64_t TORUS_TWO[NLIMBS];
extern const uint64_t TORUS_THREE[NLIMBS];
extern const uint64_t TORUS_FOUR[NLIMBS];
extern const uint64_t TORUS_EIGHT[NLIMBS];

/**
 * @brief Fp2 constants
 */
extern const fp2_t FP2_ZERO;
extern const fp2_t FP2_ONE;
extern const fp2_t FP2_I;          ///< Imaginary unit i in Fp2
extern const fp2_t FP2_MINUS_ONE;
extern const fp2_t FP2_MINUS_I;    ///< -i in Fp2

/**
 * @brief Get fundamental constant as fp2 element
 * 
 * @param value The constant value (0, 1, 2, etc.)
 * @return const fp2_t* Constant as fp2 element
 */
TORUS_API const fp2_t* get_fp2_constant(uint64_t value);

// ============================================================================
// Validation and Verification Constants
// ============================================================================

/**
 * @brief Structure for validation parameters
 */
typedef struct {
    uint32_t max_kernel_search_attempts; ///< Maximum attempts to find kernel point
    uint32_t point_verification_samples; ///< Number of samples for point verification
    double valid_curve_threshold;       ///< Threshold for curve validation
    uint32_t max_isogeny_chain_length;  ///< Maximum isogeny chain length
} validation_constants_t;

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

#ifdef __cplusplus
}
#endif

#endif // TORUS_CONSTANTS_H
