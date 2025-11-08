// include/math/modular_reduction.h
#ifndef MODULAR_REDUCTION_H
#define MODULAR_REDUCTION_H

#include "fp.h"
#include "torus_errors.h"
#include "torus_common.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file modular_reduction.h
 * @brief Modular reduction algorithms for finite field arithmetic
 * @ingroup math
 * 
 * This module implements various modular reduction algorithms optimized
 * for the specific prime used in TorusCSIDH. It includes Barrett reduction,
 * Montgomery reduction, and specialized reduction for CSIDH primes.
 */

/**
 * @brief Barrett reduction parameters
 */
typedef struct {
    fp modulus;           ///< The modulus p
    fp mu;                ///< μ = floor(2^(2k) / p) where k = ceil(log2(p))
    size_t k;             ///< k = ceil(log2(p))
    uint32_t security_level; ///< Security level for optimization
} barrett_params_t;

/**
 * @brief Montgomery reduction parameters  
 */
typedef struct {
    fp modulus;           ///< The modulus p
    fp r2;                ///< R^2 mod p where R = 2^k
    uint64_t inv;         ///< p' = -p^{-1} mod 2^64
    size_t k;             ///< k = number of bits in modulus
    uint32_t security_level; ///< Security level for optimization
} montgomery_params_t;

/**
 * @brief CSIDH-specific reduction parameters
 */
typedef struct {
    fp modulus;           ///< The modulus p
    fp p_plus_1;          ///< p + 1 for special reduction
    fp p_minus_1_half;    ///< (p - 1) / 2 for bounds checking
    uint32_t num_primes;  ///< Number of small primes in product
    const uint64_t* primes; ///< Array of small primes
    uint64_t product;     ///< Product of small primes for optimization
} csidh_reduction_params_t;

/**
 * @brief Initialize Barrett reduction parameters
 * 
 * @param params[out] Barrett parameters to initialize
 * @param modulus[in] The modulus p
 * @param security_level[in] Security level for optimization
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int barrett_params_init(barrett_params_t* params, const fp* modulus, uint32_t security_level);

/**
 * @brief Perform Barrett reduction
 * 
 * @param result[out] Result of reduction (a mod p)
 * @param a[in] Input value to reduce (must be < p^2)
 * @param params[in] Barrett reduction parameters
 * @return int TORUS_SUCCESS on success, error code on failure
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API int barrett_reduce(fp* result, const fp* a, const barrett_params_t* params);

/**
 * @brief Initialize Montgomery reduction parameters
 * 
 * @param params[out] Montgomery parameters to initialize
 * @param modulus[in] The modulus p
 * @param security_level[in] Security level for optimization
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int montgomery_params_init(montgomery_params_t* params, const fp* modulus, uint32_t security_level);

/**
 * @brief Convert to Montgomery form
 * 
 * @param result[out] Result in Montgomery form (a * R mod p)
 * @param a[in] Input value in normal form
 * @param params[in] Montgomery reduction parameters
 * @return int TORUS_SUCCESS on success, error code on failure
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API int to_montgomery(fp* result, const fp* a, const montgomery_params_t* params);

/**
 * @brief Convert from Montgomery form
 * 
 * @param result[out] Result in normal form (a * R^{-1} mod p)
 * @param a[in] Input value in Montgomery form
 * @param params[in] Montgomery reduction parameters
 * @return int TORUS_SUCCESS on success, error code on failure
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API int from_montgomery(fp* result, const fp* a, const montgomery_params_t* params);

/**
 * @brief Perform Montgomery reduction
 * 
 * @param result[out] Result of reduction (a * R^{-1} mod p)
 * @param a[in] Input value in Montgomery form (must be < p * R)
 * @param params[in] Montgomery reduction parameters
 * @return int TORUS_SUCCESS on success, error code on failure
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API int montgomery_reduce(fp* result, const fp* a, const montgomery_params_t* params);

/**
 * @brief Perform Montgomery multiplication (combines multiplication and reduction)
 * 
 * @param result[out] Result of multiplication and reduction (a * b * R^{-1} mod p)
 * @param a[in] First operand in Montgomery form
 * @param b[in] Second operand in Montgomery form
 * @param params[in] Montgomery reduction parameters
 * @return int TORUS_SUCCESS on success, error code on failure
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API int montgomery_multiply(fp* result, const fp* a, const fp* b, const montgomery_params_t* params);

/**
 * @brief Initialize CSIDH-specific reduction parameters
 * 
 * @param params[out] CSIDH reduction parameters to initialize
 * @param modulus[in] The modulus p
 * @param primes[in] Array of small primes
 * @param num_primes[in] Number of small primes
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int csidh_reduction_params_init(csidh_reduction_params_t* params, const fp* modulus, 
                                         const uint64_t* primes, uint32_t num_primes);

/**
 * @brief Specialized reduction for CSIDH primes
 * 
 * This function uses the special form of CSIDH primes (p = 4 * ∏ ℓ_i - 1)
 * for optimized reduction using the smoothness of p + 1.
 * 
 * @param result[out] Result of reduction (a mod p)
 * @param a[in] Input value to reduce
 * @param params[in] CSIDH reduction parameters
 * @return int TORUS_SUCCESS on success, error code on failure
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API int csidh_special_reduce(fp* result, const fp* a, const csidh_reduction_params_t* params);

/**
 * @brief Fast reduction for CSIDH primes using special form
 * 
 * Uses the fact that p = 4 * ∏ ℓ_i - 1 for faster reduction
 * by exploiting the smoothness of p + 1.
 * 
 * @param result[out] Result of reduction (a mod p)
 * @param a[in] Input value to reduce
 * @param params[in] CSIDH reduction parameters
 * @return int TORUS_SUCCESS on success, error code on failure
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API int csidh_fast_reduce(fp* result, const fp* a, const csidh_reduction_params_t* params);

/**
 * @brief Verify CSIDH reduction parameters
 * 
 * @param params[in] CSIDH reduction parameters to verify
 * @return int TORUS_SUCCESS if valid, error code otherwise
 */
TORUS_API int csidh_verify_params(const csidh_reduction_params_t* params);

/**
 * @brief Conditional subtraction of modulus
 * 
 * Performs: result = a - (condition ? modulus : 0)
 * 
 * @param result[out] Result of conditional subtraction
 * @param a[in] Input value
 * @param modulus[in] The modulus to conditionally subtract
 * @param condition[in] If true, subtract modulus
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API void fp_conditional_subtract(fp* result, const fp* a, const fp* modulus, uint64_t condition);

/**
 * @brief Conditional addition of modulus
 * 
 * Performs: result = a + (condition ? modulus : 0)
 * 
 * @param result[out] Result of conditional addition
 * @param a[in] Input value
 * @param modulus[in] The modulus to conditionally add
 * @param condition[in] If true, add modulus
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API void fp_conditional_add(fp* result, const fp* a, const fp* modulus, uint64_t condition);

/**
 * @brief Check if a value is greater than or equal to modulus
 * 
 * @param a[in] Value to check
 * @param modulus[in] The modulus
 * @return uint64_t 1 if a >= modulus, 0 otherwise
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API uint64_t fp_greater_or_equal(const fp* a, const fp* modulus);

/**
 * @brief Check if a value is less than modulus
 * 
 * @param a[in] Value to check
 * @param modulus[in] The modulus
 * @return uint64_t 1 if a < modulus, 0 otherwise
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API uint64_t fp_less_than(const fp* a, const fp* modulus);

/**
 * @brief Final reduction after arithmetic operations
 * 
 * Ensures the result is in the range [0, p-1] using constant-time operations.
 * 
 * @param a[in,out] Value to reduce (modified in place)
 * @param modulus[in] The modulus p
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API void fp_final_reduce(fp* a, const fp* modulus);

/**
 * @brief Reduce a value that is known to be in the range [0, 2p-1]
 * 
 * @param result[out] Result in range [0, p-1]
 * @param a[in] Input value in range [0, 2p-1]
 * @param modulus[in] The modulus p
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API void fp_reduce_once(fp* result, const fp* a, const fp* modulus);

/**
 * @brief Reduce a value that might be up to 3p-1
 * 
 * @param result[out] Result in range [0, p-1]
 * @param a[in] Input value up to 3p-1
 * @param modulus[in] The modulus p
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API void fp_reduce_twice(fp* result, const fp* a, const fp* modulus);

/**
 * @brief Get the number of bits in the modulus
 * 
 * @param modulus[in] The modulus
 * @return size_t Number of bits
 */
TORUS_API size_t fp_modulus_bits(const fp* modulus);

/**
 * @brief Get the number of limbs needed to represent the modulus
 * 
 * @param modulus[in] The modulus
 * @return size_t Number of limbs
 */
TORUS_API size_t fp_modulus_limbs(const fp* modulus);

/**
 * @brief Verify Barrett reduction parameters
 * 
 * @param params[in] Barrett parameters to verify
 * @return int TORUS_SUCCESS if valid, error code otherwise
 */
TORUS_API int barrett_verify_params(const barrett_params_t* params);

/**
 * @brief Verify Montgomery reduction parameters
 * 
 * @param params[in] Montgomery parameters to verify
 * @return int TORUS_SUCCESS if valid, error code otherwise
 */
TORUS_API int montgomery_verify_params(const montgomery_params_t* params);

/**
 * @brief Cleanup and zeroize reduction parameters
 * 
 * @param params[in] Parameters to cleanup
 */
TORUS_API void reduction_params_cleanup(void* params, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* MODULAR_REDUCTION_H */
