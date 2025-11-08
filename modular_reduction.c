// src/math/modular_reduction.h
#ifndef MODULAR_REDUCTION_H
#define MODULAR_REDUCTION_H

#include "fp.h"
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
} barrett_params_t;

/**
 * @brief Montgomery reduction parameters  
 */
typedef struct {
    fp modulus;           ///< The modulus p
    fp r2;                ///< R^2 mod p where R = 2^k
    uint64_t inv;         ///< p' = -p^{-1} mod 2^64
    size_t k;             ///< k = number of bits in modulus
} montgomery_params_t;

/**
 * @brief Initialize Barrett reduction parameters
 * 
 * @param params[out] Barrett parameters to initialize
 * @param modulus[in] The modulus p
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int barrett_params_init(barrett_params_t* params, const fp* modulus);

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
 * @return int TORUS_SUCCESS on success, error code on failure
 */
TORUS_API int montgomery_params_init(montgomery_params_t* params, const fp* modulus);

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
 * @brief Specialized reduction for CSIDH primes
 * 
 * This function uses the special form of CSIDH primes (p = 4 * ∏ ℓ_i - 1)
 * for optimized reduction.
 * 
 * @param result[out] Result of reduction (a mod p)
 * @param a[in] Input value to reduce
 * @param modulus[in] The modulus p
 * @return int TORUS_SUCCESS on success, error code on failure
 * 
 * @constant_time This function executes in constant time
 */
TORUS_API int csidh_special_reduce(fp* result, const fp* a, const fp* modulus);

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

#ifdef __cplusplus
}
#endif

#endif /* MODULAR_REDUCTION_H */
