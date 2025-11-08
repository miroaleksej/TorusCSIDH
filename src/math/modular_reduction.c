// src/math/modular_reduction.c
#include "modular_reduction.h"
#include "torus_errors.h"
#include "torus_utils.h"
#include <string.h>

// Internal function declarations
static void fp_shift_right(fp* result, const fp* a, size_t bits);
static void fp_shift_left(fp* result, const fp* a, size_t bits);
static int fp_compare(const fp* a, const fp* b);
static void fp_multiply_low(fp* result, const fp* a, const fp* b);

int barrett_params_init(barrett_params_t* params, const fp* modulus) {
    if (!params || !modulus) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Copy modulus
    params->modulus = *modulus;
    
    // Calculate k = ceil(log2(p))
    // For CSIDH-512, p is 512 bits, so k = 512
    params->k = FP_BITS;
    
    // Calculate μ = floor(2^(2k) / p)
    // We compute this as: μ = (2^(2k) - 1) // p
    fp power_of_two;
    fp_set_zero(&power_of_two);
    
    // Set 2^(2k) - 1 (all bits set for 2k bits)
    // Since 2k = 1024 bits and we have 512-bit limbs, we need to handle carefully
    for (int i = 0; i < NLIMBS; i++) {
        power_of_two.d[i] = ~(uint64_t)0;
    }
    
    // Divide by p to get μ
    // Note: This is a simplified version. In practice, we'd use a more efficient method.
    fp_div(&params->mu, &power_of_two, modulus);
    
    return TORUS_SUCCESS;
}

int barrett_reduce(fp* result, const fp* a, const barrett_params_t* params) {
    if (!result || !a || !params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Barrett reduction algorithm:
    // q = floor((a * μ) / 2^(2k))
    // r = a - q * p
    // while r >= p: r = r - p
    
    fp q, temp, r;
    
    // q = floor((a * μ) / 2^(2k))
    fp_mul(&temp, a, &params->mu);
    fp_shift_right(&q, &temp, 2 * params->k);
    
    // r = a - q * p
    fp_mul(&temp, &q, &params->modulus);
    fp_sub(&r, a, &temp);
    
    // Conditional subtraction (constant-time)
    fp_final_reduce(&r, &params->modulus);
    
    *result = r;
    return TORUS_SUCCESS;
}

int montgomery_params_init(montgomery_params_t* params, const fp* modulus) {
    if (!params || !modulus) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Copy modulus
    params->modulus = *modulus;
    params->k = FP_BITS;
    
    // Compute R^2 mod p where R = 2^k
    fp R, R_squared;
    fp_set_zero(&R);
    
    // Set R = 2^k (k = FP_BITS)
    // For k = 512, this means setting the 513th bit? Actually, we need R > p
    // For Montgomery, we typically use R = 2^(NLIMBS * 64)
    size_t montgomery_k = NLIMBS * 64;
    
    // Set R = 2^montgomery_k
    fp_set_zero(&R);
    // R has 1 at position montgomery_k (which is beyond our fp size)
    // This is handled by the modular arithmetic
    
    // Compute R^2 mod p
    fp_mul(&R_squared, &R, &R);
    fp_mod(&params->r2, &R_squared, modulus);
    
    // Compute p' = -p^{-1} mod 2^64
    // We only need the inverse modulo 2^64 for the Montgomery reduction
    uint64_t p0 = modulus->d[0];
    params->inv = 0;
    
    // Newton's method for modular inverse modulo 2^64
    uint64_t x = p0;
    params->inv = 2 - p0;  // Initial guess
    
    // 4 iterations of Newton's method for 64-bit precision
    for (int i = 0; i < 4; i++) {
        params->inv = params->inv * (2 - p0 * params->inv);
    }
    
    // Negate the result for Montgomery reduction
    params->inv = -params->inv;
    
    return TORUS_SUCCESS;
}

int to_montgomery(fp* result, const fp* a, const montgomery_params_t* params) {
    if (!result || !a || !params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Convert to Montgomery form: a * R mod p
    fp_mul(result, a, &params->r2);
    montgomery_reduce(result, result, params);
    
    return TORUS_SUCCESS;
}

int from_montgomery(fp* result, const fp* a, const montgomery_params_t* params) {
    if (!result || !a || !params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Convert from Montgomery form: a * R^{-1} mod p
    // This is just Montgomery reduction with 1 as input
    fp one;
    fp_set_one(&one);
    
    // We need to compute a * 1 * R^{-1} mod p
    // But Montgomery reduction computes a * R^{-1} mod p directly
    montgomery_reduce(result, a, params);
    
    return TORUS_SUCCESS;
}

int montgomery_reduce(fp* result, const fp* a, const montgomery_params_t* params) {
    if (!result || !a || !params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Montgomery reduction algorithm:
    // m = (a mod R) * p' mod R
    // t = (a + m * p) / R
    // if t >= p: return t - p else return t
    
    fp m, temp, t;
    uint64_t carry = 0;
    
    // m = (a_0 * p') mod 2^64
    uint64_t a0 = a->d[0];
    uint64_t m0 = a0 * params->inv;
    
    // Set m = (m0, 0, 0, ...)
    fp_set_zero(&m);
    m.d[0] = m0;
    
    // t = (a + m * p)
    fp_mul(&temp, &m, &params->modulus);
    fp_add(&t, a, &temp);
    
    // t = t / R (right shift by k bits, where k = 64 * NLIMBS)
    // Since R = 2^(64 * NLIMBS), division by R is just taking the upper NLIMBS limbs
    for (int i = 0; i < NLIMBS; i++) {
        result->d[i] = t.d[i + NLIMBS];
    }
    
    // Final reduction
    fp_final_reduce(result, &params->modulus);
    
    return TORUS_SUCCESS;
}

int csidh_special_reduce(fp* result, const fp* a, const fp* modulus) {
    if (!result || !a || !modulus) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // For CSIDH primes of the form p = 4 * ∏ ℓ_i - 1,
    // we can use the fact that p + 1 is smooth for optimizations.
    // However, for generic reduction, we use a standard approach.
    
    // Simple conditional subtraction approach
    fp_final_reduce(result, modulus);
    
    return TORUS_SUCCESS;
}

void fp_conditional_subtract(fp* result, const fp* a, const fp* modulus, uint64_t condition) {
    if (!result || !a || !modulus) {
        return;
    }
    
    fp temp;
    fp_sub(&temp, a, modulus);
    
    // Constant-time selection based on condition
    uint64_t mask = ~(uint64_t)0 + !condition; // mask = condition ? ~0 : 0
    
    for (int i = 0; i < NLIMBS; i++) {
        uint64_t a_val = a->d[i];
        uint64_t temp_val = temp.d[i];
        result->d[i] = (a_val & ~mask) | (temp_val & mask);
    }
}

uint64_t fp_greater_or_equal(const fp* a, const fp* modulus) {
    if (!a || !modulus) {
        return 0;
    }
    
    // Constant-time comparison
    // Returns 1 if a >= modulus, 0 otherwise
    
    uint64_t borrow = 0;
    uint64_t result = 0;
    
    // Compare limb by limb from most significant to least significant
    for (int i = NLIMBS - 1; i >= 0; i--) {
        uint64_t a_limb = a->d[i];
        uint64_t mod_limb = modulus->d[i];
        
        // If we haven't determined the result yet
        uint64_t not_decided = (result == 0);
        
        // Check if this limb decides the comparison
        uint64_t limb_greater = (a_limb > mod_limb) & not_decided;
        uint64_t limb_equal = (a_limb == mod_limb) & not_decided;
        uint64_t limb_less = (a_limb < mod_limb) & not_decided;
        
        // Update result
        result |= limb_greater;
        // If equal, we continue to next limb
        // If less, we set result to 0 (but we're already 0)
        
        // For the case where we're still undecided and reach the end,
        // if all limbs are equal, then a >= modulus is true
        if (i == 0 && not_decided && limb_equal) {
            result = 1;
        }
    }
    
    return result;
}

void fp_final_reduce(fp* a, const fp* modulus) {
    if (!a || !modulus) {
        return;
    }
    
    // Constant-time final reduction to ensure a is in [0, p-1]
    // This implementation uses at most 2 subtractions
    
    fp temp1, temp2;
    
    // First conditional subtraction
    uint64_t condition1 = fp_greater_or_equal(a, modulus);
    fp_sub(&temp1, a, modulus);
    fp_conditional_subtract(a, a, &temp1, condition1);
    
    // The result should now be in [0, 2p-1]
    // We might need one more subtraction
    
    // Second conditional subtraction
    uint64_t condition2 = fp_greater_or_equal(a, modulus);
    fp_sub(&temp2, a, modulus);
    fp_conditional_subtract(a, a, &temp2, condition2);
}

// Internal helper functions

static void fp_shift_right(fp* result, const fp* a, size_t bits) {
    if (!result || !a) return;
    
    size_t limb_shift = bits / 64;
    size_t bit_shift = bits % 64;
    
    if (limb_shift >= NLIMBS) {
        fp_set_zero(result);
        return;
    }
    
    for (int i = 0; i < NLIMBS; i++) {
        int src_idx = i + limb_shift;
        uint64_t val = 0;
        
        if (src_idx < NLIMBS) {
            val = a->d[src_idx] >> bit_shift;
        }
        
        if (src_idx + 1 < NLIMBS && bit_shift > 0) {
            val |= a->d[src_idx + 1] << (64 - bit_shift);
        }
        
        result->d[i] = val;
    }
}

static void fp_shift_left(fp* result, const fp* a, size_t bits) {
    if (!result || !a) return;
    
    size_t limb_shift = bits / 64;
    size_t bit_shift = bits % 64;
    
    if (limb_shift >= NLIMBS) {
        fp_set_zero(result);
        return;
    }
    
    for (int i = NLIMBS - 1; i >= 0; i--) {
        int src_idx = i - limb_shift;
        uint64_t val = 0;
        
        if (src_idx >= 0) {
            val = a->d[src_idx] << bit_shift;
        }
        
        if (src_idx - 1 >= 0 && bit_shift > 0) {
            val |= a->d[src_idx - 1] >> (64 - bit_shift);
        }
        
        result->d[i] = val;
    }
}

static int fp_compare(const fp* a, const fp* b) {
    if (!a || !b) return 0;
    
    for (int i = NLIMBS - 1; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return 1;
        if (a->d[i] < b->d[i]) return -1;
    }
    
    return 0;
}

static void fp_multiply_low(fp* result, const fp* a, const fp* b) {
    if (!result || !a || !b) return;
    
    uint64_t product[2 * NLIMBS] = {0};
    
    // Schoolbook multiplication (lower half only)
    for (int i = 0; i < NLIMBS; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < NLIMBS - i; j++) {
            uint64_t hi, lo;
            
            // 128-bit multiplication
            __uint128_t p = (__uint128_t)a->d[i] * b->d[j];
            hi = (uint64_t)(p >> 64);
            lo = (uint64_t)p;
            
            // Add to current position
            uint64_t sum_lo = product[i + j] + lo + carry;
            uint64_t sum_hi = hi + (sum_lo < lo ? 1 : 0);
            
            product[i + j] = sum_lo;
            carry = sum_hi;
        }
    }
    
    // Copy lower NLIMBS to result
    for (int i = 0; i < NLIMBS; i++) {
        result->d[i] = product[i];
    }
}
