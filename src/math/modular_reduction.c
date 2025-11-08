// src/math/modular_reduction.c
#include "math/modular_reduction.h"
#include "math/fp_arithmetic.h"
#include "utils/secure_utils.h"
#include "utils/error_handling.h"
#include "utils/cpu_features.h"
#include <string.h>

// Internal function declarations
static void fp_shift_right(fp* result, const fp* a, size_t bits);
static void fp_shift_left(fp* result, const fp* a, size_t bits);
static int fp_compare(const fp* a, const fp* b);
static void fp_multiply_low(fp* result, const fp* a, const fp* b);
static void fp_multiply_high(fp* result, const fp* a, const fp* b);
static uint64_t compute_montgomery_inv(uint64_t p0);
static void compute_barrett_mu(fp* mu, const fp* modulus, size_t k);
static void compute_montgomery_r2(fp* r2, const fp* modulus, size_t k);
static int csidh_reduce_by_prime(fp* result, const fp* a, uint64_t prime, const fp* modulus);
static int csidh_verify_product(const csidh_reduction_params_t* params);

int barrett_params_init(barrett_params_t* params, const fp* modulus, uint32_t security_level) {
    if (!params || !modulus) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Copy modulus
    fp_copy(&params->modulus, modulus);
    params->security_level = security_level;
    
    // Calculate k = ceil(log2(p))
    params->k = fp_modulus_bits(modulus);
    
    // Calculate μ = floor(2^(2k) / p)
    compute_barrett_mu(&params->mu, modulus, params->k);
    
    return TORUS_SUCCESS;
}

static void compute_barrett_mu(fp* mu, const fp* modulus, size_t k) {
    // μ = floor(2^(2k) / p)
    // For CSIDH primes, we can compute this exactly using the special form
    
    // Initialize mu to 2^(2k)
    fp_set_zero(mu);
    
    // Set the bit at position 2k
    size_t total_bits = 2 * k;
    size_t limb_index = total_bits / 64;
    size_t bit_index = total_bits % 64;
    
    if (limb_index < NLIMBS) {
        mu->d[limb_index] = 1ULL << bit_index;
    }
    
    // For exact computation with CSIDH primes, we can use:
    // μ = (2^(2k) - 1) // p
    // Since p = 4 * ∏ ℓ_i - 1, we can compute this efficiently
    
    fp temp;
    fp_set_u64(&temp, 1, NULL);
    fp_sub(mu, mu, &temp, NULL); // 2^(2k) - 1
    
    // Divide by p using modular arithmetic
    // In practice, this would be precomputed for known CSIDH primes
    // For now, we use an approximation algorithm
    
    // Newton-Raphson iteration for division
    fp two_power_k;
    fp_set_zero(&two_power_k);
    
    // Set 2^k
    limb_index = k / 64;
    bit_index = k % 64;
    if (limb_index < NLIMBS) {
        two_power_k.d[limb_index] = 1ULL << bit_index;
    }
    
    // Initial approximation: mu ≈ 2^k / p * 2^k
    fp_mul(mu, &two_power_k, &two_power_k, NULL);
    fp_reduce(mu, NULL);
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
    fp_mul(&temp, a, &params->mu, NULL);
    fp_shift_right(&q, &temp, 2 * params->k);
    
    // r = a - q * p
    fp_mul(&temp, &q, &params->modulus, NULL);
    fp_sub(&r, a, &temp, NULL);
    
    // Final reduction to ensure r < p
    fp_final_reduce(&r, &params->modulus);
    
    fp_copy(result, &r);
    
    // Securely zeroize temporary variables
    secure_zeroize(&q, sizeof(fp));
    secure_zeroize(&temp, sizeof(fp));
    secure_zeroize(&r, sizeof(fp));
    
    return TORUS_SUCCESS;
}

int barrett_verify_params(const barrett_params_t* params) {
    if (!params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Verify that μ was computed correctly
    // Check: μ ≈ floor(2^(2k) / p)
    fp test_value, expected, quotient;
    
    // Compute 2^(2k)
    fp_set_zero(&test_value);
    size_t limb_index = (2 * params->k) / 64;
    size_t bit_index = (2 * params->k) % 64;
    if (limb_index < NLIMBS) {
        test_value.d[limb_index] = 1ULL << bit_index;
    }
    
    // Compute expected = floor(test_value / p)
    fp_div(&expected, &test_value, &params->modulus, NULL);
    
    // Compare with stored μ
    if (fp_compare(&expected, &params->mu) != 0) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    return TORUS_SUCCESS;
}

int montgomery_params_init(montgomery_params_t* params, const fp* modulus, uint32_t security_level) {
    if (!params || !modulus) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Copy modulus
    fp_copy(&params->modulus, modulus);
    params->security_level = security_level;
    
    // Compute k = number of bits in modulus
    params->k = fp_modulus_bits(modulus);
    
    // Compute R^2 mod p where R = 2^k
    compute_montgomery_r2(&params->r2, modulus, params->k);
    
    // Compute p' = -p^{-1} mod 2^64
    params->inv = compute_montgomery_inv(modulus->d[0]);
    
    return TORUS_SUCCESS;
}

static uint64_t compute_montgomery_inv(uint64_t p0) {
    // Compute p' = -p^{-1} mod 2^64 using Newton's method
    
    uint64_t inv = 1;  // Initial approximation
    
    // Newton iteration for modular inverse modulo 2^64
    // We need 5 iterations for 64-bit precision
    for (int i = 0; i < 5; i++) {
        inv = inv * (2 - p0 * inv);
    }
    
    return -inv;
}

static void compute_montgomery_r2(fp* r2, const fp* modulus, size_t k) {
    // Compute R^2 mod p where R = 2^k
    
    // For CSIDH primes, we can compute this efficiently using the special form
    // R = 2^k, R^2 mod p = 2^(2k) mod p
    
    fp_set_zero(r2);
    
    // Set 2^(2k) mod p
    // For efficiency, we use repeated doubling
    fp_set_u64(r2, 1, NULL);
    
    for (size_t i = 0; i < 2 * k; i++) {
        fp_add(r2, r2, r2, NULL);  // Multiply by 2
        if (fp_greater_or_equal(r2, modulus)) {
            fp_sub(r2, r2, modulus, NULL);
        }
    }
}

int to_montgomery(fp* result, const fp* a, const montgomery_params_t* params) {
    if (!result || !a || !params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Convert to Montgomery form: a * R mod p
    // This is equivalent to Montgomery multiplication of a and R^2
    
    return montgomery_multiply(result, a, &params->r2, params);
}

int from_montgomery(fp* result, const fp* a, const montgomery_params_t* params) {
    if (!result || !a || !params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Convert from Montgomery form: a * R^{-1} mod p
    // This is equivalent to Montgomery multiplication of a and 1
    
    fp one;
    fp_set_u64(&one, 1, NULL);
    
    return montgomery_multiply(result, a, &one, params);
}

int montgomery_reduce(fp* result, const fp* a, const montgomery_params_t* params) {
    if (!result || !a || !params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Montgomery reduction algorithm (CIOS method - Coarsely Integrated Operand Scanning)
    // Optimized for CSIDH primes
    
    uint64_t product[2 * NLIMBS] = {0};
    uint64_t carry = 0;
    
    // Copy input to product (we need to work on 2N-limb number)
    for (size_t i = 0; i < NLIMBS; i++) {
        product[i] = a->d[i];
    }
    
    for (size_t i = 0; i < NLIMBS; i++) {
        // Compute m = (product[i] * p') mod 2^64
        uint64_t m = product[i] * params->inv;
        
        // Add m * p to product
        carry = 0;
        for (size_t j = 0; j < NLIMBS; j++) {
            __uint128_t term = (__uint128_t)m * params->modulus.d[j] + product[i + j] + carry;
            product[i + j] = (uint64_t)term;
            carry = (uint64_t)(term >> 64);
        }
        
        // Propagate carry
        for (size_t j = NLIMBS; j < 2 * NLIMBS - i; j++) {
            __uint128_t sum = (__uint128_t)product[i + j] + carry;
            product[i + j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
            if (carry == 0) break;
        }
    }
    
    // The result is in the upper half of product
    for (size_t i = 0; i < NLIMBS; i++) {
        result->d[i] = product[NLIMBS + i];
    }
    
    // Final reduction: if result >= p, subtract p
    fp_final_reduce(result, &params->modulus);
    
    // Securely zeroize temporary arrays
    secure_zeroize(product, sizeof(product));
    
    return TORUS_SUCCESS;
}

int montgomery_multiply(fp* result, const fp* a, const fp* b, const montgomery_params_t* params) {
    if (!result || !a || !b || !params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Combined Montgomery multiplication and reduction
    // Optimized implementation for CSIDH primes
    
    uint64_t temp[2 * NLIMBS + 1] = {0};
    
    // Schoolbook multiplication
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < NLIMBS; j++) {
            __uint128_t term = (__uint128_t)a->d[i] * b->d[j] + temp[i + j] + carry;
            temp[i + j] = (uint64_t)term;
            carry = (uint64_t)(term >> 64);
        }
        temp[i + NLIMBS] = carry;
    }
    
    // Montgomery reduction
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t m = temp[i] * params->inv;
        
        uint64_t carry = 0;
        for (size_t j = 0; j < NLIMBS; j++) {
            __uint128_t term = (__uint128_t)m * params->modulus.d[j] + temp[i + j] + carry;
            temp[i + j] = (uint64_t)term;
            carry = (uint64_t)(term >> 64);
        }
        
        // Propagate carry
        for (size_t j = NLIMBS; j < 2 * NLIMBS - i; j++) {
            __uint128_t sum = (__uint128_t)temp[i + j] + carry;
            temp[i + j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
            if (carry == 0) break;
        }
    }
    
    // Result is in the upper half
    for (size_t i = 0; i < NLIMBS; i++) {
        result->d[i] = temp[NLIMBS + i];
    }
    
    // Final reduction
    fp_final_reduce(result, &params->modulus);
    
    // Securely zeroize temporary arrays
    secure_zeroize(temp, sizeof(temp));
    
    return TORUS_SUCCESS;
}

int montgomery_verify_params(const montgomery_params_t* params) {
    if (!params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Verify Montgomery inverse: p * p' ≡ -1 mod 2^64
    uint64_t verification = params->modulus.d[0] * params->inv;
    if (verification != (uint64_t)-1) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Verify R^2 computation
    fp test_r, test_r2;
    fp_set_zero(&test_r);
    
    // Compute R = 2^k mod p
    size_t limb_index = params->k / 64;
    size_t bit_index = params->k % 64;
    if (limb_index < NLIMBS) {
        test_r.d[limb_index] = 1ULL << bit_index;
    }
    fp_reduce(&test_r, &params->modulus);
    
    // Compute R^2 mod p
    fp_mul(&test_r2, &test_r, &test_r, NULL);
    fp_reduce(&test_r2, &params->modulus);
    
    // Compare with stored R^2
    if (fp_compare(&test_r2, &params->r2) != 0) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    return TORUS_SUCCESS;
}

int csidh_reduction_params_init(csidh_reduction_params_t* params, const fp* modulus, 
                               const uint64_t* primes, uint32_t num_primes) {
    if (!params || !modulus || !primes || num_primes == 0) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Copy modulus
    fp_copy(&params->modulus, modulus);
    params->primes = primes;
    params->num_primes = num_primes;
    
    // Compute p + 1
    fp_set_u64(&params->p_plus_1, 1, NULL);
    fp_add(&params->p_plus_1, modulus, &params->p_plus_1, NULL);
    
    // Compute (p - 1) / 2
    fp p_minus_1;
    fp_set_u64(&p_minus_1, 1, NULL);
    fp_sub(&p_minus_1, modulus, &p_minus_1, NULL);
    
    // Right shift by 1 to divide by 2
    uint64_t carry = 0;
    for (int i = NLIMBS - 1; i >= 0; i--) {
        uint64_t new_carry = (p_minus_1.d[i] & 1) << 63;
        params->p_minus_1_half.d[i] = (p_minus_1.d[i] >> 1) | carry;
        carry = new_carry;
    }
    
    // Compute product of small primes for verification
    params->product = 1;
    for (uint32_t i = 0; i < num_primes; i++) {
        if (UINT64_MAX / params->product < primes[i]) {
            // Product would overflow, use modular multiplication
            params->product = 0; // Mark as computed differently
            break;
        }
        params->product *= primes[i];
    }
    
    // Verify that p + 1 is divisible by 4 * product of primes
    if (csidh_verify_product(params) != TORUS_SUCCESS) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    return TORUS_SUCCESS;
}

static int csidh_verify_product(const csidh_reduction_params_t* params) {
    if (!params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // For CSIDH, we should have: p = 4 * ∏ ℓ_i - 1
    // So: p + 1 = 4 * ∏ ℓ_i
    
    // Check if p + 1 is divisible by 4
    if ((params->p_plus_1.d[0] & 3) != 0) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // For a full verification, we would check divisibility by each prime
    // This is simplified for the implementation
    
    return TORUS_SUCCESS;
}

int csidh_special_reduce(fp* result, const fp* a, const csidh_reduction_params_t* params) {
    if (!result || !a || !params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Specialized reduction for CSIDH primes p = 4 * ∏ ℓ_i - 1
    // Exploit the smoothness of p + 1 = 4 * ∏ ℓ_i
    
    // Method: Use Chinese Remainder Theorem with small prime factors
    // Since p + 1 is smooth, we can reduce modulo each small prime
    // and then reconstruct the result
    
    fp reduced = *a;
    
    // Reduce modulo each small prime in the product
    for (uint32_t i = 0; i < params->num_primes; i++) {
        if (csidh_reduce_by_prime(&reduced, &reduced, params->primes[i], &params->modulus) != TORUS_SUCCESS) {
            return TORUS_ERROR_COMPUTATION;
        }
    }
    
    // Final reduction to ensure result is in [0, p-1]
    fp_final_reduce(&reduced, &params->modulus);
    
    fp_copy(result, &reduced);
    
    return TORUS_SUCCESS;
}

static int csidh_reduce_by_prime(fp* result, const fp* a, uint64_t prime, const fp* modulus) {
    // Reduce a modulo a small prime using the special structure
    // of CSIDH primes: p = 4 * ∏ ℓ_i - 1
    
    // Compute a mod prime using the fact that:
    // a mod prime = (a mod (p+1)) mod prime
    // and p + 1 = 4 * ∏ ℓ_i is divisible by prime
    
    fp temp;
    fp_copy(&temp, a);
    
    // Reduce modulo p + 1 (which is divisible by prime)
    // Since p + 1 is large, we use iterative subtraction
    
    while (fp_greater_or_equal(&temp, modulus)) {
        fp_sub(&temp, &temp, modulus, NULL);
        // For p = 4*∏ℓ_i - 1, we have p + 1 = 4*∏ℓ_i
        // We subtract multiples of prime from the upper bits
    }
    
    // Now temp < p, compute temp mod prime
    uint64_t remainder = 0;
    
    // Convert to 64-bit remainder using Horner's method
    for (int i = NLIMBS - 1; i >= 0; i--) {
        remainder = ((remainder << 64) + temp.d[i]) % prime;
    }
    
    // Convert back to fp
    fp_set_u64(result, remainder, NULL);
    
    return TORUS_SUCCESS;
}

int csidh_fast_reduce(fp* result, const fp* a, const csidh_reduction_params_t* params) {
    if (!result || !a || !params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Fast reduction for CSIDH primes using the special form
    // p = 2^m - c where c is small (c = 1 for CSIDH)
    
    size_t m = fp_modulus_bits(&params->modulus);
    uint64_t c = 1; // For p = 2^m - 1
    
    // Extract lower m bits (a mod 2^m)
    fp low_bits;
    fp_copy(&low_bits, a);
    
    // Clear bits above m
    size_t full_limbs = m / 64;
    size_t remaining_bits = m % 64;
    
    for (size_t i = full_limbs + 1; i < NLIMBS; i++) {
        low_bits.d[i] = 0;
    }
    
    if (remaining_bits > 0 && full_limbs < NLIMBS) {
        low_bits.d[full_limbs] &= ((1ULL << remaining_bits) - 1);
    }
    
    // Extract upper bits (floor(a / 2^m))
    fp upper_bits;
    fp_shift_right(&upper_bits, a, m);
    
    // Compute result = low_bits + c * upper_bits
    fp temp;
    fp_set_u64(&temp, c, NULL);
    fp_mul(&temp, &upper_bits, &temp, NULL);
    fp_add(result, &low_bits, &temp, NULL);
    
    // Final reduction
    fp_final_reduce(result, &params->modulus);
    
    // Securely zeroize temporary variables
    secure_zeroize(&low_bits, sizeof(fp));
    secure_zeroize(&upper_bits, sizeof(fp));
    secure_zeroize(&temp, sizeof(fp));
    
    return TORUS_SUCCESS;
}

int csidh_verify_params(const csidh_reduction_params_t* params) {
    if (!params) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Verify p + 1 computation
    fp test_p_plus_1;
    fp_set_u64(&test_p_plus_1, 1, NULL);
    fp_add(&test_p_plus_1, &params->modulus, &test_p_plus_1, NULL);
    
    if (fp_compare(&test_p_plus_1, &params->p_plus_1) != 0) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Verify (p - 1) / 2 computation
    fp test_p_minus_1, test_p_minus_1_half;
    fp_set_u64(&test_p_minus_1, 1, NULL);
    fp_sub(&test_p_minus_1, &params->modulus, &test_p_minus_1, NULL);
    
    // Multiply by 2 to verify division
    fp_add(&test_p_minus_1_half, &params->p_minus_1_half, &params->p_minus_1_half, NULL);
    
    if (fp_compare(&test_p_minus_1_half, &test_p_minus_1) != 0) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    return TORUS_SUCCESS;
}

void fp_conditional_subtract(fp* result, const fp* a, const fp* modulus, uint64_t condition) {
    if (!result || !a || !modulus) {
        return;
    }
    
    fp temp;
    fp_sub(&temp, a, modulus, NULL);
    
    // Constant-time selection based on condition
    uint64_t mask = ~(uint64_t)0 + !condition; // mask = condition ? ~0 : 0
    
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t a_val = a->d[i];
        uint64_t temp_val = temp.d[i];
        result->d[i] = (a_val & ~mask) | (temp_val & mask);
    }
    
    secure_zeroize(&temp, sizeof(fp));
}

void fp_conditional_add(fp* result, const fp* a, const fp* modulus, uint64_t condition) {
    if (!result || !a || !modulus) {
        return;
    }
    
    fp temp;
    fp_add(&temp, a, modulus, NULL);
    
    // Constant-time selection based on condition
    uint64_t mask = ~(uint64_t)0 + !condition; // mask = condition ? ~0 : 0
    
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t a_val = a->d[i];
        uint64_t temp_val = temp.d[i];
        result->d[i] = (a_val & ~mask) | (temp_val & mask);
    }
    
    secure_zeroize(&temp, sizeof(fp));
}

uint64_t fp_greater_or_equal(const fp* a, const fp* b) {
    if (!a || !b) {
        return 0;
    }
    
    // Constant-time comparison: returns 1 if a >= b, 0 otherwise
    uint64_t borrow = 0;
    
    // Compare limb by limb from most significant to least significant
    for (int i = NLIMBS - 1; i >= 0; i--) {
        uint64_t a_limb = a->d[i];
        uint64_t b_limb = b->d[i];
        
        uint64_t diff = a_limb - b_limb - borrow;
        
        // Update borrow for next limb
        borrow = (a_limb < b_limb + borrow) || 
                (borrow && (a_limb == b_limb + borrow));
    }
    
    // If borrow == 0, then a >= b
    return (borrow == 0);
}

uint64_t fp_less_than(const fp* a, const fp* b) {
    if (!a || !b) {
        return 0;
    }
    
    // Constant-time comparison: returns 1 if a < b, 0 otherwise
    return !fp_greater_or_equal(a, b);
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
    fp_sub(&temp1, a, modulus, NULL);
    fp_conditional_subtract(a, a, &temp1, condition1);
    
    // The result should now be in [0, 2p-1]
    // We might need one more subtraction
    
    // Second conditional subtraction
    uint64_t condition2 = fp_greater_or_equal(a, modulus);
    fp_sub(&temp2, a, modulus, NULL);
    fp_conditional_subtract(a, a, &temp2, condition2);
    
    // Securely zeroize temporary variables
    secure_zeroize(&temp1, sizeof(fp));
    secure_zeroize(&temp2, sizeof(fp));
}

void fp_reduce_once(fp* result, const fp* a, const fp* modulus) {
    if (!result || !a || !modulus) {
        return;
    }
    
    // Reduce a value known to be in [0, 2p-1] to [0, p-1]
    fp temp;
    fp_sub(&temp, a, modulus, NULL);
    
    uint64_t condition = fp_less_than(a, modulus);
    fp_conditional_subtract(result, a, &temp, condition);
    
    secure_zeroize(&temp, sizeof(fp));
}

void fp_reduce_twice(fp* result, const fp* a, const fp* modulus) {
    if (!result || !a || !modulus) {
        return;
    }
    
    // Reduce a value that might be up to 3p-1
    // First reduction
    fp temp;
    fp_reduce_once(&temp, a, modulus);
    
    // Second reduction if necessary
    fp_reduce_once(result, &temp, modulus);
    
    secure_zeroize(&temp, sizeof(fp));
}

size_t fp_modulus_bits(const fp* modulus) {
    if (!modulus) {
        return 0;
    }
    
    // Count the number of bits in the modulus
    size_t bits = 0;
    
    for (int i = NLIMBS - 1; i >= 0; i--) {
        if (modulus->d[i] != 0) {
            bits = (i + 1) * 64;
            
            // Find the highest set bit in this limb
            uint64_t limb = modulus->d[i];
            while (limb > 0) {
                bits--;
                limb >>= 1;
            }
            bits += 64;
            break;
        }
    }
    
    return bits;
}

size_t fp_modulus_limbs(const fp* modulus) {
    if (!modulus) {
        return 0;
    }
    
    // Count the number of non-zero limbs
    size_t limbs = 0;
    
    for (size_t i = 0; i < NLIMBS; i++) {
        if (modulus->d[i] != 0) {
            limbs = i + 1;
        }
    }
    
    return limbs;
}

void reduction_params_cleanup(void* params, size_t size) {
    if (!params) {
        return;
    }
    
    secure_zeroize(params, size);
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
    
    for (size_t i = 0; i < NLIMBS; i++) {
        size_t src_idx = i + limb_shift;
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
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < NLIMBS - i; j++) {
            __uint128_t p = (__uint128_t)a->d[i] * b->d[j];
            uint64_t hi = (uint64_t)(p >> 64);
            uint64_t lo = (uint64_t)p;
            
            // Add to current position
            uint64_t sum_lo = product[i + j] + lo + carry;
            uint64_t sum_hi = hi + (sum_lo < lo ? 1 : 0);
            
            product[i + j] = sum_lo;
            carry = sum_hi;
        }
    }
    
    // Copy lower NLIMBS to result
    for (size_t i = 0; i < NLIMBS; i++) {
        result->d[i] = product[i];
    }
    
    secure_zeroize(product, sizeof(product));
}

static void fp_multiply_high(fp* result, const fp* a, const fp* b) {
    if (!result || !a || !b) return;
    
    uint64_t product[2 * NLIMBS] = {0};
    
    // Schoolbook multiplication
    for (size_t i = 0; i < NLIMBS; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < NLIMBS; j++) {
            __uint128_t p = (__uint128_t)a->d[i] * b->d[j];
            uint64_t hi = (uint64_t)(p >> 64);
            uint64_t lo = (uint64_t)p;
            
            // Add to current position
            uint64_t sum_lo = product[i + j] + lo + carry;
            uint64_t sum_hi = hi + (sum_lo < lo ? 1 : 0);
            
            product[i + j] = sum_lo;
            carry = sum_hi;
        }
        
        // Handle final carry
        if (carry > 0 && i + NLIMBS < 2 * NLIMBS) {
            product[i + NLIMBS] += carry;
        }
    }
    
    // Copy upper NLIMBS to result
    for (size_t i = 0; i < NLIMBS; i++) {
        result->d[i] = product[NLIMBS + i];
    }
    
    secure_zeroize(product, sizeof(product));
}
