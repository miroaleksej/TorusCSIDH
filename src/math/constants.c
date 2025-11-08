// src/math/constants.c
#include "math/constants.h"
#include "math/fp_arithmetic.h"
#include "math/fp2_arithmetic.h"
#include "math/modular_reduction.h"
#include "utils/secure_utils.h"
#include "utils/error_handling.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Internal Data Structures
// ============================================================================

// Security level 128 parameters (CSIDH-512)
static const uint64_t PRIMES_128[] = {
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
    61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
    131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
    193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
    263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
    337, 347, 349, 353, 359, 367, 373, 587
};

static const int64_t EXPONENTS_128[] = {
    5, 4, 3, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

// CSIDH-512 prime: p = 4 * (3 * 5 * ... * 373 * 587) - 1
static const char* PRIME_128_HEX = 
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7";

// Security level 192 parameters (CSIDH-768)
static const uint64_t PRIMES_192[] = {
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
    61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
    131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
    193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
    263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
    337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401,
    409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
    479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563,
    569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631
};

static const int64_t EXPONENTS_192[] = {
    7, 6, 5, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2
};

static const char* PRIME_192_HEX = 
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

// Security level 256 parameters (CSIDH-1024)
static const uint64_t PRIMES_256[] = {
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
    61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
    131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
    193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
    263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
    337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401,
    409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
    479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563,
    569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631,
    641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709,
    719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797
};

static const int64_t EXPONENTS_256[] = {
    9, 8, 7, 6, 6, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4
};

// ============================================================================
// Fundamental Constants
// ============================================================================

const fp FP_ZERO = {{0}};
const fp FP_ONE = {{1, 0, 0, 0, 0, 0, 0, 0}};
const fp FP_TWO = {{2, 0, 0, 0, 0, 0, 0, 0}};
const fp FP_THREE = {{3, 0, 0, 0, 0, 0, 0, 0}};
const fp FP_FOUR = {{4, 0, 0, 0, 0, 0, 0, 0}};
const fp FP_EIGHT = {{8, 0, 0, 0, 0, 0, 0, 0}};

// Fp2 constants
const fp2 FP2_ZERO = {{{0}}, {{0}}};
const fp2 FP2_ONE = {{{1, 0, 0, 0, 0, 0, 0, 0}}, {{0}}};
const fp2 FP2_I = {{{0}}, {{1, 0, 0, 0, 0, 0, 0, 0}}};
const fp2 FP2_MINUS_ONE = {{{0}}}; // Will be initialized
const fp2 FP2_MINUS_I = {{{0}}};   // Will be initialized

// ============================================================================
// Security Parameters
// ============================================================================

static security_params_t SECURITY_PARAMS_128 = {
    .level_bits = 128,
    .p_bits = 512,
    .num_primes = sizeof(PRIMES_128) / sizeof(PRIMES_128[0]),
    .max_exponent = 5,
    .total_bits = 256,
    .primes = PRIMES_128,
    .exponents = EXPONENTS_128,
    .prime_hex = PRIME_128_HEX
};

static security_params_t SECURITY_PARAMS_192 = {
    .level_bits = 192,
    .p_bits = 768,
    .num_primes = sizeof(PRIMES_192) / sizeof(PRIMES_192[0]),
    .max_exponent = 7,
    .total_bits = 384,
    .primes = PRIMES_192,
    .exponents = EXPONENTS_192,
    .prime_hex = PRIME_192_HEX
};

static security_params_t SECURITY_PARAMS_256 = {
    .level_bits = 256,
    .p_bits = 1024,
    .num_primes = sizeof(PRIMES_256) / sizeof(PRIMES_256[0]),
    .max_exponent = 9,
    .total_bits = 512,
    .primes = PRIMES_256,
    .exponents = EXPONENTS_256,
    .prime_hex = NULL // Will be computed
};

// ============================================================================
// Prime Field Constants
// ============================================================================

static prime_constants_t PRIME_CONSTANTS_128 = {0};
static prime_constants_t PRIME_CONSTANTS_192 = {0};
static prime_constants_t PRIME_CONSTANTS_256 = {0};

// ============================================================================
// Curve Constants
// ============================================================================

static curve_constants_t CURVE_CONSTANTS_128 = {0};
static curve_constants_t CURVE_CONSTANTS_192 = {0};
static curve_constants_t CURVE_CONSTANTS_256 = {0};

// ============================================================================
// Isogeny Strategy Constants
// ============================================================================

static isogeny_strategy_t ISOGENY_STRATEGY_128 = {
    .max_degree = 13,
    .optimal_split_threshold = 50,
    .window_size = 4,
    .batch_size = 8,
    .max_chain_length = 1000,
    .kernel_search_attempts = 1000,
    .efficiency_factor = 0.85
};

static isogeny_strategy_t ISOGENY_STRATEGY_192 = {
    .max_degree = 17,
    .optimal_split_threshold = 100,
    .window_size = 5,
    .batch_size = 16,
    .max_chain_length = 2000,
    .kernel_search_attempts = 2000,
    .efficiency_factor = 0.82
};

static isogeny_strategy_t ISOGENY_STRATEGY_256 = {
    .max_degree = 21,
    .optimal_split_threshold = 150,
    .window_size = 6,
    .batch_size = 24,
    .max_chain_length = 3000,
    .kernel_search_attempts = 3000,
    .efficiency_factor = 0.80
};

// ============================================================================
// Validation Constants
// ============================================================================

static validation_constants_t VALIDATION_CONSTANTS_128 = {
    .max_kernel_search_attempts = 1000,
    .point_verification_samples = 10,
    .valid_curve_threshold = 0.95,
    .max_isogeny_chain_length = 1000,
    .security_margin = 20,
    .rejection_sampling_threshold = 0.99
};

static validation_constants_t VALIDATION_CONSTANTS_192 = {
    .max_kernel_search_attempts = 2000,
    .point_verification_samples = 15,
    .valid_curve_threshold = 0.98,
    .max_isogeny_chain_length = 2000,
    .security_margin = 24,
    .rejection_sampling_threshold = 0.995
};

static validation_constants_t VALIDATION_CONSTANTS_256 = {
    .max_kernel_search_attempts = 3000,
    .point_verification_samples = 20,
    .valid_curve_threshold = 0.99,
    .max_isogeny_chain_length = 3000,
    .security_margin = 28,
    .rejection_sampling_threshold = 0.998
};

// ============================================================================
// Performance Constants
// ============================================================================

static performance_constants_t PERFORMANCE_CONSTANTS_128 = {
    .cache_line_size = 64,
    .l1_cache_size = 32,
    .l2_cache_size = 256,
    .l3_cache_size = 8192,
    .optimal_thread_count = 4,
    .vector_size = 4,
    .memory_alignment = 64
};

static performance_constants_t PERFORMANCE_CONSTANTS_192 = {
    .cache_line_size = 64,
    .l1_cache_size = 32,
    .l2_cache_size = 512,
    .l3_cache_size = 16384,
    .optimal_thread_count = 8,
    .vector_size = 4,
    .memory_alignment = 64
};

static performance_constants_t PERFORMANCE_CONSTANTS_256 = {
    .cache_line_size = 64,
    .l1_cache_size = 32,
    .l2_cache_size = 1024,
    .l3_cache_size = 32768,
    .optimal_thread_count = 16,
    .vector_size = 8,
    .memory_alignment = 128
};

// ============================================================================
// Precomputed Tables
// ============================================================================

static isogeny_table_entry_t* ISOGENY_TABLE_128 = NULL;
static isogeny_table_entry_t* ISOGENY_TABLE_192 = NULL;
static isogeny_table_entry_t* ISOGENY_TABLE_256 = NULL;

static fp* SQUARE_ROOTS_TABLE_128 = NULL;
static fp* SQUARE_ROOTS_TABLE_192 = NULL;
static fp* SQUARE_ROOTS_TABLE_256 = NULL;

static fp* INVERSION_TABLE_128 = NULL;
static fp* INVERSION_TABLE_192 = NULL;
static fp* INVERSION_TABLE_256 = NULL;

static fp2* FROBENIUS_CONSTANTS_128 = NULL;
static fp2* FROBENIUS_CONSTANTS_192 = NULL;
static fp2* FROBENIUS_CONSTANTS_256 = NULL;

// ============================================================================
// Internal State
// ============================================================================

static int constants_initialized = 0;
static const char* LIBRARY_VERSION = "TorusCSIDH 1.0.0";
static const char* BUILD_CONFIGURATION = 
#if defined(NDEBUG)
    "Release"
#else
    "Debug"
#endif
#if defined(__AVX2__)
    " AVX2"
#endif
#if defined(__ARM_NEON)
    " NEON"
#endif
;

// ============================================================================
// Internal Helper Functions
// ============================================================================

/**
 * @brief Convert hex string to fp element
 */
static int hex_to_fp(fp* result, const char* hex_str) {
    if (!result || !hex_str) return 0;
    
    size_t len = strlen(hex_str);
    if (len == 0 || len % 2 != 0) return 0;
    
    // Convert hex string to bytes
    uint8_t* bytes = malloc(len / 2);
    if (!bytes) return 0;
    
    for (size_t i = 0; i < len / 2; i++) {
        char hex_byte[3] = {hex_str[2*i], hex_str[2*i + 1], '\0'};
        bytes[i] = (uint8_t)strtoul(hex_byte, NULL, 16);
    }
    
    // Convert bytes to fp (big-endian)
    fp_set_zero(result);
    size_t bytes_per_limb = sizeof(uint64_t);
    
    for (size_t i = 0; i < NLIMBS; i++) {
        for (size_t j = 0; j < bytes_per_limb; j++) {
            size_t byte_index = (NLIMBS - 1 - i) * bytes_per_limb + j;
            if (byte_index < len / 2) {
                result->d[i] |= ((uint64_t)bytes[byte_index]) << (8 * (bytes_per_limb - 1 - j));
            }
        }
    }
    
    free(bytes);
    return 1;
}

/**
 * @brief Compute prime constants for a given security level
 */
static int compute_prime_constants(prime_constants_t* constants, const security_params_t* params) {
    if (!constants || !params) return 0;
    
    // Set modulus from hex string
    if (!hex_to_fp(&constants->modulus, params->prime_hex)) {
        return 0;
    }
    
    // Compute p - 1
    fp_set_one(&constants->modulus_minus_one, NULL);
    fp_sub(&constants->modulus_minus_one, &constants->modulus, &constants->modulus_minus_one, NULL);
    
    // Compute p - 2
    fp_set_u64(&constants->modulus_minus_two, 2, NULL);
    fp_sub(&constants->modulus_minus_two, &constants->modulus, &constants->modulus_minus_two, NULL);
    
    // Compute p + 1
    fp_set_one(&constants->modulus_plus_one, NULL);
    fp_add(&constants->modulus_plus_one, &constants->modulus, &constants->modulus_plus_one, NULL);
    
    // Compute (p + 1) / 2
    fp_copy(&constants->modulus_plus_one_div_two, &constants->modulus_plus_one);
    // fp_div2 would be implemented in fp_arithmetic
    for (int i = NLIMBS - 1; i >= 0; i--) {
        if (i > 0) {
            constants->modulus_plus_one_div_two.d[i-1] |= (constants->modulus_plus_one_div_two.d[i] & 1) << 63;
        }
        constants->modulus_plus_one_div_two.d[i] >>= 1;
    }
    
    // Compute (p - 1) / 2
    fp_copy(&constants->modulus_minus_one_div_two, &constants->modulus_minus_one);
    for (int i = NLIMBS - 1; i >= 0; i--) {
        if (i > 0) {
            constants->modulus_minus_one_div_two.d[i-1] |= (constants->modulus_minus_one_div_two.d[i] & 1) << 63;
        }
        constants->modulus_minus_one_div_two.d[i] >>= 1;
    }
    
    // Compute Montgomery constants
    constants->bits = params->p_bits;
    constants->bytes = (params->p_bits + 7) / 8;
    
    // Compute Montgomery R = 2^bits mod p
    fp_set_u64(&constants->montgomery_r, 1, NULL);
    for (uint32_t i = 0; i < constants->bits; i++) {
        fp_add(&constants->montgomery_r, &constants->montgomery_r, &constants->montgomery_r, NULL);
        fp_reduce(&constants->montgomery_r, NULL);
    }
    
    // Compute Montgomery R^2 = (2^bits)^2 mod p
    fp_mul(&constants->montgomery_r2, &constants->montgomery_r, &constants->montgomery_r, NULL);
    fp_reduce(&constants->montgomery_r2, NULL);
    
    // Compute Montgomery inverse
    constants->montgomery_inv = 0;
    uint64_t p0 = constants->modulus.d[0];
    uint64_t inv = 1;
    
    // Newton's method for modular inverse modulo 2^64
    for (int i = 0; i < 5; i++) {
        inv = inv * (2 - p0 * inv);
    }
    constants->montgomery_inv = -inv;
    
    return 1;
}

/**
 * @brief Initialize curve constants
 */
static int initialize_curve_constants(curve_constants_t* constants, security_level_t level) {
    if (!constants) return 0;
    
    constants->security_level = level;
    
    // Base curve: y^2 = x^3 + x (A = 0 in Montgomery form)
    fp2_set_zero(&constants->A, NULL);
    
    // C = 1
    fp2_set_one(&constants->C, NULL);
    
    // A + 2C = 2
    fp2_set_u64(&constants->A_plus_2C, 2, NULL);
    
    // 4C = 4
    fp2_set_u64(&constants->four_C, 4, NULL);
    
    // A24 = (A + 2C) / 4C = 2/4 = 1/2
    // We need to compute 1/2 in Fp2
    fp2_set_u64(&constants->A24, 1, NULL);
    fp2 half;
    fp2_set_u64(&half, 2, NULL);
    fp2_inv(&half, &half, NULL);
    fp2_mul(&constants->A24, &constants->A24, &half, NULL);
    
    // C24 = 4C = 4
    fp2_copy(&constants->C24, &constants->four_C, NULL);
    
    // Cofactor for supersingular curves: typically 1 for CSIDH
    fp_set_one(&constants->cofactor, NULL);
    
    return 1;
}

/**
 * @brief Initialize precomputed isogeny tables
 */
static int initialize_isogeny_tables(security_level_t level) {
    const security_params_t* params = get_security_params(level);
    if (!params) return 0;
    
    isogeny_table_entry_t** table_ptr = NULL;
    size_t table_size = 0;
    
    switch (level) {
        case TORUS_SECURITY_128:
            table_ptr = &ISOGENY_TABLE_128;
            table_size = params->num_primes;
            break;
        case TORUS_SECURITY_192:
            table_ptr = &ISOGENY_TABLE_192;
            table_size = params->num_primes;
            break;
        case TORUS_SECURITY_256:
            table_ptr = &ISOGENY_TABLE_256;
            table_size = params->num_primes;
            break;
        default:
            return 0;
    }
    
    if (*table_ptr != NULL) {
        free(*table_ptr);
    }
    
    *table_ptr = calloc(table_size, sizeof(isogeny_table_entry_t));
    if (!*table_ptr) {
        return 0;
    }
    
    // Initialize table entries
    for (size_t i = 0; i < table_size; i++) {
        (*table_ptr)[i].prime = params->primes[i];
        (*table_ptr)[i].degree = params->primes[i];
        
        // For production, we would precompute actual kernel points and coefficients
        // This is a placeholder implementation
        fp2_set_zero(&(*table_ptr)[i].kernel_point, NULL);
        for (int j = 0; j < 4; j++) {
            fp2_set_zero(&(*table_ptr)[i].isogeny_coeffs[j], NULL);
        }
    }
    
    return 1;
}

/**
 * @brief Initialize square roots tables
 */
static int initialize_square_roots_tables(security_level_t level) {
    const prime_constants_t* prime_const = get_prime_constants(level);
    if (!prime_const) return 0;
    
    fp** table_ptr = NULL;
    size_t table_size = 256; // Precompute 256 square roots
    
    switch (level) {
        case TORUS_SECURITY_128:
            table_ptr = &SQUARE_ROOTS_TABLE_128;
            break;
        case TORUS_SECURITY_192:
            table_ptr = &SQUARE_ROOTS_TABLE_192;
            break;
        case TORUS_SECURITY_256:
            table_ptr = &SQUARE_ROOTS_TABLE_256;
            break;
        default:
            return 0;
    }
    
    if (*table_ptr != NULL) {
        free(*table_ptr);
    }
    
    *table_ptr = calloc(table_size, sizeof(fp));
    if (!*table_ptr) {
        return 0;
    }
    
    // Precompute square roots for small values
    // In production, this would use more sophisticated algorithms
    for (size_t i = 0; i < table_size; i++) {
        fp value;
        fp_set_u64(&value, i, NULL);
        
        // Try to compute square root
        // This is simplified - actual implementation would be more complex
        if (fp_is_square(&value, NULL)) {
            fp_sqrt(&(*table_ptr)[i], &value, NULL);
        } else {
            fp_set_zero(&(*table_ptr)[i]);
        }
    }
    
    return 1;
}

// ============================================================================
// Public API Implementation
// ============================================================================

const security_params_t* get_security_params(security_level_t level) {
    switch (level) {
        case TORUS_SECURITY_128:
            return &SECURITY_PARAMS_128;
        case TORUS_SECURITY_192:
            return &SECURITY_PARAMS_192;
        case TORUS_SECURITY_256:
            return &SECURITY_PARAMS_256;
        case TORUS_SECURITY_512:
        default:
            return NULL;
    }
}

uint32_t get_prime_count(security_level_t level) {
    const security_params_t* params = get_security_params(level);
    return params ? params->num_primes : 0;
}

const uint64_t* get_primes_array(security_level_t level) {
    const security_params_t* params = get_security_params(level);
    return params ? params->primes : NULL;
}

const int64_t* get_exponent_bounds(security_level_t level) {
    const security_params_t* params = get_security_params(level);
    return params ? params->exponents : NULL;
}

uint32_t get_max_exponent(security_level_t level) {
    const security_params_t* params = get_security_params(level);
    return params ? params->max_exponent : 0;
}

const prime_constants_t* get_prime_constants(security_level_t level) {
    if (!constants_initialized) {
        return NULL;
    }
    
    switch (level) {
        case TORUS_SECURITY_128:
            return &PRIME_CONSTANTS_128;
        case TORUS_SECURITY_192:
            return &PRIME_CONSTANTS_192;
        case TORUS_SECURITY_256:
            return &PRIME_CONSTANTS_256;
        default:
            return NULL;
    }
}

const fp* get_prime_modulus(security_level_t level) {
    const prime_constants_t* constants = get_prime_constants(level);
    return constants ? &constants->modulus : NULL;
}

const fp* get_montgomery_r(security_level_t level) {
    const prime_constants_t* constants = get_prime_constants(level);
    return constants ? &constants->montgomery_r : NULL;
}

const fp* get_montgomery_r2(security_level_t level) {
    const prime_constants_t* constants = get_prime_constants(level);
    return constants ? &constants->montgomery_r2 : NULL;
}

uint64_t get_montgomery_inv(security_level_t level) {
    const prime_constants_t* constants = get_prime_constants(level);
    return constants ? constants->montgomery_inv : 0;
}

const curve_constants_t* get_curve_constants(security_level_t level) {
    if (!constants_initialized) {
        return NULL;
    }
    
    switch (level) {
        case TORUS_SECURITY_128:
            return &CURVE_CONSTANTS_128;
        case TORUS_SECURITY_192:
            return &CURVE_CONSTANTS_192;
        case TORUS_SECURITY_256:
            return &CURVE_CONSTANTS_256;
        default:
            return NULL;
    }
}

const fp2* get_base_curve_A(security_level_t level) {
    const curve_constants_t* constants = get_curve_constants(level);
    return constants ? &constants->A : NULL;
}

const fp2* get_base_curve_C(security_level_t level) {
    const curve_constants_t* constants = get_curve_constants(level);
    return constants ? &constants->C : NULL;
}

const fp2* get_precomputed_A24(security_level_t level) {
    const curve_constants_t* constants = get_curve_constants(level);
    return constants ? &constants->A24 : NULL;
}

const fp* get_curve_cofactor(security_level_t level) {
    const curve_constants_t* constants = get_curve_constants(level);
    return constants ? &constants->cofactor : NULL;
}

const isogeny_strategy_t* get_isogeny_strategy(security_level_t level) {
    switch (level) {
        case TORUS_SECURITY_128:
            return &ISOGENY_STRATEGY_128;
        case TORUS_SECURITY_192:
            return &ISOGENY_STRATEGY_192;
        case TORUS_SECURITY_256:
            return &ISOGENY_STRATEGY_256;
        default:
            return NULL;
    }
}

uint32_t get_optimal_batch_size(security_level_t level) {
    const isogeny_strategy_t* strategy = get_isogeny_strategy(level);
    return strategy ? strategy->batch_size : 1;
}

uint32_t get_window_size(security_level_t level) {
    const isogeny_strategy_t* strategy = get_isogeny_strategy(level);
    return strategy ? strategy->window_size : 4;
}

uint32_t get_max_chain_length(security_level_t level) {
    const isogeny_strategy_t* strategy = get_isogeny_strategy(level);
    return strategy ? strategy->max_chain_length : 1000;
}

const isogeny_table_entry_t* get_precomputed_isogeny_table(security_level_t level) {
    if (!constants_initialized) {
        return NULL;
    }
    
    switch (level) {
        case TORUS_SECURITY_128:
            return ISOGENY_TABLE_128;
        case TORUS_SECURITY_192:
            return ISOGENY_TABLE_192;
        case TORUS_SECURITY_256:
            return ISOGENY_TABLE_256;
        default:
            return NULL;
    }
}

const fp* get_square_roots_table(security_level_t level) {
    if (!constants_initialized) {
        return NULL;
    }
    
    switch (level) {
        case TORUS_SECURITY_128:
            return SQUARE_ROOTS_TABLE_128;
        case TORUS_SECURITY_192:
            return SQUARE_ROOTS_TABLE_192;
        case TORUS_SECURITY_256:
            return SQUARE_ROOTS_TABLE_256;
        default:
            return NULL;
    }
}

const fp* get_inversion_table(security_level_t level) {
    if (!constants_initialized) {
        return NULL;
    }
    
    switch (level) {
        case TORUS_SECURITY_128:
            return INVERSION_TABLE_128;
        case TORUS_SECURITY_192:
            return INVERSION_TABLE_192;
        case TORUS_SECURITY_256:
            return INVERSION_TABLE_256;
        default:
            return NULL;
    }
}

const fp2* get_frobenius_constants(security_level_t level) {
    if (!constants_initialized) {
        return NULL;
    }
    
    switch (level) {
        case TORUS_SECURITY_128:
            return FROBENIUS_CONSTANTS_128;
        case TORUS_SECURITY_192:
            return FROBENIUS_CONSTANTS_192;
        case TORUS_SECURITY_256:
            return FROBENIUS_CONSTANTS_256;
        default:
            return NULL;
    }
}

const fp2* get_fp2_constant(uint64_t value) {
    switch (value) {
        case 0:
            return &FP2_ZERO;
        case 1:
            return &FP2_ONE;
        case 2:
            // Create constant for 2
            {
                static fp2 FP2_TWO = {0};
                if (FP2_TWO.x.d[0] == 0) {
                    fp2_set_u64(&FP2_TWO, 2, NULL);
                }
                return &FP2_TWO;
            }
        default:
            return NULL;
    }
}

const validation_constants_t* get_validation_constants(security_level_t level) {
    switch (level) {
        case TORUS_SECURITY_128:
            return &VALIDATION_CONSTANTS_128;
        case TORUS_SECURITY_192:
            return &VALIDATION_CONSTANTS_192;
        case TORUS_SECURITY_256:
            return &VALIDATION_CONSTANTS_256;
        default:
            return NULL;
    }
}

uint32_t get_max_kernel_attempts(security_level_t level) {
    const validation_constants_t* constants = get_validation_constants(level);
    return constants ? constants->max_kernel_search_attempts : 1000;
}

uint32_t get_security_margin(security_level_t level) {
    const validation_constants_t* constants = get_validation_constants(level);
    return constants ? constants->security_margin : 20;
}

const performance_constants_t* get_performance_constants(security_level_t level) {
    switch (level) {
        case TORUS_SECURITY_128:
            return &PERFORMANCE_CONSTANTS_128;
        case TORUS_SECURITY_192:
            return &PERFORMANCE_CONSTANTS_192;
        case TORUS_SECURITY_256:
            return &PERFORMANCE_CONSTANTS_256;
        default:
            return NULL;
    }
}

uint32_t get_optimal_alignment(security_level_t level) {
    const performance_constants_t* constants = get_performance_constants(level);
    return constants ? constants->memory_alignment : 64;
}

int constants_initialize(void) {
    if (constants_initialized) {
        return TORUS_SUCCESS;
    }
    
    // Initialize Fp2 constants
    fp2_set_u64(&FP2_MINUS_ONE, 1, NULL);
    fp2_neg(&FP2_MINUS_ONE, &FP2_MINUS_ONE, NULL);
    
    fp2_set_u64(&FP2_MINUS_I, 0, NULL);
    fp_set_u64(&FP2_MINUS_I.y, 1, NULL);
    fp2_neg(&FP2_MINUS_I, &FP2_MINUS_I, NULL);
    
    // Initialize prime constants for each security level
    if (!compute_prime_constants(&PRIME_CONSTANTS_128, &SECURITY_PARAMS_128)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    if (!compute_prime_constants(&PRIME_CONSTANTS_192, &SECURITY_PARAMS_192)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    if (!compute_prime_constants(&PRIME_CONSTANTS_256, &SECURITY_PARAMS_256)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    // Initialize curve constants
    if (!initialize_curve_constants(&CURVE_CONSTANTS_128, TORUS_SECURITY_128)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    if (!initialize_curve_constants(&CURVE_CONSTANTS_192, TORUS_SECURITY_192)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    if (!initialize_curve_constants(&CURVE_CONSTANTS_256, TORUS_SECURITY_256)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    // Initialize precomputed tables
    if (!initialize_isogeny_tables(TORUS_SECURITY_128)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    if (!initialize_isogeny_tables(TORUS_SECURITY_192)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    if (!initialize_isogeny_tables(TORUS_SECURITY_256)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    if (!initialize_square_roots_tables(TORUS_SECURITY_128)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    if (!initialize_square_roots_tables(TORUS_SECURITY_192)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    if (!initialize_square_roots_tables(TORUS_SECURITY_256)) {
        return TORUS_ERROR_INITIALIZATION;
    }
    
    constants_initialized = 1;
    return TORUS_SUCCESS;
}

void constants_cleanup(void) {
    if (!constants_initialized) {
        return;
    }
    
    // Free precomputed tables
    if (ISOGENY_TABLE_128) {
        free(ISOGENY_TABLE_128);
        ISOGENY_TABLE_128 = NULL;
    }
    
    if (ISOGENY_TABLE_192) {
        free(ISOGENY_TABLE_192);
        ISOGENY_TABLE_192 = NULL;
    }
    
    if (ISOGENY_TABLE_256) {
        free(ISOGENY_TABLE_256);
        ISOGENY_TABLE_256 = NULL;
    }
    
    if (SQUARE_ROOTS_TABLE_128) {
        free(SQUARE_ROOTS_TABLE_128);
        SQUARE_ROOTS_TABLE_128 = NULL;
    }
    
    if (SQUARE_ROOTS_TABLE_192) {
        free(SQUARE_ROOTS_TABLE_192);
        SQUARE_ROOTS_TABLE_192 = NULL;
    }
    
    if (SQUARE_ROOTS_TABLE_256) {
        free(SQUARE_ROOTS_TABLE_256);
        SQUARE_ROOTS_TABLE_256 = NULL;
    }
    
    if (INVERSION_TABLE_128) {
        free(INVERSION_TABLE_128);
        INVERSION_TABLE_128 = NULL;
    }
    
    if (INVERSION_TABLE_192) {
        free(INVERSION_TABLE_192);
        INVERSION_TABLE_192 = NULL;
    }
    
    if (INVERSION_TABLE_256) {
        free(INVERSION_TABLE_256);
        INVERSION_TABLE_256 = NULL;
    }
    
    if (FROBENIUS_CONSTANTS_128) {
        free(FROBENIUS_CONSTANTS_128);
        FROBENIUS_CONSTANTS_128 = NULL;
    }
    
    if (FROBENIUS_CONSTANTS_192) {
        free(FROBENIUS_CONSTANTS_192);
        FROBENIUS_CONSTANTS_192 = NULL;
    }
    
    if (FROBENIUS_CONSTANTS_256) {
        free(FROBENIUS_CONSTANTS_256);
        FROBENIUS_CONSTANTS_256 = NULL;
    }
    
    // Securely zeroize all constant structures
    secure_zeroize(&PRIME_CONSTANTS_128, sizeof(prime_constants_t));
    secure_zeroize(&PRIME_CONSTANTS_192, sizeof(prime_constants_t));
    secure_zeroize(&PRIME_CONSTANTS_256, sizeof(prime_constants_t));
    
    secure_zeroize(&CURVE_CONSTANTS_128, sizeof(curve_constants_t));
    secure_zeroize(&CURVE_CONSTANTS_192, sizeof(curve_constants_t));
    secure_zeroize(&CURVE_CONSTANTS_256, sizeof(curve_constants_t));
    
    constants_initialized = 0;
}

int constants_verify_initialization(void) {
    return constants_initialized;
}

const char* get_library_version(void) {
    return LIBRARY_VERSION;
}

const char* get_build_configuration(void) {
    return BUILD_CONFIGURATION;
}
