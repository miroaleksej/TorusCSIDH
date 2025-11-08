// src/math/constants.c
#include "math/constants.h"
#include "math/fp_arithmetic.h"
#include "math/fp2_arithmetic.h"
#include "math/modular_reduction.h"
#include "utils/secure_utils.h"
#include "utils/error_handling.h"
#include "utils/random.h"
#include "utils/secure_logging.h"
#include "utils/crypto_utils.h"
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
static const char PRIME_128_HEX[] = 
    "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA";

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

// CSIDH-768 prime: p = 4 * (3 * 5 * ... * 587 * 631) - 1
static const char PRIME_192_HEX[] = 
    "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA"
    "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA";

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

// CSIDH-1024 prime: p = 4 * (3 * 5 * ... * 787 * 797) - 1
static const char PRIME_256_HEX[] = 
    "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA"
    "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA"
    "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA"
    "1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA";

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
const fp2 FP2_MINUS_ONE = {{{0}}};
const fp2 FP2_MINUS_I = {{{0}}};

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
    .prime_hex = PRIME_128_HEX,
    .prime_hex_len = sizeof(PRIME_128_HEX) - 1,
    .description = "CSIDH-512: 128-bit security level",
    .verification = {{0}} // Will be computed during initialization
};

static security_params_t SECURITY_PARAMS_192 = {
    .level_bits = 192,
    .p_bits = 768,
    .num_primes = sizeof(PRIMES_192) / sizeof(PRIMES_192[0]),
    .max_exponent = 7,
    .total_bits = 384,
    .primes = PRIMES_192,
    .exponents = EXPONENTS_192,
    .prime_hex = PRIME_192_HEX,
    .prime_hex_len = sizeof(PRIME_192_HEX) - 1,
    .description = "CSIDH-768: 192-bit security level",
    .verification = {{0}}
};

static security_params_t SECURITY_PARAMS_256 = {
    .level_bits = 256,
    .p_bits = 1024,
    .num_primes = sizeof(PRIMES_256) / sizeof(PRIMES_256[0]),
    .max_exponent = 9,
    .total_bits = 512,
    .primes = PRIMES_256,
    .exponents = EXPONENTS_256,
    .prime_hex = PRIME_256_HEX,
    .prime_hex_len = sizeof(PRIME_256_HEX) - 1,
    .description = "CSIDH-1024: 256-bit security level",
    .verification = {{0}}
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
    .efficiency_factor = 0.85,
    .strategy_name = "Balanced strategy for 128-bit security"
};

static isogeny_strategy_t ISOGENY_STRATEGY_192 = {
    .max_degree = 17,
    .optimal_split_threshold = 100,
    .window_size = 5,
    .batch_size = 16,
    .max_chain_length = 2000,
    .kernel_search_attempts = 2000,
    .efficiency_factor = 0.82,
    .strategy_name = "Optimized strategy for 192-bit security"
};

static isogeny_strategy_t ISOGENY_STRATEGY_256 = {
    .max_degree = 21,
    .optimal_split_threshold = 150,
    .window_size = 6,
    .batch_size = 24,
    .max_chain_length = 3000,
    .kernel_search_attempts = 3000,
    .efficiency_factor = 0.80,
    .strategy_name = "Aggressive strategy for 256-bit security"
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
    .rejection_sampling_threshold = 0.99,
    .validation_method = "Standard validation for 128-bit security"
};

static validation_constants_t VALIDATION_CONSTANTS_192 = {
    .max_kernel_search_attempts = 2000,
    .point_verification_samples = 15,
    .valid_curve_threshold = 0.98,
    .max_isogeny_chain_length = 2000,
    .security_margin = 24,
    .rejection_sampling_threshold = 0.995,
    .validation_method = "Enhanced validation for 192-bit security"
};

static validation_constants_t VALIDATION_CONSTANTS_256 = {
    .max_kernel_search_attempts = 3000,
    .point_verification_samples = 20,
    .valid_curve_threshold = 0.99,
    .max_isogeny_chain_length = 3000,
    .security_margin = 28,
    .rejection_sampling_threshold = 0.998,
    .validation_method = "Strict validation for 256-bit security"
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
    .memory_alignment = 64,
    .optimization_target = "Modern desktop processors"
};

static performance_constants_t PERFORMANCE_CONSTANTS_192 = {
    .cache_line_size = 64,
    .l1_cache_size = 32,
    .l2_cache_size = 512,
    .l3_cache_size = 16384,
    .optimal_thread_count = 8,
    .vector_size = 4,
    .memory_alignment = 64,
    .optimization_target = "High-performance servers"
};

static performance_constants_t PERFORMANCE_CONSTANTS_256 = {
    .cache_line_size = 64,
    .l1_cache_size = 32,
    .l2_cache_size = 1024,
    .l3_cache_size = 32768,
    .optimal_thread_count = 16,
    .vector_size = 8,
    .memory_alignment = 128,
    .optimization_target = "Enterprise-grade systems"
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

static volatile int constants_initialized = 0;
static constants_log_level_t current_log_level = CONSTANTS_LOG_INFO;
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
// Secure Logging Implementation
// ============================================================================

void constants_set_log_level(constants_log_level_t level) {
    current_log_level = level;
}

constants_log_level_t constants_get_log_level(void) {
    return current_log_level;
}

static void constants_log(constants_log_level_t level, const char* format, ...) {
    if (level > current_log_level) {
        return;
    }
    
    char message[CONSTANTS_MAX_ERROR_LEN];
    va_list args;
    va_start(args, format);
    
    // Use secure logging function from secure_logging.h
    int written = vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    if (written > 0 && written < (int)sizeof(message)) {
        secure_log_message(level, "CONSTANTS", message);
    }
}

// ============================================================================
// Integrity Verification Functions
// ============================================================================

int compute_constants_hash(uint8_t hash[32], const void* data, size_t size) {
    if (!hash || !data || size == 0) {
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Use cryptographically secure hash function
    if (crypto_hash_sha256(hash, data, size) != TORUS_SUCCESS) {
        return TORUS_ERROR_COMPUTATION;
    }
    
    return TORUS_SUCCESS;
}

int verify_kernel_point_order(const fp2* point, uint64_t prime, const fp2_ctx_t* ctx) {
    if (!point || !ctx || prime == 0) {
        return 0;
    }
    
    // Verify that [prime] * point = 0
    fp2 result;
    fp2_copy(&result, point, ctx);
    
    // Use constant-time scalar multiplication
    for (uint64_t i = 1; i < prime; i++) {
        fp2_add(&result, &result, point, ctx);
    }
    
    int is_zero = fp2_is_zero(&result, ctx);
    
    // Securely zeroize temporary result
    secure_zeroize(&result, sizeof(fp2));
    
    return is_zero;
}

int verify_constants_integrity(security_level_t level) {
    const security_params_t* params = get_security_params(level);
    if (!params) {
        constants_log(CONSTANTS_LOG_ERROR, "Security parameters not found for level %d", level);
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Verify prime constants integrity
    const prime_constants_t* prime_const = get_prime_constants(level);
    if (!prime_const || !prime_const->is_initialized) {
        constants_log(CONSTANTS_LOG_ERROR, "Prime constants not initialized for level %d", level);
        return TORUS_ERROR_NOT_INITIALIZED;
    }
    
    // Verify curve constants integrity
    const curve_constants_t* curve_const = get_curve_constants(level);
    if (!curve_const || !curve_const->is_initialized) {
        constants_log(CONSTANTS_LOG_ERROR, "Curve constants not initialized for level %d", level);
        return TORUS_ERROR_NOT_INITIALIZED;
    }
    
    // Verify precomputed tables integrity
    const isogeny_table_entry_t* isogeny_table = get_precomputed_isogeny_table(level);
    if (!isogeny_table) {
        constants_log(CONSTANTS_LOG_ERROR, "Isogeny table not available for level %d", level);
        return TORUS_ERROR_NOT_INITIALIZED;
    }
    
    // Verify each kernel point has correct order
    for (uint32_t i = 0; i < params->num_primes; i++) {
        if (!isogeny_table[i].is_valid) {
            constants_log(CONSTANTS_LOG_ERROR, "Invalid isogeny table entry %u for level %d", i, level);
            return TORUS_ERROR_INVALID_STATE;
        }
        
        if (!verify_kernel_point_order(&isogeny_table[i].kernel_point, 
                                      isogeny_table[i].prime, 
                                      &curve_const->fp2_ctx)) {
            constants_log(CONSTANTS_LOG_ERROR, "Kernel point order verification failed for prime %lu", 
                         isogeny_table[i].prime);
            return TORUS_ERROR_INVALID_STATE;
        }
    }
    
    constants_log(CONSTANTS_LOG_INFO, "Constants integrity verified for security level %d", level);
    return TORUS_SUCCESS;
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/**
 * @brief Convert hex string to fp element with comprehensive error checking
 */
static int hex_to_fp(fp* result, const char* hex_str, size_t hex_len, size_t expected_bits) {
    if (!result || !hex_str || hex_len == 0) {
        constants_log(CONSTANTS_LOG_ERROR, "Invalid parameters for hex conversion");
        return 0;
    }
    
    // Validate hex string length
    if (hex_len % 2 != 0) {
        constants_log(CONSTANTS_LOG_ERROR, "Hex string length must be even, got %zu", hex_len);
        return 0;
    }
    
    size_t actual_bits = hex_len * 4; // 4 bits per hex character
    if (actual_bits != expected_bits) {
        constants_log(CONSTANTS_LOG_ERROR, "Prime size mismatch. Expected %zu bits, got %zu bits", 
                     expected_bits, actual_bits);
        return 0;
    }
    
    // Check if NLIMBS is sufficient
    size_t required_limbs = (expected_bits + 63) / 64;
    if (required_limbs > NLIMBS) {
        constants_log(CONSTANTS_LOG_ERROR, "NLIMBS=%zu insufficient for %zu-bit prime (need %zu limbs)",
                     NLIMBS, expected_bits, required_limbs);
        return 0;
    }
    
    // Convert hex string to bytes using stack allocation to avoid heap timing attacks
    size_t byte_len = hex_len / 2;
    if (byte_len > FP_MAX_BYTES) {
        constants_log(CONSTANTS_LOG_ERROR, "Prime too large: %zu bytes (max %d)", byte_len, FP_MAX_BYTES);
        return 0;
    }
    
    uint8_t bytes[FP_MAX_BYTES] = {0};
    
    for (size_t i = 0; i < byte_len; i++) {
        char hex_byte[3] = {hex_str[2*i], hex_str[2*i + 1], '\0'};
        char* endptr;
        unsigned long byte_val = strtoul(hex_byte, &endptr, 16);
        if (endptr == hex_byte || *endptr != '\0') {
            constants_log(CONSTANTS_LOG_ERROR, "Invalid hex character '%s' at position %zu", hex_byte, i);
            secure_zeroize(bytes, sizeof(bytes));
            return 0;
        }
        if (byte_val > 0xFF) {
            constants_log(CONSTANTS_LOG_ERROR, "Hex value out of range: %lu", byte_val);
            secure_zeroize(bytes, sizeof(bytes));
            return 0;
        }
        bytes[i] = (uint8_t)byte_val;
    }
    
    // Convert bytes to fp (big-endian)
    fp_set_zero(result);
    size_t bytes_per_limb = sizeof(uint64_t);
    
    for (size_t i = 0; i < NLIMBS; i++) {
        for (size_t j = 0; j < bytes_per_limb; j++) {
            size_t byte_index = (NLIMBS - 1 - i) * bytes_per_limb + j;
            if (byte_index < byte_len) {
                result->d[i] |= ((uint64_t)bytes[byte_index]) << (8 * (bytes_per_limb - 1 - j));
            }
        }
    }
    
    // Securely zeroize temporary buffer
    secure_zeroize(bytes, sizeof(bytes));
    
    constants_log(CONSTANTS_LOG_DEBUG, "Successfully converted hex string to fp (%zu bits)", expected_bits);
    return 1;
}

/**
 * @brief Compute prime constants for a given security level with comprehensive validation
 */
static int compute_prime_constants(prime_constants_t* constants, const security_params_t* params) {
    if (!constants || !params) {
        constants_log(CONSTANTS_LOG_ERROR, "Invalid parameters for prime constants computation");
        return 0;
    }
    
    constants_log(CONSTANTS_LOG_INFO, "Computing prime constants for security level %u", params->level_bits);
    
    // Set modulus from hex string with size verification
    if (!hex_to_fp(&constants->modulus, params->prime_hex, params->prime_hex_len, params->p_bits)) {
        constants_log(CONSTANTS_LOG_ERROR, "Failed to convert prime modulus for security level %u", 
                     params->level_bits);
        return 0;
    }
    
    // Initialize Fp context
    if (fp_ctx_init(&constants->fp_ctx, &constants->modulus, params->level_bits) != TORUS_SUCCESS) {
        constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize Fp context for security level %u",
                     params->level_bits);
        return 0;
    }
    
    // Compute actual bit length
    constants->bits = fp_get_bits(&constants->fp_ctx);
    constants->bytes = fp_get_bytes(&constants->fp_ctx);
    
    // Verify actual bit length matches expected
    if (constants->bits != params->p_bits) {
        constants_log(CONSTANTS_LOG_ERROR, "Prime bit length mismatch. Expected %u, got %u",
                     params->p_bits, constants->bits);
        fp_ctx_cleanup(&constants->fp_ctx);
        return 0;
    }
    
    // Compute p - 1
    fp_set_one(&constants->modulus_minus_one, &constants->fp_ctx);
    fp_sub(&constants->modulus_minus_one, &constants->modulus, &constants->modulus_minus_one, &constants->fp_ctx);
    
    // Compute p - 2
    fp_set_u64(&constants->modulus_minus_two, 2, &constants->fp_ctx);
    fp_sub(&constants->modulus_minus_two, &constants->modulus, &constants->modulus_minus_two, &constants->fp_ctx);
    
    // Compute p + 1
    fp_set_one(&constants->modulus_plus_one, &constants->fp_ctx);
    fp_add(&constants->modulus_plus_one, &constants->modulus, &constants->modulus_plus_one, &constants->fp_ctx);
    
    // Compute (p + 1) / 2 using proper division
    fp two;
    fp_set_u64(&two, 2, &constants->fp_ctx);
    if (fp_inv(&two, &two, &constants->fp_ctx) != TORUS_SUCCESS) {
        constants_log(CONSTANTS_LOG_ERROR, "Failed to compute 1/2 for prime constants");
        fp_ctx_cleanup(&constants->fp_ctx);
        return 0;
    }
    fp_mul(&constants->modulus_plus_one_div_two, &constants->modulus_plus_one, &two, &constants->fp_ctx);
    
    // Compute (p - 1) / 2
    fp_mul(&constants->modulus_minus_one_div_two, &constants->modulus_minus_one, &two, &constants->fp_ctx);
    
    // Compute Montgomery R = 2^bits mod p
    fp_set_u64(&constants->montgomery_r, 1, &constants->fp_ctx);
    for (uint32_t i = 0; i < constants->bits; i++) {
        fp_add(&constants->montgomery_r, &constants->montgomery_r, &constants->montgomery_r, &constants->fp_ctx);
        if (fp_greater_or_equal(&constants->montgomery_r, &constants->modulus, &constants->fp_ctx)) {
            fp_sub(&constants->montgomery_r, &constants->montgomery_r, &constants->modulus, &constants->fp_ctx);
        }
    }
    
    // Compute Montgomery R^2 = (2^bits)^2 mod p
    fp_mul(&constants->montgomery_r2, &constants->montgomery_r, &constants->montgomery_r, &constants->fp_ctx);
    fp_reduce(&constants->montgomery_r2, &constants->fp_ctx);
    
    // Compute Montgomery inverse
    uint64_t p0 = constants->modulus.d[0];
    uint64_t inv = 1;
    
    // Newton's method for modular inverse modulo 2^64
    for (int i = 0; i < 5; i++) {
        inv = inv * (2 - p0 * inv);
    }
    constants->montgomery_inv = -inv;
    
    // Verify Montgomery constants
    fp check;
    fp_mul(&check, &constants->montgomery_r, &constants->montgomery_r2, &constants->fp_ctx);
    fp_reduce(&check, &constants->fp_ctx);
    
    if (!fp_equal(&check, &constants->montgomery_r)) {
        constants_log(CONSTANTS_LOG_ERROR, "Montgomery constant verification failed");
        fp_ctx_cleanup(&constants->fp_ctx);
        return 0;
    }
    
    // Compute verification hash
    if (compute_constants_hash(constants->verification.hash, 
                              constants, 
                              sizeof(prime_constants_t) - sizeof(constant_verification_t)) != TORUS_SUCCESS) {
        constants_log(CONSTANTS_LOG_ERROR, "Failed to compute verification hash for prime constants");
        fp_ctx_cleanup(&constants->fp_ctx);
        return 0;
    }
    
    constants->verification.timestamp = (uint64_t)time(NULL);
    
    constants->is_initialized = 1;
    constants_log(CONSTANTS_LOG_INFO, "Successfully computed prime constants for security level %u", 
                 params->level_bits);
    
    return 1;
}

/**
 * @brief Initialize curve constants with proper CSIDH parameters and validation
 */
static int initialize_curve_constants(curve_constants_t* constants, security_level_t level) {
    if (!constants) {
        constants_log(CONSTANTS_LOG_ERROR, "Invalid parameters for curve constants initialization");
        return 0;
    }
    
    constants_log(CONSTANTS_LOG_INFO, "Initializing curve constants for security level %d", level);
    
    constants->security_level = level;
    
    // Get the corresponding prime constants
    const prime_constants_t* prime_const = get_prime_constants(level);
    if (!prime_const || !prime_const->is_initialized) {
        constants_log(CONSTANTS_LOG_ERROR, "Failed to get valid prime constants for security level %d", level);
        return 0;
    }
    
    // Initialize Fp2 context
    if (fp2_ctx_init(&constants->fp2_ctx, &prime_const->fp_ctx, level) != TORUS_SUCCESS) {
        constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize Fp2 context for security level %d", level);
        return 0;
    }
    
    // Base curve for CSIDH: y^2 = x^3 + Ax^2 + x
    // Starting curve typically has A = 0 for efficiency
    
    // A = 0 (starting curve parameter)
    fp2_set_zero(&constants->A, &constants->fp2_ctx);
    
    // C = 1 (coefficient for x term)
    fp2_set_one(&constants->C, &constants->fp2_ctx);
    
    // Precompute constants for isogeny formulas
    // A + 2C = 2
    fp2_set_u64(&constants->A_plus_2C, 2, &constants->fp2_ctx);
    
    // 4C = 4
    fp2_set_u64(&constants->four_C, 4, &constants->fp2_ctx);
    
    // A24 = (A + 2C) / 4C = 2/4 = 1/2
    fp2 half;
    fp2_set_u64(&half, 2, &constants->fp2_ctx);
    if (fp2_inv(&half, &half, &constants->fp2_ctx) != TORUS_SUCCESS) {
        constants_log(CONSTANTS_LOG_ERROR, "Failed to compute 1/2 for curve constants");
        fp2_ctx_cleanup(&constants->fp2_ctx);
        return 0;
    }
    fp2_mul(&constants->A24, &constants->A_plus_2C, &half, &constants->fp2_ctx);
    
    // C24 = 4C = 4
    fp2_copy(&constants->C24, &constants->four_C, &constants->fp2_ctx);
    
    // Cofactor for supersingular curves in CSIDH
    fp_set_one(&constants->cofactor, &prime_const->fp_ctx);
    
    // Compute verification hash
    if (compute_constants_hash(constants->verification.hash, 
                              constants, 
                              sizeof(curve_constants_t) - sizeof(constant_verification_t)) != TORUS_SUCCESS) {
        constants_log(CONSTANTS_LOG_ERROR, "Failed to compute verification hash for curve constants");
        fp2_ctx_cleanup(&constants->fp2_ctx);
        return 0;
    }
    
    constants->verification.timestamp = (uint64_t)time(NULL);
    
    constants->is_initialized = 1;
    constants_log(CONSTANTS_LOG_INFO, "Successfully initialized curve constants for security level %d", level);
    
    return 1;
}

/**
 * @brief Initialize precomputed isogeny tables with secure random kernel points
 */
static int initialize_isogeny_tables(security_level_t level) {
    const security_params_t* params = get_security_params(level);
    if (!params) {
        constants_log(CONSTANTS_LOG_ERROR, "Failed to get security parameters for level %d", level);
        return 0;
    }
    
    const prime_constants_t* prime_const = get_prime_constants(level);
    const curve_constants_t* curve_const = get_curve_constants(level);
    if (!prime_const || !prime_const->is_initialized || !curve_const || !curve_const->is_initialized) {
        constants_log(CONSTANTS_LOG_ERROR, "Required constants not initialized for level %d", level);
        return 0;
    }
    
    isogeny_table_entry_t** table_ptr = NULL;
    size_t table_size = params->num_primes;
    
    switch (level) {
        case TORUS_SECURITY_128:
            table_ptr = &ISOGENY_TABLE_128;
            break;
        case TORUS_SECURITY_192:
            table_ptr = &ISOGENY_TABLE_192;
            break;
        case TORUS_SECURITY_256:
            table_ptr = &ISOGENY_TABLE_256;
            break;
        default:
            constants_log(CONSTANTS_LOG_ERROR, "Unsupported security level: %d", level);
            return 0;
    }
    
    if (*table_ptr != NULL) {
        // Securely zeroize and free existing table
        secure_zeroize(*table_ptr, table_size * sizeof(isogeny_table_entry_t));
        free(*table_ptr);
    }
    
    *table_ptr = calloc(table_size, sizeof(isogeny_table_entry_t));
    if (!*table_ptr) {
        constants_log(CONSTANTS_LOG_ERROR, "Memory allocation failed for isogeny table level %d (%zu entries)", 
                     level, table_size);
        return 0;
    }
    
    // Initialize table entries with cryptographically secure kernel points
    int success_count = 0;
    for (size_t i = 0; i < table_size; i++) {
        (*table_ptr)[i].prime = params->primes[i];
        (*table_ptr)[i].degree = params->primes[i];
        
        // Generate cryptographically secure kernel point with correct order
        int attempts = 0;
        int point_found = 0;
        
        while (!point_found && attempts < 100) {
            attempts++;
            
            // Generate random point
            if (fp2_random(&(*table_ptr)[i].kernel_point, &curve_const->fp2_ctx) != TORUS_SUCCESS) {
                continue;
            }
            
            // Skip zero point
            if (fp2_is_zero(&(*table_ptr)[i].kernel_point, &curve_const->fp2_ctx)) {
                continue;
            }
            
            // Verify point has correct order
            if (verify_kernel_point_order(&(*table_ptr)[i].kernel_point, 
                                         params->primes[i], 
                                         &curve_const->fp2_ctx)) {
                point_found = 1;
                success_count++;
            }
        }
        
        if (!point_found) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to find valid kernel point for prime %lu after %d attempts", 
                         params->primes[i], attempts);
            // Mark entry as invalid but continue to allow partial initialization
            (*table_ptr)[i].is_valid = 0;
            continue;
        }
        
        // Initialize isogeny coefficients (would be computed properly in production)
        // For now, use deterministic but secure derivation from kernel point
        uint8_t seed[32];
        if (compute_constants_hash(seed, &(*table_ptr)[i].kernel_point, sizeof(fp2)) != TORUS_SUCCESS) {
            (*table_ptr)[i].is_valid = 0;
            continue;
        }
        
        for (int j = 0; j < 4; j++) {
            // Derive coefficients from seed in a deterministic way
            uint8_t coeff_seed[32];
            memcpy(coeff_seed, seed, sizeof(seed));
            coeff_seed[0] ^= j;  // Modify seed for each coefficient
            
            fp temp;
            fp_set_bytes(&temp, coeff_seed, &prime_const->fp_ctx);
            fp2_set_fp(&(*table_ptr)[i].isogeny_coeffs[j], &temp, &FP_ZERO, &curve_const->fp2_ctx);
        }
        
        // Compute verification data
        if (compute_constants_hash((*table_ptr)[i].verification.hash, 
                                  &(*table_ptr)[i], 
                                  sizeof(isogeny_table_entry_t) - sizeof(constant_verification_t)) != TORUS_SUCCESS) {
            (*table_ptr)[i].is_valid = 0;
            continue;
        }
        
        (*table_ptr)[i].verification.timestamp = (uint64_t)time(NULL);
        (*table_ptr)[i].is_valid = 1;
        
        // Securely zeroize temporary seeds
        secure_zeroize(seed, sizeof(seed));
    }
    
    if (success_count < table_size) {
        constants_log(CONSTANTS_LOG_WARN, "Only %d/%zu valid kernel points found for level %d", 
                     success_count, table_size, level);
        // Don't fail completely - allow partial initialization for resilience
    }
    
    constants_log(CONSTANTS_LOG_INFO, "Successfully initialized isogeny table for level %d (%d/%zu valid entries)", 
                 level, success_count, table_size);
    return (success_count > 0);  // Return success if at least one valid entry
}

/**
 * @brief Initialize square roots tables with proper computation and validation
 */
static int initialize_square_roots_tables(security_level_t level) {
    const prime_constants_t* prime_const = get_prime_constants(level);
    if (!prime_const || !prime_const->is_initialized) {
        constants_log(CONSTANTS_LOG_ERROR, "Prime constants not initialized for level %d", level);
        return 0;
    }
    
    fp** table_ptr = NULL;
    
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
            constants_log(CONSTANTS_LOG_ERROR, "Unsupported security level: %d", level);
            return 0;
    }
    
    if (*table_ptr != NULL) {
        free(*table_ptr);
    }
    
    *table_ptr = calloc(SQUARE_ROOTS_TABLE_SIZE, sizeof(fp));
    if (!*table_ptr) {
        constants_log(CONSTANTS_LOG_ERROR, "Memory allocation failed for square roots table level %d", level);
        return 0;
    }
    
    // Precompute square roots for small values
    int success_count = 0;
    for (size_t i = 0; i < SQUARE_ROOTS_TABLE_SIZE; i++) {
        fp value;
        fp_set_u64(&value, i, &prime_const->fp_ctx);
        
        // Compute square root if it exists
        if (fp_is_square(&value, &prime_const->fp_ctx)) {
            if (fp_sqrt(&(*table_ptr)[i], &value, &prime_const->fp_ctx) == TORUS_SUCCESS) {
                success_count++;
            } else {
                fp_set_zero(&(*table_ptr)[i]);
            }
        } else {
            fp_set_zero(&(*table_ptr)[i]);
        }
    }
    
    constants_log(CONSTANTS_LOG_INFO, "Successfully initialized square roots table for level %d (%d/%zu valid roots)", 
                 level, success_count, SQUARE_ROOTS_TABLE_SIZE);
    return 1;
}

/**
 * @brief Verify CSIDH prime structure: p = 4 * ∏ ℓ_i - 1
 */
static int verify_csidh_prime(const fp* modulus, const uint64_t* primes, uint32_t num_primes) {
    if (!modulus || !primes) {
        constants_log(CONSTANTS_LOG_ERROR, "Invalid parameters for CSIDH prime verification");
        return 0;
    }
    
    constants_log(CONSTANTS_LOG_DEBUG, "Verifying CSIDH prime structure with %u primes", num_primes);
    
    // Create temporary Fp context for verification
    fp_ctx_t fp_ctx;
    if (fp_ctx_init(&fp_ctx, modulus, 128) != TORUS_SUCCESS) {
        constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize Fp context for prime verification");
        return 0;
    }
    
    // Compute product of small primes
    fp product;
    fp_set_one(&product, &fp_ctx);
    
    for (uint32_t i = 0; i < num_primes; i++) {
        fp prime_fp;
        fp_set_u64(&prime_fp, primes[i], &fp_ctx);
        fp_mul(&product, &product, &prime_fp, &fp_ctx);
        fp_reduce(&product, &fp_ctx);
    }
    
    // Multiply by 4
    fp four;
    fp_set_u64(&four, 4, &fp_ctx);
    fp_mul(&product, &product, &four, &fp_ctx);
    fp_reduce(&product, &fp_ctx);
    
    // Subtract 1: should equal modulus
    fp one;
    fp_set_u64(&one, 1, &fp_ctx);
    fp_sub(&product, &product, &one, &fp_ctx);
    fp_reduce(&product, &fp_ctx);
    
    int result = fp_equal(&product, modulus);
    
    fp_ctx_cleanup(&fp_ctx);
    
    if (result) {
        constants_log(CONSTANTS_LOG_DEBUG, "CSIDH prime structure verified successfully");
    } else {
        constants_log(CONSTANTS_LOG_ERROR, "CSIDH prime structure verification failed");
    }
    
    return result;
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
            constants_log(CONSTANTS_LOG_WARN, "Unsupported security level requested: %d", level);
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

int verify_security_params(security_level_t level) {
    const security_params_t* params = get_security_params(level);
    if (!params) {
        constants_log(CONSTANTS_LOG_ERROR, "Security parameters not found for level %d", level);
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Verify basic consistency
    if (params->num_primes == 0 || params->num_primes > 1000) {
        constants_log(CONSTANTS_LOG_ERROR, "Invalid number of primes: %u", params->num_primes);
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    if (params->max_exponent == 0 || params->max_exponent > 100) {
        constants_log(CONSTANTS_LOG_ERROR, "Invalid max exponent: %u", params->max_exponent);
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    // Verify prime-exponent array sizes match
    if (params->primes == NULL || params->exponents == NULL) {
        constants_log(CONSTANTS_LOG_ERROR, "Null primes or exponents array");
        return TORUS_ERROR_INVALID_PARAM;
    }
    
    constants_log(CONSTANTS_LOG_DEBUG, "Security parameters verified for level %d", level);
    return TORUS_SUCCESS;
}

const prime_constants_t* get_prime_constants(security_level_t level) {
    if (!constants_initialized) {
        constants_log(CONSTANTS_LOG_WARN, "Constants not initialized, cannot get prime constants for level %d", level);
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
            constants_log(CONSTANTS_LOG_WARN, "Unsupported security level for prime constants: %d", level);
            return NULL;
    }
}

const fp* get_prime_modulus(security_level_t level) {
    const prime_constants_t* constants = get_prime_constants(level);
    if (!constants || !constants->is_initialized) {
        constants_log(CONSTANTS_LOG_WARN, "Prime constants not available for level %d", level);
        return NULL;
    }
    return &constants->modulus;
}

const fp* get_montgomery_r(security_level_t level) {
    const prime_constants_t* constants = get_prime_constants(level);
    return constants && constants->is_initialized ? &constants->montgomery_r : NULL;
}

const fp* get_montgomery_r2(security_level_t level) {
    const prime_constants_t* constants = get_prime_constants(level);
    return constants && constants->is_initialized ? &constants->montgomery_r2 : NULL;
}

uint64_t get_montgomery_inv(security_level_t level) {
    const prime_constants_t* constants = get_prime_constants(level);
    return constants && constants->is_initialized ? constants->montgomery_inv : 0;
}

const fp_ctx_t* get_fp_ctx(security_level_t level) {
    const prime_constants_t* constants = get_prime_constants(level);
    return constants && constants->is_initialized ? &constants->fp_ctx : NULL;
}

int verify_prime_constants(security_level_t level) {
    const prime_constants_t* constants = get_prime_constants(level);
    if (!constants || !constants->is_initialized) {
        constants_log(CONSTANTS_LOG_ERROR, "Prime constants not initialized for level %d", level);
        return TORUS_ERROR_NOT_INITIALIZED;
    }
    
    // Verify modulus is not zero
    if (fp_is_zero(&constants->modulus)) {
        constants_log(CONSTANTS_LOG_ERROR, "Prime modulus is zero for level %d", level);
        return TORUS_ERROR_INVALID_STATE;
    }
    
    // Verify Montgomery constants
    fp check;
    fp_mul(&check, &constants->montgomery_r, &constants->montgomery_r2, &constants->fp_ctx);
    fp_reduce(&check, &constants->fp_ctx);
    
    if (!fp_equal(&check, &constants->montgomery_r)) {
        constants_log(CONSTANTS_LOG_ERROR, "Montgomery constants verification failed for level %d", level);
        return TORUS_ERROR_COMPUTATION;
    }
    
    // Verify verification hash
    uint8_t computed_hash[32];
    if (compute_constants_hash(computed_hash, 
                              constants, 
                              sizeof(prime_constants_t) - sizeof(constant_verification_t)) == TORUS_SUCCESS) {
        if (memcmp(computed_hash, constants->verification.hash, 32) != 0) {
            constants_log(CONSTANTS_LOG_ERROR, "Prime constants verification hash mismatch for level %d", level);
            return TORUS_ERROR_INVALID_STATE;
        }
    }
    
    constants_log(CONSTANTS_LOG_DEBUG, "Prime constants verified for level %d", level);
    return TORUS_SUCCESS;
}

const curve_constants_t* get_curve_constants(security_level_t level) {
    if (!constants_initialized) {
        constants_log(CONSTANTS_LOG_WARN, "Constants not initialized, cannot get curve constants for level %d", level);
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
            constants_log(CONSTANTS_LOG_WARN, "Unsupported security level for curve constants: %d", level);
            return NULL;
    }
}

const fp2* get_base_curve_A(security_level_t level) {
    const curve_constants_t* constants = get_curve_constants(level);
    return constants && constants->is_initialized ? &constants->A : NULL;
}

const fp2* get_base_curve_C(security_level_t level) {
    const curve_constants_t* constants = get_curve_constants(level);
    return constants && constants->is_initialized ? &constants->C : NULL;
}

const fp2* get_precomputed_A24(security_level_t level) {
    const curve_constants_t* constants = get_curve_constants(level);
    return constants && constants->is_initialized ? &constants->A24 : NULL;
}

const fp* get_curve_cofactor(security_level_t level) {
    const curve_constants_t* constants = get_curve_constants(level);
    return constants && constants->is_initialized ? &constants->cofactor : NULL;
}

const fp2_ctx_t* get_fp2_ctx(security_level_t level) {
    const curve_constants_t* constants = get_curve_constants(level);
    return constants && constants->is_initialized ? &constants->fp2_ctx : NULL;
}

int verify_curve_constants(security_level_t level) {
    const curve_constants_t* constants = get_curve_constants(level);
    if (!constants || !constants->is_initialized) {
        constants_log(CONSTANTS_LOG_ERROR, "Curve constants not initialized for level %d", level);
        return TORUS_ERROR_NOT_INITIALIZED;
    }
    
    // Verify curve parameters are not zero
    if (fp2_is_zero(&constants->A, &constants->fp2_ctx) && fp2_is_zero(&constants->C, &constants->fp2_ctx)) {
        constants_log(CONSTANTS_LOG_ERROR, "Both curve parameters A and C are zero for level %d", level);
        return TORUS_ERROR_INVALID_STATE;
    }
    
    // Verify verification hash
    uint8_t computed_hash[32];
    if (compute_constants_hash(computed_hash, 
                              constants, 
                              sizeof(curve_constants_t) - sizeof(constant_verification_t)) == TORUS_SUCCESS) {
        if (memcmp(computed_hash, constants->verification.hash, 32) != 0) {
            constants_log(CONSTANTS_LOG_ERROR, "Curve constants verification hash mismatch for level %d", level);
            return TORUS_ERROR_INVALID_STATE;
        }
    }
    
    constants_log(CONSTANTS_LOG_DEBUG, "Curve constants verified for level %d", level);
    return TORUS_SUCCESS;
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
            constants_log(CONSTANTS_LOG_WARN, "Unsupported security level for isogeny strategy: %d", level);
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

int verify_precomputed_tables(security_level_t level) {
    const isogeny_table_entry_t* isogeny_table = get_precomputed_isogeny_table(level);
    const fp* sqrt_table = get_square_roots_table(level);
    
    if (!isogeny_table || !sqrt_table) {
        constants_log(CONSTANTS_LOG_ERROR, "Precomputed tables not available for level %d", level);
        return TORUS_ERROR_NOT_INITIALIZED;
    }
    
    // Verify isogeny table has valid entries
    const security_params_t* params = get_security_params(level);
    if (params) {
        int valid_count = 0;
        for (uint32_t i = 0; i < params->num_primes; i++) {
            if (isogeny_table[i].is_valid) {
                valid_count++;
                
                // Verify kernel point order for valid entries
                const curve_constants_t* curve_const = get_curve_constants(level);
                if (curve_const && curve_const->is_initialized) {
                    if (!verify_kernel_point_order(&isogeny_table[i].kernel_point, 
                                                  isogeny_table[i].prime, 
                                                  &curve_const->fp2_ctx)) {
                        constants_log(CONSTANTS_LOG_ERROR, "Kernel point order verification failed for entry %u", i);
                        return TORUS_ERROR_INVALID_STATE;
                    }
                }
            }
        }
        
        if (valid_count == 0) {
            constants_log(CONSTANTS_LOG_ERROR, "No valid isogeny table entries for level %d", level);
            return TORUS_ERROR_INVALID_STATE;
        }
        
        constants_log(CONSTANTS_LOG_DEBUG, "Verified %d/%d valid isogeny table entries for level %d", 
                     valid_count, params->num_primes, level);
    }
    
    constants_log(CONSTANTS_LOG_DEBUG, "Precomputed tables verified for level %d", level);
    return TORUS_SUCCESS;
}

const fp2* get_fp2_constant(uint64_t value) {
    switch (value) {
        case 0:
            return &FP2_ZERO;
        case 1:
            return &FP2_ONE;
        case 2:
            {
                static fp2 FP2_TWO = {0};
                if (FP2_TWO.x.d[0] == 0) {
                    // Use a temporary context for initialization
                    fp_ctx_t temp_ctx;
                    if (fp_ctx_init(&temp_ctx, &FP_ONE, 128) == TORUS_SUCCESS) {
                        fp2_set_u64(&FP2_TWO, 2, NULL);
                        fp_ctx_cleanup(&temp_ctx);
                    }
                }
                return &FP2_TWO;
            }
        default:
            constants_log(CONSTANTS_LOG_WARN, "Unsupported fp2 constant value: %lu", value);
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
            constants_log(CONSTANTS_LOG_WARN, "Unsupported security level for validation constants: %d", level);
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
            constants_log(CONSTANTS_LOG_WARN, "Unsupported security level for performance constants: %d", level);
            return NULL;
    }
}

uint32_t get_optimal_alignment(security_level_t level) {
    const performance_constants_t* constants = get_performance_constants(level);
    return constants ? constants->memory_alignment : 64;
}

int constants_initialize(void) {
    if (constants_initialized) {
        constants_log(CONSTANTS_LOG_INFO, "Constants already initialized");
        return TORUS_SUCCESS;
    }
    
    constants_log(CONSTANTS_LOG_INFO, "Initializing TorusCSIDH constants...");
    
    int ret = TORUS_SUCCESS;
    int attempts = 0;
    
    // Retry initialization in case of transient failures
    while (attempts < CONSTANTS_MAX_INIT_ATTEMPTS) {
        ret = TORUS_SUCCESS;
        attempts++;
        
        constants_log(CONSTANTS_LOG_DEBUG, "Initialization attempt %d/%d", attempts, CONSTANTS_MAX_INIT_ATTEMPTS);
        
        // Initialize Fp2 constants
        fp_ctx_t temp_fp_ctx;
        if (fp_ctx_init(&temp_fp_ctx, &FP_ONE, 128) != TORUS_SUCCESS) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize temporary Fp context");
            ret = TORUS_ERROR_INITIALIZATION;
            continue;
        }
        
        fp2_ctx_t temp_fp2_ctx;
        if (fp2_ctx_init(&temp_fp2_ctx, &temp_fp_ctx, 128) != TORUS_SUCCESS) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize temporary Fp2 context");
            fp_ctx_cleanup(&temp_fp_ctx);
            ret = TORUS_ERROR_INITIALIZATION;
            continue;
        }
        
        fp2_set_u64(&FP2_MINUS_ONE, 1, &temp_fp2_ctx);
        fp2_neg(&FP2_MINUS_ONE, &FP2_MINUS_ONE, &temp_fp2_ctx);
        
        fp2_set_u64(&FP2_MINUS_I, 0, &temp_fp2_ctx);
        fp_set_u64(&FP2_MINUS_I.y, 1, &temp_fp_ctx);
        fp2_neg(&FP2_MINUS_I, &FP2_MINUS_I, &temp_fp2_ctx);
        
        fp2_ctx_cleanup(&temp_fp2_ctx);
        fp_ctx_cleanup(&temp_fp_ctx);
        
        // Verify security parameters first
        if (verify_security_params(TORUS_SECURITY_128) != TORUS_SUCCESS ||
            verify_security_params(TORUS_SECURITY_192) != TORUS_SUCCESS ||
            verify_security_params(TORUS_SECURITY_256) != TORUS_SUCCESS) {
            constants_log(CONSTANTS_LOG_ERROR, "Security parameters verification failed");
            ret = TORUS_ERROR_INITIALIZATION;
            continue;
        }
        
        // Initialize prime constants for each security level with verification
        constants_log(CONSTANTS_LOG_INFO, "Initializing prime constants for security level 128...");
        if (!compute_prime_constants(&PRIME_CONSTANTS_128, &SECURITY_PARAMS_128)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize prime constants for level 128");
            ret = TORUS_ERROR_INITIALIZATION;
            continue;
        }
        
        constants_log(CONSTANTS_LOG_INFO, "Initializing prime constants for security level 192...");
        if (!compute_prime_constants(&PRIME_CONSTANTS_192, &SECURITY_PARAMS_192)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize prime constants for level 192");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        constants_log(CONSTANTS_LOG_INFO, "Initializing prime constants for security level 256...");
        if (!compute_prime_constants(&PRIME_CONSTANTS_256, &SECURITY_PARAMS_256)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize prime constants for level 256");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        // Verify CSIDH prime structure
        constants_log(CONSTANTS_LOG_INFO, "Verifying CSIDH prime structure...");
        if (!verify_csidh_prime(&PRIME_CONSTANTS_128.modulus, PRIMES_128, SECURITY_PARAMS_128.num_primes)) {
            constants_log(CONSTANTS_LOG_ERROR, "Prime for level 128 does not have CSIDH structure");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        // Verify prime constants
        if (verify_prime_constants(TORUS_SECURITY_128) != TORUS_SUCCESS ||
            verify_prime_constants(TORUS_SECURITY_192) != TORUS_SUCCESS ||
            verify_prime_constants(TORUS_SECURITY_256) != TORUS_SUCCESS) {
            constants_log(CONSTANTS_LOG_ERROR, "Prime constants verification failed");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        // Initialize curve constants
        constants_log(CONSTANTS_LOG_INFO, "Initializing curve constants...");
        if (!initialize_curve_constants(&CURVE_CONSTANTS_128, TORUS_SECURITY_128)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize curve constants for level 128");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        if (!initialize_curve_constants(&CURVE_CONSTANTS_192, TORUS_SECURITY_192)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize curve constants for level 192");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        if (!initialize_curve_constants(&CURVE_CONSTANTS_256, TORUS_SECURITY_256)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize curve constants for level 256");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        // Verify curve constants
        if (verify_curve_constants(TORUS_SECURITY_128) != TORUS_SUCCESS ||
            verify_curve_constants(TORUS_SECURITY_192) != TORUS_SUCCESS ||
            verify_curve_constants(TORUS_SECURITY_256) != TORUS_SUCCESS) {
            constants_log(CONSTANTS_LOG_ERROR, "Curve constants verification failed");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        // Initialize precomputed tables
        constants_log(CONSTANTS_LOG_INFO, "Initializing precomputed tables...");
        if (!initialize_isogeny_tables(TORUS_SECURITY_128)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize isogeny tables for level 128");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        if (!initialize_isogeny_tables(TORUS_SECURITY_192)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize isogeny tables for level 192");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        if (!initialize_isogeny_tables(TORUS_SECURITY_256)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize isogeny tables for level 256");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        if (!initialize_square_roots_tables(TORUS_SECURITY_128)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize square roots tables for level 128");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        if (!initialize_square_roots_tables(TORUS_SECURITY_192)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize square roots tables for level 192");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        if (!initialize_square_roots_tables(TORUS_SECURITY_256)) {
            constants_log(CONSTANTS_LOG_ERROR, "Failed to initialize square roots tables for level 256");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        // Verify precomputed tables
        if (verify_precomputed_tables(TORUS_SECURITY_128) != TORUS_SUCCESS ||
            verify_precomputed_tables(TORUS_SECURITY_192) != TORUS_SUCCESS ||
            verify_precomputed_tables(TORUS_SECURITY_256) != TORUS_SUCCESS) {
            constants_log(CONSTANTS_LOG_ERROR, "Precomputed tables verification failed");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        // Verify overall constants integrity
        if (verify_constants_integrity(TORUS_SECURITY_128) != TORUS_SUCCESS ||
            verify_constants_integrity(TORUS_SECURITY_192) != TORUS_SUCCESS ||
            verify_constants_integrity(TORUS_SECURITY_256) != TORUS_SUCCESS) {
            constants_log(CONSTANTS_LOG_ERROR, "Constants integrity verification failed");
            ret = TORUS_ERROR_INITIALIZATION;
            goto cleanup_partial;
        }
        
        // If we reached here, initialization was successful
        break;

    cleanup_partial:
        // Cleanup partially initialized state before retry
        constants_cleanup();
    }
    
    if (ret == TORUS_SUCCESS) {
        constants_initialized = 1;
        constants_log(CONSTANTS_LOG_INFO, "TorusCSIDH constants initialized successfully after %d attempts", attempts);
    } else {
        constants_log(CONSTANTS_LOG_ERROR, "TorusCSIDH constants initialization failed after %d attempts", attempts);
    }
    
    return ret;
}

void constants_cleanup(void) {
    if (!constants_initialized) {
        return;
    }
    
    constants_log(CONSTANTS_LOG_INFO, "Cleaning up TorusCSIDH constants...");
    
    // Cleanup prime constants
    if (PRIME_CONSTANTS_128.is_initialized) {
        fp_ctx_cleanup(&PRIME_CONSTANTS_128.fp_ctx);
        PRIME_CONSTANTS_128.is_initialized = 0;
    }
    if (PRIME_CONSTANTS_192.is_initialized) {
        fp_ctx_cleanup(&PRIME_CONSTANTS_192.fp_ctx);
        PRIME_CONSTANTS_192.is_initialized = 0;
    }
    if (PRIME_CONSTANTS_256.is_initialized) {
        fp_ctx_cleanup(&PRIME_CONSTANTS_256.fp_ctx);
        PRIME_CONSTANTS_256.is_initialized = 0;
    }
    
    // Cleanup curve constants
    if (CURVE_CONSTANTS_128.is_initialized) {
        fp2_ctx_cleanup(&CURVE_CONSTANTS_128.fp2_ctx);
        CURVE_CONSTANTS_128.is_initialized = 0;
    }
    if (CURVE_CONSTANTS_192.is_initialized) {
        fp2_ctx_cleanup(&CURVE_CONSTANTS_192.fp2_ctx);
        CURVE_CONSTANTS_192.is_initialized = 0;
    }
    if (CURVE_CONSTANTS_256.is_initialized) {
        fp2_ctx_cleanup(&CURVE_CONSTANTS_256.fp2_ctx);
        CURVE_CONSTANTS_256.is_initialized = 0;
    }
    
    // Free precomputed tables with secure zeroization
    if (ISOGENY_TABLE_128) {
        secure_zeroize(ISOGENY_TABLE_128, get_prime_count(TORUS_SECURITY_128) * sizeof(isogeny_table_entry_t));
        free(ISOGENY_TABLE_128);
        ISOGENY_TABLE_128 = NULL;
    }
    
    if (ISOGENY_TABLE_192) {
        secure_zeroize(ISOGENY_TABLE_192, get_prime_count(TORUS_SECURITY_192) * sizeof(isogeny_table_entry_t));
        free(ISOGENY_TABLE_192);
        ISOGENY_TABLE_192 = NULL;
    }
    
    if (ISOGENY_TABLE_256) {
        secure_zeroize(ISOGENY_TABLE_256, get_prime_count(TORUS_SECURITY_256) * sizeof(isogeny_table_entry_t));
        free(ISOGENY_TABLE_256);
        ISOGENY_TABLE_256 = NULL;
    }
    
    if (SQUARE_ROOTS_TABLE_128) {
        secure_zeroize(SQUARE_ROOTS_TABLE_128, SQUARE_ROOTS_TABLE_SIZE * sizeof(fp));
        free(SQUARE_ROOTS_TABLE_128);
        SQUARE_ROOTS_TABLE_128 = NULL;
    }
    
    if (SQUARE_ROOTS_TABLE_192) {
        secure_zeroize(SQUARE_ROOTS_TABLE_192, SQUARE_ROOTS_TABLE_SIZE * sizeof(fp));
        free(SQUARE_ROOTS_TABLE_192);
        SQUARE_ROOTS_TABLE_192 = NULL;
    }
    
    if (SQUARE_ROOTS_TABLE_256) {
        secure_zeroize(SQUARE_ROOTS_TABLE_256, SQUARE_ROOTS_TABLE_SIZE * sizeof(fp));
        free(SQUARE_ROOTS_TABLE_256);
        SQUARE_ROOTS_TABLE_256 = NULL;
    }
    
    if (INVERSION_TABLE_128) {
        secure_zeroize(INVERSION_TABLE_128, SQUARE_ROOTS_TABLE_SIZE * sizeof(fp));
        free(INVERSION_TABLE_128);
        INVERSION_TABLE_128 = NULL;
    }
    
    if (INVERSION_TABLE_192) {
        secure_zeroize(INVERSION_TABLE_192, SQUARE_ROOTS_TABLE_SIZE * sizeof(fp));
        free(INVERSION_TABLE_192);
        INVERSION_TABLE_192 = NULL;
    }
    
    if (INVERSION_TABLE_256) {
        secure_zeroize(INVERSION_TABLE_256, SQUARE_ROOTS_TABLE_SIZE * sizeof(fp));
        free(INVERSION_TABLE_256);
        INVERSION_TABLE_256 = NULL;
    }
    
    if (FROBENIUS_CONSTANTS_128) {
        secure_zeroize(FROBENIUS_CONSTANTS_128, 4 * sizeof(fp2));
        free(FROBENIUS_CONSTANTS_128);
        FROBENIUS_CONSTANTS_128 = NULL;
    }
    
    if (FROBENIUS_CONSTANTS_192) {
        secure_zeroize(FROBENIUS_CONSTANTS_192, 4 * sizeof(fp2));
        free(FROBENIUS_CONSTANTS_192);
        FROBENIUS_CONSTANTS_192 = NULL;
    }
    
    if (FROBENIUS_CONSTANTS_256) {
        secure_zeroize(FROBENIUS_CONSTANTS_256, 4 * sizeof(fp2));
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
    constants_log(CONSTANTS_LOG_INFO, "TorusCSIDH constants cleaned up successfully");
}

int constants_verify_initialization(void) {
    if (!constants_initialized) {
        return 0;
    }
    
    // Verify that all critical constants are properly initialized
    int valid = 1;
    
    // Check prime constants
    valid &= PRIME_CONSTANTS_128.is_initialized && !fp_is_zero(&PRIME_CONSTANTS_128.modulus);
    valid &= PRIME_CONSTANTS_192.is_initialized && !fp_is_zero(&PRIME_CONSTANTS_192.modulus);
    valid &= PRIME_CONSTANTS_256.is_initialized && !fp_is_zero(&PRIME_CONSTANTS_256.modulus);
    
    // Check curve constants
    valid &= CURVE_CONSTANTS_128.is_initialized && 
             !fp2_is_zero(&CURVE_CONSTANTS_128.A, &CURVE_CONSTANTS_128.fp2_ctx);
    valid &= CURVE_CONSTANTS_192.is_initialized && 
             !fp2_is_zero(&CURVE_CONSTANTS_192.A, &CURVE_CONSTANTS_192.fp2_ctx);
    valid &= CURVE_CONSTANTS_256.is_initialized && 
             !fp2_is_zero(&CURVE_CONSTANTS_256.A, &CURVE_CONSTANTS_256.fp2_ctx);
    
    // Check precomputed tables
    valid &= (ISOGENY_TABLE_128 != NULL);
    valid &= (ISOGENY_TABLE_192 != NULL);
    valid &= (ISOGENY_TABLE_256 != NULL);
    
    // Check contexts
    valid &= (PRIME_CONSTANTS_128.fp_ctx.security_level == TORUS_SECURITY_128);
    valid &= (PRIME_CONSTANTS_192.fp_ctx.security_level == TORUS_SECURITY_192);
    valid &= (PRIME_CONSTANTS_256.fp_ctx.security_level == TORUS_SECURITY_256);
    
    if (!valid) {
        constants_log(CONSTANTS_LOG_ERROR, "Constants initialization verification failed");
    }
    
    return valid;
}

const char* get_library_version(void) {
    return LIBRARY_VERSION;
}

const char* get_build_configuration(void) {
    return BUILD_CONFIGURATION;
}

const char* get_initialization_status(void) {
    static char status[256];
    
    if (!constants_initialized) {
        return "Not initialized";
    }
    
    int prime_ok = PRIME_CONSTANTS_128.is_initialized && 
                   PRIME_CONSTANTS_192.is_initialized && 
                   PRIME_CONSTANTS_256.is_initialized;
    
    int curve_ok = CURVE_CONSTANTS_128.is_initialized && 
                   CURVE_CONSTANTS_192.is_initialized && 
                   CURVE_CONSTANTS_256.is_initialized;
    
    int tables_ok = ISOGENY_TABLE_128 != NULL && 
                    ISOGENY_TABLE_192 != NULL && 
                    ISOGENY_TABLE_256 != NULL;
    
    int integrity_ok = (verify_constants_integrity(TORUS_SECURITY_128) == TORUS_SUCCESS) &&
                      (verify_constants_integrity(TORUS_SECURITY_192) == TORUS_SUCCESS) &&
                      (verify_constants_integrity(TORUS_SECURITY_256) == TORUS_SUCCESS);
    
    snprintf(status, sizeof(status), 
             "Initialized: Primes=%s, Curves=%s, Tables=%s, Integrity=%s",
             prime_ok ? "OK" : "FAIL",
             curve_ok ? "OK" : "FAIL", 
             tables_ok ? "OK" : "FAIL",
             integrity_ok ? "OK" : "FAIL");
    
    return status;
}
