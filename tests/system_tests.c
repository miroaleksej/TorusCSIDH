// tests/system_tests.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include <complex.h>
#include <limits.h>
#include <float.h>
#include "toruscsidh.h"
#include "openssl_integration/toruscsidh_kem.h"

#define TEST_ITERATIONS 1000
#define PERFORMANCE_ITERATIONS 10000
#define MAX_THREADS 16
#define STRESS_THREADS 8
#define STRESS_DURATION 5 // seconds

/* Data structure for thread testing */
typedef struct {
    HYBRID_KEM_CTX* ctx;
    int thread_id;
    int iterations;
    bool* success;
    pthread_mutex_t* lock;
} ThreadData;

/* Test context structure */
typedef struct {
    HYBRID_KEM_CTX* toruscsidh_ctx;
    EVP_PKEY* p256_key_alice;
    EVP_PKEY* p256_key_bob;
    unsigned char* toruscsidh_pubkey_alice;
    size_t toruscsidh_pubkey_alice_len;
    unsigned char* toruscsidh_pubkey_bob;
    size_t toruscsidh_pubkey_bob_len;
    unsigned char shared_secret_alice[32];
    unsigned char shared_secret_bob[32];
    size_t shared_secret_len;
} TestContext;

/* Helper functions */
double get_current_time(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

void handle_openssl_error(const char* function, int line) {
    unsigned long err;
    char err_str[256];
    
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_str, sizeof(err_str));
        fprintf(stderr, "[%s:%d] OpenSSL error: %s\n", function, line, err_str);
    }
}

bool generate_random_bytes(unsigned char* buf, size_t len) {
    if (RAND_bytes(buf, len) != 1) {
        handle_openssl_error(__FUNCTION__, __LINE__);
        return false;
    }
    return true;
}

/* Test 1: OpenSSL integration testing */
bool test_openssl_integration(TestContext* ctx) {
    printf("🔍 Testing OpenSSL integration...\n");
    
    // Initialize hybrid KEM context
    ctx->toruscsidh_ctx = HYBRID_KEM_new(1);
    if (!ctx->toruscsidh_ctx) {
        fprintf(stderr, "❌ Failed to create TorusCSIDH context\n");
        return false;
    }
    
    // Generate Alice's hybrid key pair
    if (!HYBRID_KEM_keygen(ctx->toruscsidh_ctx, 
                         &ctx->toruscsidh_pubkey_alice, &ctx->toruscsidh_pubkey_alice_len,
                         &ctx->p256_key_alice)) {
        fprintf(stderr, "❌ Failed to generate Alice's hybrid key pair\n");
        return false;
    }
    
    // Generate Bob's hybrid key pair
    if (!HYBRID_KEM_keygen(ctx->toruscsidh_ctx, 
                         &ctx->toruscsidh_pubkey_bob, &ctx->toruscsidh_pubkey_bob_len,
                         &ctx->p256_key_bob)) {
        fprintf(stderr, "❌ Failed to generate Bob's hybrid key pair\n");
        return false;
    }
    
    // Alice computes shared secret using Bob's public key
    if (!HYBRID_KEM_decapsulate(ctx->toruscsidh_ctx,
                              ctx->toruscsidh_pubkey_bob, ctx->toruscsidh_pubkey_bob_len,
                              ctx->p256_key_bob,
                              ctx->shared_secret_alice, &ctx->shared_secret_len)) {
        fprintf(stderr, "❌ Failed to compute Alice's shared secret\n");
        return false;
    }
    
    // Bob computes shared secret using Alice's public key
    if (!HYBRID_KEM_decapsulate(ctx->toruscsidh_ctx,
                              ctx->toruscsidh_pubkey_alice, ctx->toruscsidh_pubkey_alice_len,
                              ctx->p256_key_alice,
                              ctx->shared_secret_bob, &ctx->shared_secret_len)) {
        fprintf(stderr, "❌ Failed to compute Bob's shared secret\n");
        return false;
    }
    
    // Verify shared secrets match
    if (memcmp(ctx->shared_secret_alice, ctx->shared_secret_bob, ctx->shared_secret_len) != 0) {
        fprintf(stderr, "❌ Shared secrets do not match!\n");
        fprintf(stderr, "Alice's secret: ");
        for (size_t i = 0; i < ctx->shared_secret_len; i++) {
            fprintf(stderr, "%02x", ctx->shared_secret_alice[i]);
        }
        fprintf(stderr, "\nBob's secret:   ");
        for (size_t i = 0; i < ctx->shared_secret_len; i++) {
            fprintf(stderr, "%02x", ctx->shared_secret_bob[i]);
        }
        fprintf(stderr, "\n");
        return false;
    }
    
    printf("✅ OpenSSL integration test passed successfully\n");
    printf("   Shared secret length: %zu bytes\n", ctx->shared_secret_len);
    printf("   Public key sizes: Alice=%zu bytes, Bob=%zu bytes\n",
           ctx->toruscsidh_pubkey_alice_len, ctx->toruscsidh_pubkey_bob_len);
    
    return true;
}

/* Test 2: Performance benchmarking */
bool test_performance(TestContext* ctx) {
    printf("⚡ Testing performance metrics...\n");
    
    double start_time, end_time;
    double total_time = 0.0;
    unsigned char shared_secret[32];
    size_t secret_len;
    
    // Key generation performance
    start_time = get_current_time();
    for (int i = 0; i < PERFORMANCE_ITERATIONS; i++) {
        unsigned char* pubkey = NULL;
        size_t pubkey_len = 0;
        EVP_PKEY* p256_key = NULL;
        
        if (!HYBRID_KEM_keygen(ctx->toruscsidh_ctx, &pubkey, &pubkey_len, &p256_key)) {
            fprintf(stderr, "❌ Key generation failed at iteration %d\n", i);
            return false;
        }
        
        // Cleanup
        if (pubkey) free(pubkey);
        if (p256_key) EVP_PKEY_free(p256_key);
    }
    end_time = get_current_time();
    total_time = end_time - start_time;
    
    printf("✅ Key generation performance:\n");
    printf("   Operations: %d\n", PERFORMANCE_ITERATIONS);
    printf("   Total time: %.4f seconds\n", total_time);
    printf("   Operations per second: %.2f\n", PERFORMANCE_ITERATIONS / total_time);
    printf("   Average time per operation: %.2f ms\n", (total_time / PERFORMANCE_ITERATIONS) * 1000);
    
    // Key exchange performance
    start_time = get_current_time();
    for (int i = 0; i < PERFORMANCE_ITERATIONS; i++) {
        if (!HYBRID_KEM_decapsulate(ctx->toruscsidh_ctx,
                                  ctx->toruscsidh_pubkey_bob, ctx->toruscsidh_pubkey_bob_len,
                                  ctx->p256_key_bob,
                                  shared_secret, &secret_len)) {
            fprintf(stderr, "❌ Key exchange failed at iteration %d\n", i);
            return false;
        }
    }
    end_time = get_current_time();
    total_time = end_time - start_time;
    
    printf("✅ Key exchange performance:\n");
    printf("   Operations: %d\n", PERFORMANCE_ITERATIONS);
    printf("   Total time: %.4f seconds\n", total_time);
    printf("   Operations per second: %.2f\n", PERFORMANCE_ITERATIONS / total_time);
    printf("   Average time per operation: %.2f ms\n", (total_time / PERFORMANCE_ITERATIONS) * 1000);
    
    // Memory usage estimation
    struct mallinfo mi = mallinfo();
    printf("✅ Memory usage:\n");
    printf("   Total allocated: %d bytes\n", mi.uordblks);
    printf("   Total free: %d bytes\n", mi.fordblks);
    
    return true;
}

/* Test 3: Fault tolerance testing */
bool test_fault_tolerance(TestContext* ctx) {
    printf("🛡️ Testing fault tolerance...\n");
    
    // Test 1: NULL context handling
    printf("   Testing NULL context handling...");
    if (HYBRID_KEM_keygen(NULL, NULL, NULL, NULL)) {
        fprintf(stderr, "❌ NULL context should fail key generation\n");
        return false;
    }
    printf("✅\n");
    
    // Test 2: Invalid public key handling
    printf("   Testing invalid public key handling...");
    unsigned char invalid_pubkey[256];
    memset(invalid_pubkey, 0xFF, sizeof(invalid_pubkey));
    
    unsigned char shared_secret[32];
    size_t secret_len = sizeof(shared_secret);
    
    if (HYBRID_KEM_decapsulate(ctx->toruscsidh_ctx,
                             invalid_pubkey, sizeof(invalid_pubkey),
                             ctx->p256_key_bob,
                             shared_secret, &secret_len)) {
        fprintf(stderr, "❌ Invalid public key should fail decryption\n");
        return false;
    }
    printf("✅\n");
    
    // Test 3: Memory stress testing
    printf("   Testing memory stress tolerance...");
    void** allocations = malloc(1000 * sizeof(void*));
    if (!allocations) {
        fprintf(stderr, "❌ Failed to allocate memory for stress test\n");
        return false;
    }
    
    int alloc_count = 0;
    for (int i = 0; i < 1000; i++) {
        allocations[i] = malloc(1024 * 1024); // 1MB allocation
        if (!allocations[i]) {
            break;
        }
        alloc_count++;
    }
    
    // Test key generation under memory pressure
    bool success = false;
    unsigned char* pubkey = NULL;
    size_t pubkey_len = 0;
    EVP_PKEY* p256_key = NULL;
    
    if (HYBRID_KEM_keygen(ctx->toruscsidh_ctx, &pubkey, &pubkey_len, &p256_key)) {
        success = true;
        if (pubkey) free(pubkey);
        if (p256_key) EVP_PKEY_free(p256_key);
    }
    
    // Cleanup
    for (int i = 0; i < alloc_count; i++) {
        if (allocations[i]) free(allocations[i]);
    }
    free(allocations);
    
    if (!success) {
        fprintf(stderr, "❌ Key generation failed under memory pressure\n");
        return false;
    }
    printf("✅\n");
    
    // Test 4: Corrupted data handling
    printf("   Testing corrupted data handling...");
    unsigned char* corrupted_pubkey = malloc(ctx->toruscsidh_pubkey_bob_len);
    if (!corrupted_pubkey) {
        fprintf(stderr, "❌ Failed to allocate memory for corrupted key\n");
        return false;
    }
    
    memcpy(corrupted_pubkey, ctx->toruscsidh_pubkey_bob, ctx->toruscsidh_pubkey_bob_len);
    // Corrupt the middle of the key
    corrupted_pubkey[ctx->toruscsidh_pubkey_bob_len / 2] ^= 0xFF;
    
    if (HYBRID_KEM_decapsulate(ctx->toruscsidh_ctx,
                             corrupted_pubkey, ctx->toruscsidh_pubkey_bob_len,
                             ctx->p256_key_bob,
                             shared_secret, &secret_len)) {
        fprintf(stderr, "❌ Should fail with corrupted public key\n");
        free(corrupted_pubkey);
        return false;
    }
    free(corrupted_pubkey);
    printf("✅\n");
    
    // Test 5: Thread safety under concurrent access
    printf("   Testing thread safety under concurrent access...");
    
    pthread_t threads[MAX_THREADS];
    bool thread_success[MAX_THREADS] = {false};
    pthread_mutex_t lock;
    pthread_mutex_init(&lock, NULL);
    
    for (int i = 0; i < MAX_THREADS; i++) {
        ThreadData* data = malloc(sizeof(ThreadData));
        if (!data) {
            fprintf(stderr, "❌ Failed to allocate thread data\n");
            pthread_mutex_destroy(&lock);
            return false;
        }
        
        data->ctx = ctx->toruscsidh_ctx;
        data->thread_id = i;
        data->iterations = 100;
        data->success = &thread_success[i];
        data->lock = &lock;
        
        if (pthread_create(&threads[i], NULL, 
                          (void*(*)(void*))[](void* arg) {
                              ThreadData* data = (ThreadData*)arg;
                              *data->success = true;
                              
                              for (int j = 0; j < data->iterations; j++) {
                                  unsigned char* pubkey = NULL;
                                  size_t pubkey_len = 0;
                                  EVP_PKEY* p256_key = NULL;
                                  
                                  if (!HYBRID_KEM_keygen(data->ctx, &pubkey, &pubkey_len, &p256_key)) {
                                      pthread_mutex_lock(data->lock);
                                      fprintf(stderr, "❌ Thread %d failed at iteration %d\n", 
                                              data->thread_id, j);
                                      pthread_mutex_unlock(data->lock);
                                      *data->success = false;
                                      break;
                                  }
                                  
                                  if (pubkey) free(pubkey);
                                  if (p256_key) EVP_PKEY_free(p256_key);
                              }
                              
                              free(data);
                              return NULL;
                          }, data) != 0) {
            fprintf(stderr, "❌ Failed to create thread %d\n", i);
            pthread_mutex_destroy(&lock);
            free(data);
            return false;
        }
    }
    
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    bool all_success = true;
    for (int i = 0; i < MAX_THREADS; i++) {
        if (!thread_success[i]) {
            all_success = false;
            break;
        }
    }
    
    pthread_mutex_destroy(&lock);
    
    if (!all_success) {
        fprintf(stderr, "❌ Concurrent operations failed\n");
        return false;
    }
    printf("✅\n");
    
    printf("✅ All fault tolerance tests passed successfully\n");
    return true;
}

/* Test 4: Security testing */
bool test_security(TestContext* ctx) {
    printf("🔒 Testing security properties...\n");
    
    // Test 1: Side-channel resistance (timing analysis)
    printf("   Testing side-channel resistance (timing analysis)...");
    
    double timings[1000];
    unsigned char shared_secret[32];
    size_t secret_len;
    
    // Warm up cache
    for (int i = 0; i < 10; i++) {
        HYBRID_KEM_decapsulate(ctx->toruscsidh_ctx,
                             ctx->toruscsidh_pubkey_bob, ctx->toruscsidh_pubkey_bob_len,
                             ctx->p256_key_bob,
                             shared_secret, &secret_len);
    }
    
    // Measure timing for key exchange operations
    for (int i = 0; i < 1000; i++) {
        double start = get_current_time();
        HYBRID_KEM_decapsulate(ctx->toruscsidh_ctx,
                             ctx->toruscsidh_pubkey_bob, ctx->toruscsidh_pubkey_bob_len,
                             ctx->p256_key_bob,
                             shared_secret, &secret_len);
        double end = get_current_time();
        timings[i] = (end - start) * 1000000; // microseconds
    }
    
    // Calculate statistical properties
    double min_time = timings[0];
    double max_time = timings[0];
    double sum_time = 0.0;
    double squared_sum = 0.0;
    
    for (int i = 0; i < 1000; i++) {
        if (timings[i] < min_time) min_time = timings[i];
        if (timings[i] > max_time) max_time = timings[i];
        sum_time += timings[i];
        squared_sum += timings[i] * timings[i];
    }
    
    double mean_time = sum_time / 1000.0;
    double variance = (squared_sum / 1000.0) - (mean_time * mean_time);
    double std_dev = sqrt(variance);
    double timing_ratio = max_time / min_time;
    
    printf("\n");
    printf("      Minimum time: %.2f μs\n", min_time);
    printf("      Maximum time: %.2f μs\n", max_time);
    printf("      Mean time: %.2f μs\n", mean_time);
    printf("      Standard deviation: %.2f μs\n", std_dev);
    printf("      Timing ratio (max/min): %.4f\n", timing_ratio);
    
    if (timing_ratio > 1.01) {
        fprintf(stderr, "❌ Timing variation exceeds 1%% threshold (%.4f)\n", timing_ratio);
        fprintf(stderr, "    This may indicate vulnerability to timing side-channel attacks\n");
        return false;
    }
    printf("✅ Timing variation within acceptable limits\n");
    
    // Test 2: Memory zeroization verification
    printf("   Testing memory zeroization...");
    
    // Create sensitive data
    unsigned char sensitive_data[64];
    for (size_t i = 0; i < sizeof(sensitive_data); i++) {
        sensitive_data[i] = (unsigned char)(i % 256);
    }
    
    // Copy sensitive data to stack
    unsigned char stack_copy[64];
    memcpy(stack_copy, sensitive_data, sizeof(stack_copy));
    
    // Create a new context that will handle sensitive data
    HYBRID_KEM_CTX* temp_ctx = HYBRID_KEM_new(1);
    if (!temp_ctx) {
        fprintf(stderr, "❌ Failed to create temporary context\n");
        return false;
    }
    
    // Generate a key that should use the sensitive data
    unsigned char* temp_pubkey;
    size_t temp_pubkey_len;
    EVP_PKEY* temp_p256_key;
    
    if (!HYBRID_KEM_keygen(temp_ctx, &temp_pubkey, &temp_pubkey_len, &temp_p256_key)) {
        fprintf(stderr, "❌ Failed to generate temporary key\n");
        HYBRID_KEM_free(temp_ctx);
        return false;
    }
    
    // Free the context (should zeroize sensitive data)
    HYBRID_KEM_free(temp_ctx);
    
    // Check if stack data was zeroized
    bool zeroized = true;
    for (size_t i = 0; i < sizeof(stack_copy); i++) {
        if (stack_copy[i] != 0) {
            zeroized = false;
            break;
        }
    }
    
    if (!zeroized) {
        fprintf(stderr, "❌ Memory zeroization test failed\n");
        if (temp_pubkey) free(temp_pubkey);
        if (temp_p256_key) EVP_PKEY_free(temp_p256_key);
        return false;
    }
    
    if (temp_pubkey) free(temp_pubkey);
    if (temp_p256_key) EVP_PKEY_free(temp_p256_key);
    printf("✅\n");
    
    // Test 3: Input validation against malformed data
    printf("   Testing input validation against malformed data...\n");
    
    // Test with truncated public key
    unsigned char truncated_key[16]; // Too short
    memset(truncated_key, 0, sizeof(truncated_key));
    
    printf("      Testing truncated public key...");
    if (HYBRID_KEM_decapsulate(ctx->toruscsidh_ctx,
                             truncated_key, sizeof(truncated_key),
                             ctx->p256_key_bob,
                             shared_secret, &secret_len)) {
        fprintf(stderr, "❌ Should fail with truncated public key\n");
        return false;
    }
    printf("✅\n");
    
    // Test with excessively long public key
    unsigned char* long_key = malloc(1000000); // 1MB key
    if (!long_key) {
        fprintf(stderr, "❌ Failed to allocate memory for long key test\n");
        return false;
    }
    memset(long_key, 0, 1000000);
    
    printf("      Testing excessively long public key...");
    if (HYBRID_KEM_decapsulate(ctx->toruscsidh_ctx,
                             long_key, 1000000,
                             ctx->p256_key_bob,
                             shared_secret, &secret_len)) {
        fprintf(stderr, "❌ Should fail with excessively long public key\n");
        free(long_key);
        return false;
    }
    free(long_key);
    printf("✅\n");
    
    // Test with random garbage data
    unsigned char garbage_key[256];
    if (!generate_random_bytes(garbage_key, sizeof(garbage_key))) {
        fprintf(stderr, "❌ Failed to generate random garbage data\n");
        return false;
    }
    
    printf("      Testing random garbage public key...");
    if (HYBRID_KEM_decapsulate(ctx->toruscsidh_ctx,
                             garbage_key, sizeof(garbage_key),
                             ctx->p256_key_bob,
                             shared_secret, &secret_len)) {
        fprintf(stderr, "❌ Should fail with random garbage public key\n");
        return false;
    }
    printf("✅\n");
    
    printf("✅ All security tests passed successfully\n");
    return true;
}

/* Stress test: Concurrent operations under load */
void* stress_test_worker(void* arg) {
    ThreadData* data = (ThreadData*)arg;
    *data->success = true;
    
    for (int i = 0; i < data->iterations && *data->success; i++) {
        unsigned char* pubkey = NULL;
        size_t pubkey_len = 0;
        EVP_PKEY* p256_key = NULL;
        
        if (!HYBRID_KEM_keygen(data->ctx, &pubkey, &pubkey_len, &p256_key)) {
            pthread_mutex_lock(data->lock);
            fprintf(stderr, "❌ Thread %d failed at iteration %d during stress test\n", 
                    data->thread_id, i);
            pthread_mutex_unlock(data->lock);
            *data->success = false;
            break;
        }
        
        unsigned char shared_secret[32];
        size_t secret_len = sizeof(shared_secret);
        
        if (!HYBRID_KEM_decapsulate(data->ctx,
                                  ctx->toruscsidh_pubkey_bob, ctx->toruscsidh_pubkey_bob_len,
                                  ctx->p256_key_bob,
                                  shared_secret, &secret_len)) {
            pthread_mutex_lock(data->lock);
            fprintf(stderr, "❌ Thread %d failed decryption at iteration %d during stress test\n", 
                    data->thread_id, i);
            pthread_mutex_unlock(data->lock);
            *data->success = false;
            if (pubkey) free(pubkey);
            if (p256_key) EVP_PKEY_free(p256_key);
            break;
        }
        
        if (pubkey) free(pubkey);
        if (p256_key) EVP_PKEY_free(p256_key);
    }
    
    return NULL;
}

bool test_stress(TestContext* ctx) {
    printf("🔥 Testing system under stress conditions...\n");
    
    pthread_t threads[STRESS_THREADS];
    bool thread_success[STRESS_THREADS] = {false};
    pthread_mutex_t lock;
    pthread_mutex_init(&lock, NULL);
    
    // Start stress test threads
    for (int i = 0; i < STRESS_THREADS; i++) {
        ThreadData* data = malloc(sizeof(ThreadData));
        if (!data) {
            fprintf(stderr, "❌ Failed to allocate thread data for stress test\n");
            pthread_mutex_destroy(&lock);
            return false;
        }
        
        data->ctx = ctx->toruscsidh_ctx;
        data->thread_id = i;
        data->iterations = 1000;
        data->success = &thread_success[i];
        data->lock = &lock;
        
        if (pthread_create(&threads[i], NULL, stress_test_worker, data) != 0) {
            fprintf(stderr, "❌ Failed to create stress test thread %d\n", i);
            pthread_mutex_destroy(&lock);
            free(data);
            return false;
        }
    }
    
    // Run for specified duration
    sleep(STRESS_DURATION);
    
    // Check results
    bool all_success = true;
    for (int i = 0; i < STRESS_THREADS; i++) {
        pthread_join(threads[i], NULL);
        if (!thread_success[i]) {
            all_success = false;
            fprintf(stderr, "❌ Stress test failed for thread %d\n", i);
        }
    }
    
    pthread_mutex_destroy(&lock);
    
    if (all_success) {
        printf("✅ Stress test passed successfully\n");
        printf("   Duration: %d seconds\n", STRESS_DURATION);
        printf("   Threads: %d\n", STRESS_THREADS);
        printf("   Total operations: %d\n", STRESS_THREADS * 1000);
    } else {
        fprintf(stderr, "❌ Stress test failed\n");
        return false;
    }
    
    return true;
}

/* Cleanup function */
void cleanup_test_context(TestContext* ctx) {
    if (ctx->toruscsidh_ctx) {
        HYBRID_KEM_free(ctx->toruscsidh_ctx);
    }
    if (ctx->p256_key_alice) {
        EVP_PKEY_free(ctx->p256_key_alice);
    }
    if (ctx->p256_key_bob) {
        EVP_PKEY_free(ctx->p256_key_bob);
    }
    if (ctx->toruscsidh_pubkey_alice) {
        free(ctx->toruscsidh_pubkey_alice);
    }
    if (ctx->toruscsidh_pubkey_bob) {
        free(ctx->toruscsidh_pubkey_bob);
    }
    
    // Clear sensitive data from memory
    memset(ctx->shared_secret_alice, 0, sizeof(ctx->shared_secret_alice));
    memset(ctx->shared_secret_bob, 0, sizeof(ctx->shared_secret_bob));
    
    printf("🧹 Test context cleaned up successfully\n");
}

/* Main system test function */
int main(int argc, char** argv) {
    printf("🚀 Starting TorusCSIDH System Tests\n");
    printf("=====================================\n");
    
    // Initialize OpenSSL
    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                           OPENSSL_INIT_ADD_ALL_CIPHERS | 
                           OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)) {
        fprintf(stderr, "❌ Failed to initialize OpenSSL\n");
        return 1;
    }
    
    // Seed random number generator
    unsigned char seed[32];
    if (!generate_random_bytes(seed, sizeof(seed))) {
        fprintf(stderr, "❌ Failed to seed random number generator\n");
        OPENSSL_cleanup();
        return 1;
    }
    
    RAND_seed(seed, sizeof(seed));
    
    // Initialize test context
    TestContext ctx = {0};
    
    // Run test modules
    bool all_tests_passed = true;
    
    if (!test_openssl_integration(&ctx)) {
        fprintf(stderr, "❌ OpenSSL integration test failed\n");
        all_tests_passed = false;
    } else {
        printf("\n✅ OpenSSL integration test completed successfully\n");
    }
    
    if (all_tests_passed && !test_performance(&ctx)) {
        fprintf(stderr, "❌ Performance test failed\n");
        all_tests_passed = false;
    } else if (all_tests_passed) {
        printf("\n✅ Performance test completed successfully\n");
    }
    
    if (all_tests_passed && !test_fault_tolerance(&ctx)) {
        fprintf(stderr, "❌ Fault tolerance test failed\n");
        all_tests_passed = false;
    } else if (all_tests_passed) {
        printf("\n✅ Fault tolerance test completed successfully\n");
    }
    
    if (all_tests_passed && !test_security(&ctx)) {
        fprintf(stderr, "❌ Security test failed\n");
        all_tests_passed = false;
    } else if (all_tests_passed) {
        printf("\n✅ Security test completed successfully\n");
    }
    
    if (all_tests_passed && !test_stress(&ctx)) {
        fprintf(stderr, "❌ Stress test failed\n");
        all_tests_passed = false;
    } else if (all_tests_passed) {
        printf("\n✅ Stress test completed successfully\n");
    }
    
    // Cleanup
    cleanup_test_context(&ctx);
    OPENSSL_cleanup();
    
    // Final result
    printf("\n");
    printf("=====================================\n");
    if (all_tests_passed) {
        printf("🎉 🎉 🎉 ALL SYSTEM TESTS PASSED 🎉 🎉 🎉\n");
        printf("System is ready for production deployment\n");
        return 0;
    } else {
        printf("❌ ❌ ❌ SOME SYSTEM TESTS FAILED ❌ ❌ ❌\n");
        printf("System is NOT ready for production deployment\n");
        return 1;
    }
}
