// tests/integration/key_exchange.rs
//! Integration tests for the TorusCSIDH key exchange protocol with comprehensive security validation.
//! These tests verify the complete workflow from key generation to shared secret computation,
//! including resistance to known attacks and performance characteristics.

use rug::{Integer, ops::Pow};
use std::time::{Instant, Duration};
use proptest::prelude::*;
use criterion::{Criterion, black_box};
use toruscsidh::{
    params::NistLevel1Params,
    arithmetic::{Fp, Fp2},
    curves::{
        EllipticCurve,
        GeometricVerifier,
        VerificationResult,
        ProjectivePoint
    },
    protocols::key_exchange::{TorusCSIDHKeyExchange, SharedSecret},
    errors::TorusCSIDHError,
    security::rate_limiting::RateLimiter
};

/// Test fixture for key exchange operations
struct KeyExchangeFixture {
    params: &'static NistLevel1Params,
    protocol: TorusCSIDHKeyExchange,
    verifier: GeometricVerifier,
}

impl KeyExchangeFixture {
    /// Setup test fixture with fresh parameters
    fn new() -> Self {
        let params = NistLevel1Params::global();
        let protocol = TorusCSIDHKeyExchange::new(params).expect("Protocol initialization failed");
        let verifier = GeometricVerifier::new(params);
        Self {
            params,
            protocol,
            verifier,
        }
    }

    /// Generate a valid key pair for testing
    fn generate_keypair(&self) -> (Vec<i32>, EllipticCurve) {
        let private_key = self.protocol.generate_private_key();
        let public_key = self.protocol.generate_public_key(&private_key)
            .expect("Public key generation should succeed");
        (private_key, public_key)
    }

    /// Generate an invalid curve for attack simulation
    fn generate_invalid_curve(&self) -> EllipticCurve {
        // Create a curve with invalid coefficients
        let invalid_a = Fp2::new(
            Fp::new(Integer::from(5), self.params), // Non-supersingular coefficient
            Fp::new(Integer::from(0), self.params),
            self.params
        );
        EllipticCurve {
            a_coeff: invalid_a,
            b_coeff: self.protocol.base_curve.b_coeff.clone(),
            params: self.params,
        }
    }
}

#[test]
fn test_full_key_exchange_workflow() {
    let fixture = KeyExchangeFixture::new();
    
    // Generate key pairs for both parties
    let (alice_private, alice_public) = fixture.generate_keypair();
    let (bob_private, bob_public) = fixture.generate_keypair();
    
    // Alice computes shared secret with Bob's public key
    let alice_shared = fixture.protocol.compute_shared_secret(&alice_private, &bob_public)
        .expect("Alice should compute shared secret successfully");
    
    // Bob computes shared secret with Alice's public key
    let bob_shared = fixture.protocol.compute_shared_secret(&bob_private, &alice_public)
        .expect("Bob should compute shared secret successfully");
    
    // Verify shared secrets match
    assert_eq!(alice_shared.derived_key, bob_shared.derived_key,
               "Shared secrets must be identical for successful key exchange");
    
    // Verify security properties
    assert_eq!(alice_shared.derived_key.len(), 32,
               "Shared secret must be 32 bytes for SHA-256 output");
    assert_ne!(alice_shared.derived_key, vec![0u8; 32],
               "Shared secret must not be all zeros");
    
    // Verify verification metadata
    let security_level = alice_shared.verify_metadata(&fixture.verifier);
    assert!(security_level >= 128,
            "Security level must be at least 128 bits for NIST Level 1");
}

#[test]
fn test_resistance_to_invalid_curve_attacks() {
    let fixture = KeyExchangeFixture::new();
    
    // Generate valid key pair for Alice
    let (alice_private, _) = fixture.generate_keypair();
    
    // Create invalid curve (potential attack vector)
    let invalid_curve = fixture.generate_invalid_curve();
    
    // Attempt to compute shared secret with invalid curve
    let result = fixture.protocol.compute_shared_secret(&alice_private, &invalid_curve);
    
    // Verify attack is detected and rejected
    assert!(result.is_err(), "Invalid curve attack should be detected");
    
    // Verify the error is security-related
    if let Err(TorusCSIDHError::SecurityViolation { severity, .. }) = result {
        assert!(severity == SecuritySeverity::Critical,
                "Security violation must be classified as critical");
    } else {
        panic!("Expected security violation error for invalid curve attack");
    }
    
    // Verify geometric verification detects the invalid curve
    let verification_result = fixture.verifier.verify_curve(&invalid_curve);
    assert_ne!(verification_result, VerificationResult::Valid,
               "Geometric verification must detect invalid curves");
}

#[test]
fn test_key_exchange_with_malformed_data() {
    let fixture = KeyExchangeFixture::new();
    
    // Test case 1: Too short private key
    let short_private_key = vec![1; 10]; // Should be 14 elements for NIST Level 1
    let (_, valid_public) = fixture.generate_keypair();
    let short_result = fixture.protocol.compute_shared_secret(&short_private_key, &valid_public);
    assert!(short_result.is_err(), "Should reject short private key");
    
    // Test case 2: Too long private key
    let mut long_private_key = vec![1; 20];
    long_private_key[14] = 999; // Out of bounds value
    let long_result = fixture.protocol.compute_shared_secret(&long_private_key, &valid_public);
    assert!(long_result.is_err(), "Should reject long private key");
    
    // Test case 3: Invalid public key coordinates
    let invalid_public = EllipticCurve {
        a_coeff: Fp2::new(
            Fp::new(Integer::from(999999), fixture.params),
            Fp::new(Integer::from(0), fixture.params),
            fixture.params
        ),
        b_coeff: Fp2::new(
            Fp::new(Integer::from(888888), fixture.params),
            Fp::new(Integer::from(0), fixture.params),
            fixture.params
        ),
        params: fixture.params,
    };
    let (valid_private, _) = fixture.generate_keypair();
    let invalid_result = fixture.protocol.compute_shared_secret(&valid_private, &invalid_public);
    assert!(invalid_result.is_err(), "Should reject invalid public key coordinates");
}

proptest! {
    #[test]
    fn test_key_exchange_properties(
        seed in 0u64..1000
    ) {
        let fixture = KeyExchangeFixture::new();
        
        // Generate deterministic keys for testing
        let mut alice_private = fixture.protocol.generate_private_key();
        let mut bob_private = fixture.protocol.generate_private_key();
        
        // Make keys deterministic based on seed
        for i in 0..alice_private.len() {
            alice_private[i] = ((seed as i32 + i as i32) % (2 * fixture.params.bounds[i] + 1)) - fixture.params.bounds[i] as i32;
            bob_private[i] = ((seed as i32 * 2 + i as i32) % (2 * fixture.params.bounds[i] + 1)) - fixture.params.bounds[i] as i32;
        }
        
        let alice_public = fixture.protocol.generate_public_key(&alice_private).expect("Alice public key failed");
        let bob_public = fixture.protocol.generate_public_key(&bob_private).expect("Bob public key failed");
        
        let alice_shared = fixture.protocol.compute_shared_secret(&alice_private, &bob_public).expect("Alice shared secret failed");
        let bob_shared = fixture.protocol.compute_shared_secret(&bob_private, &alice_public).expect("Bob shared secret failed");
        
        prop_assert_eq!(alice_shared.derived_key, bob_shared.derived_key,
                       "Shared secrets must be identical for same key material");
        
        // Verify the shared secret is not trivial
        let zero_key = vec![0u8; 32];
        prop_assert_ne!(alice_shared.derived_key, zero_key,
                       "Shared secret must not be trivial (all zeros)");
        
        // Verify the shared secret has sufficient entropy
        let entropy = calculate_entropy(&alice_shared.derived_key);
        prop_assert!(entropy > 4.0, "Shared secret entropy must be greater than 4 bits/byte");
    }
    
    #[test]
    fn test_side_channel_resistance(
        seeds in proptest::collection::vec(0u64..1000, 1..10)
    ) {
        let fixture = KeyExchangeFixture::new();
        let (_, bob_public) = fixture.generate_keypair();
        
        // Measure timing for different private keys
        let mut timings = Vec::new();
        
        for seed in seeds {
            let mut alice_private = fixture.protocol.generate_private_key();
            
            // Create varying private keys based on seed
            for i in 0..alice_private.len() {
                alice_private[i] = ((seed as i32 + i as i32) % (2 * fixture.params.bounds[i] + 1)) - fixture.params.bounds[i] as i32;
            }
            
            let start = Instant::now();
            let _ = fixture.protocol.compute_shared_secret(&alice_private, &bob_public);
            let elapsed = start.elapsed().as_nanos();
            timings.push(elapsed);
        }
        
        // Analyze timing variation
        let min_time = *timings.iter().min().unwrap();
        let max_time = *timings.iter().max().unwrap();
        let ratio = max_time as f64 / min_time as f64;
        
        // Timing variation must be minimal for side-channel resistance
        prop_assert!(ratio < 1.01, "Timing variation ratio must be < 1.01 (is {})", ratio);
    }
}

#[test]
fn test_dos_attack_resistance() {
    let fixture = KeyExchangeFixture::new();
    let rate_limiter = RateLimiter::new(10, 1.0); // 10 tokens, 1 token/second recovery
    
    // Generate a valid public key for attack simulation
    let (_, bob_public) = fixture.generate_keypair();
    
    // Simulate DoS attack with rapid requests
    let malicious_client_id = "attacker123";
    let mut successful_requests = 0;
    let mut failed_requests = 0;
    
    for i in 0..20 {
        // Craft malicious private key with extreme values
        let mut malicious_private = vec![0; fixture.params.primes.len()];
        for j in 0..malicious_private.len() {
            malicious_private[j] = if i % 2 == 0 {
                fixture.params.bounds[j] * 100  // Extremely large positive value
            } else {
                -fixture.params.bounds[j] * 100 // Extremely large negative value
            };
        }
        
        // Check rate limiting before processing
        if rate_limiter.check_allow(malicious_client_id, 1) {
            let result = fixture.protocol.compute_shared_secret(&malicious_private, &bob_public);
            if result.is_ok() {
                successful_requests += 1;
            } else {
                failed_requests += 1;
            }
        } else {
            failed_requests += 1;
        }
    }
    
    // Verify DoS protection is effective
    assert!(successful_requests <= 10, "Rate limiting should limit successful requests");
    assert!(failed_requests >= 10, "Most requests should be blocked by rate limiting");
    
    // Verify system remains operational after attack
    let (legitimate_private, _) = fixture.generate_keypair();
    let legitimate_result = fixture.protocol.compute_shared_secret(&legitimate_private, &bob_public);
    assert!(legitimate_result.is_ok(), "System should remain operational for legitimate users");
}

#[test]
fn test_performance_characteristics() {
    let fixture = KeyExchangeFixture::new();
    
    // Warm up the system
    for _ in 0..5 {
        let (private_key1, public_key1) = fixture.generate_keypair();
        let (private_key2, _) = fixture.generate_keypair();
        fixture.protocol.compute_shared_secret(&private_key1, &public_key1).ok();
        fixture.protocol.compute_shared_secret(&private_key2, &public_key1).ok();
    }
    
    const ITERATIONS: usize = 100;
    let mut total_time = Duration::new(0, 0);
    
    // Measure key exchange performance
    for _ in 0..ITERATIONS {
        let (alice_private, alice_public) = fixture.generate_keypair();
        let (_, bob_public) = fixture.generate_keypair();
        
        let start = Instant::now();
        let _ = fixture.protocol.compute_shared_secret(&alice_private, &bob_public).expect("Key exchange failed");
        let elapsed = start.elapsed();
        
        total_time += elapsed;
    }
    
    let avg_time = total_time / ITERATIONS as u32;
    let avg_micros = avg_time.as_micros() as f64;
    
    // Performance benchmarks for NIST Level 1
    println!("Average key exchange time: {:.2} μs", avg_micros);
    println!("Key exchanges per second: {:.0}", 1_000_000.0 / avg_micros);
    
    // Verify performance meets requirements
    assert!(avg_micros <= 1500.0, 
            "Average key exchange time must be <= 1500 μs (is {:.2} μs)", avg_micros);
    assert!(1_000_000.0 / avg_micros >= 650.0,
            "Must achieve at least 650 key exchanges per second (is {:.0})", 
            1_000_000.0 / avg_micros);
}

#[test]
fn test_security_metadata_analysis() {
    let fixture = KeyExchangeFixture::new();
    
    // Generate key pairs
    let (alice_private, alice_public) = fixture.generate_keypair();
    let (bob_private, bob_public) = fixture.generate_keypair();
    
    // Compute shared secrets
    let alice_shared = fixture.protocol.compute_shared_secret(&alice_private, &bob_public)
        .expect("Alice shared secret computation failed");
    let bob_shared = fixture.protocol.compute_shared_secret(&bob_private, &alice_public)
        .expect("Bob shared secret computation failed");
    
    // Analyze security metadata
    let alice_analysis = analyze_security_metadata(&alice_shared.metadata);
    let bob_analysis = analyze_security_metadata(&bob_shared.metadata);
    
    // Verify metadata consistency
    assert_eq!(alice_analysis.verification_steps, bob_analysis.verification_steps,
               "Verification steps must be consistent between parties");
    assert_eq!(alice_analysis.suspicious_curves_detected, bob_analysis.suspicious_curves_detected,
               "Suspicious curve detection must be consistent");
    
    // Verify security guarantees
    assert!(alice_analysis.max_verification_time < 100_000, // 100 microseconds
            "Maximum verification time must be < 100 μs (is {} ns)",
            alice_analysis.max_verification_time);
    assert_eq!(alice_analysis.suspicious_curves_detected, 0,
               "No suspicious curves should be detected in valid exchange");
}

/// Analyze security metadata for comprehensive validation
struct SecurityAnalysis {
    verification_steps: usize,
    max_verification_time: u64,
    suspicious_curves_detected: usize,
    entropy_estimate: f64,
}

fn analyze_security_metadata(metadata: &VerificationMetadata) -> SecurityAnalysis {
    // Calculate entropy estimate from verification times
    let entropy_estimate = (metadata.max_verification_time as f64) / 1000.0;
    
    SecurityAnalysis {
        verification_steps: metadata.verification_steps,
        max_verification_time: metadata.max_verification_time,
        suspicious_curves_detected: metadata.suspicious_curves_detected,
        entropy_estimate,
    }
}

/// Calculate entropy of byte sequence
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    
    for &byte in data {
        counts[byte as usize] += 1;
    }
    
    let total = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}

#[test]
fn test_replay_attack_detection() {
    let fixture = KeyExchangeFixture::new();
    
    // Generate initial key exchange
    let (alice_private, alice_public) = fixture.generate_keypair();
    let (bob_private, bob_public) = fixture.generate_keypair();
    
    // First exchange
    let first_shared = fixture.protocol.compute_shared_secret(&alice_private, &bob_public)
        .expect("First key exchange failed");
    
    // Attempt to replay the same parameters
    let replay_result = fixture.protocol.compute_shared_secret(&alice_private, &bob_public);
    
    // Replay should work (stateless protocol) but we should detect unusual patterns
    assert!(replay_result.is_ok(), "Replay should be valid for stateless protocol");
    
    let replay_shared = replay_result.unwrap();
    assert_eq!(first_shared.derived_key, replay_shared.derived_key,
               "Replayed exchange should produce same shared secret");
    
    // Now test with rate limiting for replay detection
    let rate_limiter = RateLimiter::new(5, 0.5); // 5 tokens, 0.5 tokens/second recovery
    let client_id = "replay_attacker";
    
    // Simulate rapid replays
    let mut replay_count = 0;
    for i in 0..10 {
        if rate_limiter.check_allow(client_id, 1) {
            fixture.protocol.compute_shared_secret(&alice_private, &bob_public).ok();
            replay_count += 1;
        }
    }
    
    assert!(replay_count <= 5, "Rate limiting should prevent excessive replays");
}

#[test]
fn test_fault_injection_resistance() {
    let fixture = KeyExchangeFixture::new();
    
    // Generate valid keys
    let (valid_private, valid_public) = fixture.generate_keypair();
    
    // Create fault-injected curve by slightly modifying coordinates
    let fault_injected_curve = {
        let mut curve = valid_public.clone();
        let current_value = &curve.a_coeff.real.value;
        let fault_value = current_value + Integer::from(1);
        curve.a_coeff = Fp2::new(
            Fp::new(fault_value, fixture.params),
            curve.a_coeff.imag.clone(),
            fixture.params
        );
        curve
    };
    
    // Attempt to compute shared secret with fault-injected curve
    let result = fixture.protocol.compute_shared_secret(&valid_private, &fault_injected_curve);
    
    // Fault injection should be detected
    assert!(result.is_err(), "Fault injection should be detected");
    
    // Verify the error is security-related
    if let Err(TorusCSIDHError::SecurityViolation { violation_type, severity, .. }) = result {
        assert!(violation_type.contains("fault"),
                "Error should indicate fault injection attack");
        assert!(severity == SecuritySeverity::Critical,
                "Fault injection should be critical security violation");
    } else {
        panic!("Expected security violation error for fault injection");
    }
}

#[test]
fn test_key_exchange_with_large_parameters() {
    // Test with artificially large parameters to stress the system
    let params = NistLevel1Params::global();
    let large_bounds: [i32; 14] = [10; 14]; // Much larger than standard bounds
    
    // Create protocol with large bounds
    let mut protocol = TorusCSIDHKeyExchange::new(params).expect("Protocol initialization failed");
    unsafe {
        // Use unsafe to modify bounds for testing purposes only
        std::ptr::write(&mut protocol.params.bounds as *mut [i32; 14], large_bounds);
    }
    
    // Generate keys with large parameters
    let private_key = protocol.generate_private_key();
    
    // Key generation should handle large parameters gracefully
    for (i, &exponent) in private_key.iter().enumerate() {
        assert!(exponent.abs() <= large_bounds[i],
                "Exponent {} must be within large bounds (is {}, bound is {})",
                i, exponent, large_bounds[i]);
    }
    
    // Public key generation should not panic
    let public_key = protocol.generate_public_key(&private_key);
    assert!(public_key.is_ok(), "Public key generation should succeed with large parameters");
}

#[test]
fn test_zeroization_security() {
    let fixture = KeyExchangeFixture::new();
    
    // Generate keys
    let (private_key, public_key) = fixture.generate_keypair();
    
    // Create copy of private key values before zeroization
    let private_key_bytes: Vec<i32> = private_key.clone();
    
    // Compute shared secret
    let shared_secret = fixture.protocol.compute_shared_secret(&private_key, &public_key)
        .expect("Key exchange failed");
    
    // Check that private key data is still present (not zeroized yet)
    assert_eq!(private_key[0], private_key_bytes[0],
               "Private key should not be zeroized before explicit zeroization");
    
    // Explicitly zeroize private key
    zeroize::Zeroize::zeroize(&mut private_key.clone());
    
    // Verify zeroization was effective
    let mut all_zero = true;
    for &value in &private_key {
        if value != 0 {
            all_zero = false;
            break;
        }
    }
    
    assert!(all_zero, "Private key must be completely zeroized after explicit zeroization");
    
    // Verify shared secret is not zeroized
    assert!(!shared_secret.derived_key.iter().all(|&b| b == 0),
            "Shared secret must not be zeroized");
}
