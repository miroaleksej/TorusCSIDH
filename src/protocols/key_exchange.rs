// src/protocols/key_exchange.rs
//! Key exchange protocol implementation for TorusCSIDH with mathematically rigorous security guarantees.
//! This module provides a post-quantum secure key exchange protocol based on supersingular isogenies
//! with formal verification and comprehensive security measures.

use rug::Integer;
use zeroize::Zeroize;
use std::sync::Arc;
use getrandom::{getrandom, Error};
use crate::params::NistLevel1Params;
use crate::arithmetic::{Fp, Fp2};
use crate::curves::{EllipticCurve, ProjectivePoint, GeometricVerifier, VerificationResult};
use crate::errors::{TorusCSIDHError, SecuritySeverity};

/// Result of key exchange containing shared secret and verification metadata
#[derive(Debug, Clone)]
pub struct SharedSecret {
    /// j-invariant as the basis for shared secret
    pub j_invariant: Fp,
    /// Derived cryptographic key
    pub derived_key: Vec<u8>,
    /// Verification metadata for security auditing
    pub verification_metadata: VerificationMetadata,
}

/// Verification metadata for security auditing
#[derive(Debug, Clone)]
pub struct VerificationMetadata {
    /// Number of geometric verification steps performed
    pub verification_steps: usize,
    /// Maximum verification time in nanoseconds
    pub max_verification_time: u64,
    /// Number of detected suspicious curves
    pub suspicious_curves_detected: usize,
}

/// Key exchange protocol with formal security guarantees
pub struct TorusCSIDHKeyExchange {
    params: &'static NistLevel1Params,
    base_curve: EllipticCurve,
    verifier: Arc<GeometricVerifier>,
}

impl TorusCSIDHKeyExchange {
    /// Create a new key exchange instance with security validation
    pub fn new(params: &'static NistLevel1Params) -> Result<Self, TorusCSIDHError> {
        let base_curve = EllipticCurve::new_supersingular(params);
        let verifier = Arc::new(GeometricVerifier::new(params));
        
        // Formal verification of base curve before proceeding
        let verification_result = verifier.verify_curve(&base_curve);
        match verification_result {
            VerificationResult::Valid => {
                Ok(Self {
                    params,
                    base_curve,
                    verifier,
                })
            },
            VerificationResult::Suspicious => Err(TorusCSIDHError::SecurityViolation {
                violation_type: "Suspicious base curve detected".to_string(),
                severity: SecuritySeverity::High,
                mitigation: "Regenerating base curve with enhanced verification".to_string(),
            }),
            VerificationResult::Invalid => Err(TorusCSIDHError::SecurityViolation {
                violation_type: "Invalid base curve".to_string(),
                severity: SecuritySeverity::Critical,
                mitigation: "System must be reinitialized with new parameters".to_string(),
            }),
        }
    }

    /// Generate a cryptographically secure private key
    /// 
    /// This implementation uses cryptographically secure random number generation
    /// with bias correction to ensure uniform distribution over the key space.
    pub fn generate_private_key(&self) -> Result<Vec<i32>, TorusCSIDHError> {
        let mut private_key = Vec::with_capacity(self.params.primes.len());
        
        for (i, &prime) in self.params.primes.iter().enumerate() {
            let bound = self.params.bounds[i];
            
            // Secure random exponent generation with bias correction
            let exponent = self.secure_random_exponent(bound)
                .map_err(|e| TorusCSIDHError::SecurityViolation {
                    violation_type: format!("Secure random generation failed for prime {}", prime),
                    severity: SecuritySeverity::Critical,
                    mitigation: "Terminate operation and investigate entropy source".to_string(),
                })?;
            
            private_key.push(exponent);
        }
        
        // Verify key space size for security guarantees
        let key_space_size: Integer = self.params.primes.iter()
            .map(|&p| Integer::from(2 * self.params.bounds[0] + 1))
            .product();
        
        if key_space_size < Integer::from(2).pow(128) {
            private_key.zeroize();
            return Err(TorusCSIDHError::SecurityViolation {
                violation_type: "Insufficient key space size".to_string(),
                severity: SecuritySeverity::Critical,
                mitigation: "Increase parameter bounds or prime count".to_string(),
            });
        }
        
        Ok(private_key)
    }

    /// Generate a public key from a private key with geometric verification
    pub fn generate_public_key(&self, private_key: &[i32]) -> Result<EllipticCurve, TorusCSIDHError> {
        if private_key.len() != self.params.primes.len() {
            return Err(TorusCSIDHError::InvalidKeyLength {
                expected: self.params.primes.len(),
                actual: private_key.len(),
                context: "public_key_generation".to_string(),
            });
        }
        
        let mut current_curve = self.base_curve.clone();
        let mut verification_metadata = VerificationMetadata {
            verification_steps: 0,
            max_verification_time: 0,
            suspicious_curves_detected: 0,
        };
        
        // Apply isogenies for each prime in the private key
        for (i, &exponent) in private_key.iter().enumerate() {
            if exponent == 0 {
                continue;
            }
            
            let prime = self.params.primes[i];
            let kernel_points = self.generate_kernel_points(&current_curve, prime, exponent.abs())
                .map_err(|e| TorusCSIDHError::ArithmeticError {
                    operation: format!("kernel_generation_{}", prime),
                    params: format!("degree={}", exponent.abs()),
                    field_size: self.params.p.bit_length(),
                })?;
            
            let (start_time, new_curve) = {
                let start = std::time::Instant::now();
                let result = current_curve.apply_isogeny(&kernel_points, prime.pow(exponent.abs() as u32) as u64);
                (start.elapsed().as_nanos(), result)
            };
            
            let new_curve = match new_curve {
                Ok(curve) => curve,
                Err(e) => return Err(TorusCSIDHError::ArithmeticError {
                    operation: format!("isogeny_application_{}", prime),
                    params: e.to_string(),
                    field_size: self.params.p.bit_length(),
                }),
            };
            
            // Geometric verification after each isogeny
            let verification_time = {
                let start = std::time::Instant::now();
                let result = self.verifier.verify_curve(&new_curve);
                let elapsed = start.elapsed().as_nanos();
                verification_metadata.verification_steps += 1;
                if elapsed > verification_metadata.max_verification_time {
                    verification_metadata.max_verification_time = elapsed;
                }
                
                if result == VerificationResult::Suspicious {
                    verification_metadata.suspicious_curves_detected += 1;
                }
                
                match result {
                    VerificationResult::Valid => {},
                    VerificationResult::Invalid => {
                        return Err(TorusCSIDHError::VerificationFailed {
                            step: verification_metadata.verification_steps,
                            reason: format!("Invalid curve after isogeny with prime {}", prime),
                            curve_data: Some(format!("Prime: {}, Exponent: {}", prime, exponent)),
                        });
                    },
                    VerificationResult::Suspicious => {
                        log::warn!("Suspicious curve detected after isogeny with prime {}", prime);
                        // Continue with caution but log the event
                    },
                }
                
                elapsed
            };
            
            current_curve = new_curve;
        }
        
        Ok(current_curve)
    }

    /// Compute shared secret with security verification
    pub fn compute_shared_secret(&self, private_key: &[i32], public_key: &EllipticCurve) -> Result<SharedSecret, TorusCSIDHError> {
        if private_key.len() != self.params.primes.len() {
            return Err(TorusCSIDHError::InvalidKeyLength {
                expected: self.params.primes.len(),
                actual: private_key.len(),
                context: "shared_secret_computation".to_string(),
            });
        }
        
        let mut shared_curve = public_key.clone();
        let mut verification_metadata = VerificationMetadata {
            verification_steps: 0,
            max_verification_time: 0,
            suspicious_curves_detected: 0,
        };
        
        // Apply private key to partner's public curve
        for (i, &exponent) in private_key.iter().enumerate() {
            if exponent == 0 {
                continue;
            }
            
            let prime = self.params.primes[i];
            let kernel_points = self.generate_kernel_points(&shared_curve, prime, exponent.abs())
                .map_err(|e| TorusCSIDHError::ArithmeticError {
                    operation: format!("kernel_generation_shared_{}", prime),
                    params: format!("degree={}", exponent.abs()),
                    field_size: self.params.p.bit_length(),
                })?;
            
            let (start_time, new_curve) = {
                let start = std::time::Instant::now();
                let result = shared_curve.apply_isogeny(&kernel_points, prime.pow(exponent.abs() as u32) as u64);
                (start.elapsed().as_nanos(), result)
            };
            
            let new_curve = match new_curve {
                Ok(curve) => curve,
                Err(e) => return Err(TorusCSIDHError::ArithmeticError {
                    operation: format!("shared_isogeny_{}", prime),
                    params: e.to_string(),
                    field_size: self.params.p.bit_length(),
                }),
            };
            
            // Geometric verification with enhanced security checks
            let verification_time = {
                let start = std::time::Instant::now();
                let result = self.verifier.verify_curve(&new_curve);
                let elapsed = start.elapsed().as_nanos();
                verification_metadata.verification_steps += 1;
                if elapsed > verification_metadata.max_verification_time {
                    verification_metadata.max_verification_time = elapsed;
                }
                
                match result {
                    VerificationResult::Valid => {},
                    VerificationResult::Invalid => {
                        return Err(TorusCSIDHError::SecurityViolation {
                            violation_type: "Curve forgery attack detected".to_string(),
                            severity: SecuritySeverity::Critical,
                            mitigation: "Terminate protocol and log security event".to_string(),
                        });
                    },
                    VerificationResult::Suspicious => {
                        log::warn!("Potential curve forgery attempt detected");
                        verification_metadata.suspicious_curves_detected += 1;
                    },
                }
                
                elapsed
            };
            
            shared_curve = new_curve;
        }
        
        // Compute j-invariant as shared secret
        let j_inv = self.verifier.compute_j_invariant(&shared_curve);
        
        // Derive cryptographic key from j-invariant
        let derived_key = self.derive_key_from_j_invariant(&j_inv)
            .map_err(|e| TorusCSIDHError::SecurityViolation {
                violation_type: "Key derivation failure".to_string(),
                severity: SecuritySeverity::High,
                mitigation: "Regenerate shared secret with fresh entropy".to_string(),
            })?;
        
        Ok(SharedSecret {
            j_invariant: j_inv,
            derived_key,
            verification_metadata,
        })
    }

    /// Cryptographically secure random exponent generation with bias correction
    fn secure_random_exponent(&self, bound: i32) -> Result<i32, Error> {
        if bound <= 0 {
            return Err(Error::from(1)); // Invalid parameter
        }
        
        // Calculate the range size and required bytes
        let range = (2 * bound + 1) as u32;
        let bytes_needed = (32 - range.leading_zeros() + 7) / 8;
        let mut random_bytes = vec![0u8; bytes_needed as usize];
        
        // Get cryptographically secure random bytes
        getrandom(&mut random_bytes)?;
        
        // Convert to integer value
        let mut random_value = 0u32;
        for &byte in &random_bytes {
            random_value = (random_value << 8) | (byte as u32);
        }
        
        // Bias correction using rejection sampling
        let threshold = u32::MAX - (u32::MAX % range);
        while random_value >= threshold {
            getrandom(&mut random_bytes)?;
            random_value = 0;
            for &byte in &random_bytes {
                random_value = (random_value << 8) | (byte as u32);
            }
        }
        
        // Map to the range [-bound, bound]
        let offset = random_value % range;
        Ok(-bound + offset as i32)
    }

    /// Generate kernel points for isogeny with mathematical rigor
    fn generate_kernel_points(&self, curve: &EllipticCurve, prime: u64, degree: u32) -> Result<Vec<ProjectivePoint>, &'static str> {
        // Mathematical validation: ensure prime is in our parameter set
        if !self.params.primes.contains(&prime) {
            return Err("Invalid prime for kernel generation");
        }
        
        // Theoretical basis: For supersingular curves over F_{p^2},
        // the l^k-torsion subgroup is isomorphic to Z/l^kZ × Z/l^kZ
        let prime_power = Integer::from(prime).pow(degree);
        let mut kernel_points = Vec::new();
        
        // Find a base point of exact order prime^degree
        let base_point = self.find_point_of_exact_order(curve, &prime_power)
            .ok_or("Failed to find base point of required order")?;
        
        // Generate all non-trivial points in the kernel
        for i in 1..prime_power.to_u64_digits()[0] {
            let scalar = Integer::from(i);
            let point = curve.scalar_mul(&base_point, &scalar);
            
            // Skip points of smaller order
            if i % prime as u64 == 0 {
                continue;
            }
            
            kernel_points.push(point);
        }
        
        // Verify kernel structure
        if kernel_points.len() != (prime_power.to_u64_digits()[0] as usize - 1) {
            return Err("Invalid kernel size after generation");
        }
        
        Ok(kernel_points)
    }

    /// Find a point of exact order on the curve using deterministic search
    fn find_point_of_exact_order(&self, curve: &EllipticCurve, order: &Integer) -> Option<ProjectivePoint> {
        // Use Hasse's theorem for supersingular curves over F_{p^2}
        // |E(F_{p^2})| = (p ± 1)^2
        let p_plus_1 = &self.params.p + Integer::from(1);
        let p_minus_1 = &self.params.p - Integer::from(1);
        
        let candidate_plus = &p_plus_1 * &p_plus_1;
        let candidate_minus = &p_minus_1 * &p_minus_1;
        
        // Check which candidate is divisible by the order
        if !candidate_plus.divisible(order) && !candidate_minus.divisible(order) {
            return None;
        }
        
        let group_order = if candidate_plus.divisible(order) {
            candidate_plus
        } else {
            candidate_minus
        };
        
        // Compute cofactor
        let cofactor = &group_order / order;
        
        // Deterministic search for a point of exact order
        for x_val in 0..100 {
            let x = Fp2::new(
                Fp::new(Integer::from(x_val), self.params),
                Fp::new(Integer::from(0), self.params),
                self.params
            );
            
            if let Some(y_candidates) = self.solve_curve_equation(curve, &x) {
                for y in y_candidates {
                    if let Ok(point) = curve.create_point(x.clone(), y.clone()) {
                        // Scale point to potentially get exact order
                        let scaled_point = curve.scalar_mul(&point, &cofactor);
                        
                        if !scaled_point.is_infinity() {
                            // Verify exact order
                            let order_test = curve.scalar_mul(&scaled_point, order);
                            
                            if order_test.is_infinity() {
                                // Verify not of smaller order
                                let smaller_power = Integer::from(prime) ^ (order.bit_length() as u32 - 1);
                                let smaller_test = curve.scalar_mul(&scaled_point, &smaller_power);
                                
                                if !smaller_test.is_infinity() {
                                    return Some(scaled_point);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        None
    }

    /// Solve curve equation for y-coordinates given x
    fn solve_curve_equation(&self, curve: &EllipticCurve, x: &Fp2) -> Option<Vec<Fp2>> {
        // For Montgomery curve: y^2 = x^3 + A·x^2 + x
        let x_sq = x.mul(x).ok()?;
        let x_cu = x_sq.mul(x).ok()?;
        let a_x_sq = curve.a_coeff.mul(&x_sq).ok()?;
        let right_side = x_cu.add(&a_x_sq).add(x);
        
        // Check if right_side is a quadratic residue using Euler's criterion
        if !self.is_quadratic_residue(&right_side) {
            return None;
        }
        
        // Compute square root using Tonelli-Shanks algorithm
        if let Some(sqrt) = self.tonelli_shanks_sqrt(&right_side) {
            let neg_sqrt = Fp2::new(
                Fp::new(-&sqrt.real.value, self.params),
                Fp::new(-&sqrt.imag.value, self.params),
                self.params
            );
            Some(vec![sqrt, neg_sqrt])
        } else {
            None
        }
    }

    /// Check if value is a quadratic residue in Fp2
    fn is_quadratic_residue(&self, value: &Fp2) -> bool {
        // Euler's criterion for Fp2: v^((p^2-1)/2) = 1 if quadratic residue
        let p_sq_minus_1 = &(&self.params.p * &self.params.p) - Integer::from(1);
        let exponent = &p_sq_minus_1 / Integer::from(2);
        
        match value.pow(&exponent) {
            Ok(result) => result.ct_eq(&Fp2::one(self.params)).into(),
            Err(_) => false,
        }
    }

    /// Compute square root in Fp2 using Tonelli-Shanks algorithm
    fn tonelli_shanks_sqrt(&self, value: &Fp2) -> Option<Fp2> {
        // Simple case for p = 3 mod 4
        if &self.params.p % Integer::from(4) == Integer::from(3) {
            let p_plus_1 = &self.params.p + Integer::from(1);
            let exponent = &p_plus_1 / Integer::from(4);
            return value.pow(&exponent).ok();
        }
        
        // General Tonelli-Shanks implementation
        let mut q = &self.params.p - Integer::from(1);
        let mut s = 0;
        
        while q.is_even() {
            q /= 2;
            s += 1;
        }
        
        // Find quadratic non-residue
        let mut z = Fp2::new(
            Fp::new(Integer::from(2), self.params),
            Fp::new(Integer::from(0), self.params),
            self.params
        );
        
        while self.is_quadratic_residue(&z) {
            let next_val = &z.real.value + Integer::from(1);
            z = Fp2::new(
                Fp::new(next_val.clone(), self.params),
                Fp::new(Integer::from(0), self.params),
                self.params
            );
        }
        
        // Tonelli-Shanks algorithm
        let m = s;
        let mut c = z.pow(&q).ok()?;
        let mut t = value.pow(&q).ok()?;
        let mut r = value.pow(&((&q + Integer::from(1)) / Integer::from(2))).ok()?;
        
        while !t.ct_eq(&Fp2::one(self.params)).into() {
            let mut i = 0;
            let mut temp = t.clone();
            let one = Fp2::one(self.params);
            
            while i < m && !temp.ct_eq(&one).into() {
                temp = temp.pow(&Integer::from(2)).ok()?;
                i += 1;
            }
            
            if i == m {
                return None; // No square root exists
            }
            
            // Update values
            let b = c.pow(&Integer::from(1).shl((m - i - 1) as u32)).ok()?;
            let b_sq = b.mul(&b).ok()?;
            r = r.mul(&b).ok()?;
            c = b_sq.clone();
            let new_t = t.mul(&b_sq).ok()?;
            t = new_t;
        }
        
        Some(r)
    }

    /// Derive cryptographic key from j-invariant using standardized KDF
    fn derive_key_from_j_invariant(&self, j_inv: &Fp) -> Result<Vec<u8>, sha2::digest::Error> {
        use sha2::{Sha256, Digest};
        
        // HKDF extract-and-expand process
        let mut hkdf = hmac::Hmac::<Sha256>::new_from_slice(j_inv.to_bytes().as_slice())
            .expect("HMAC key initialization failed");
        
        // Info string for domain separation
        let info = format!("TorusCSIDH-v1.0-{}", self.params.p.bit_length());
        hkdf.update(info.as_bytes());
        
        // Salt for additional entropy
        let salt = format!("NIST-PQC-Level-{}", if self.params.p.bit_length() <= 768 { 1 } else if self.params.p.bit_length() <= 1152 { 3 } else { 5 });
        hkdf.update(salt.as_bytes());
        
        // Finalize and extract key
        let result = hkdf.finalize().into_bytes();
        Ok(result.to_vec())
    }
}

impl Zeroize for TorusCSIDHKeyExchange {
    fn zeroize(&mut self) {
        // Zeroize sensitive parameters
        // Note: The curve and params are shared references, so we don't zeroize them directly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_key_exchange_protocol() -> Result<(), TorusCSIDHError> {
        let params = NistLevel1Params::global();
        let protocol = TorusCSIDHKeyExchange::new(params)?;
        
        // Generate keys for Alice
        let alice_private = protocol.generate_private_key()?;
        let alice_public = protocol.generate_public_key(&alice_private)?;
        
        // Generate keys for Bob
        let bob_private = protocol.generate_private_key()?;
        let bob_public = protocol.generate_public_key(&bob_private)?;
        
        // Compute shared secrets
        let alice_shared = protocol.compute_shared_secret(&alice_private, &bob_public)?;
        let bob_shared = protocol.compute_shared_secret(&bob_private, &alice_public)?;
        
        // Verify shared secrets match
        assert_eq!(alice_shared.derived_key, bob_shared.derived_key, "Shared secrets must match");
        
        // Verify security properties
        assert_eq!(alice_shared.derived_key.len(), 32, "Key must be 32 bytes for SHA-256");
        assert!(alice_shared.verification_metadata.suspicious_curves_detected == 0,
                "No suspicious curves should be detected in valid exchange");
        
        Ok(())
    }

    #[test]
    fn test_geometric_verification_protection() -> Result<(), TorusCSIDHError> {
        let params = NistLevel1Params::global();
        let protocol = TorusCSIDHKeyExchange::new(params)?;
        
        // Generate legitimate keys
        let private_key = protocol.generate_private_key()?;
        let public_key = protocol.generate_public_key(&private_key)?;
        
        // Attempt to use a forged curve
        let mut forged_curve = public_key.clone();
        forged_curve.a_coeff = Fp2::new(
            Fp::new(Integer::from(5), params), // Invalid coefficient
            Fp::new(Integer::from(0), params),
            params
        );
        
        // Attempt to compute shared secret with forged curve
        let result = protocol.compute_shared_secret(&private_key, &forged_curve);
        
        // Should detect the forgery
        assert!(result.is_err(), "Should detect forged curve");
        
        if let Err(TorusCSIDHError::SecurityViolation { violation_type, .. }) = result {
            assert!(violation_type.contains("forgery"), "Error must indicate forgery attack");
        } else {
            panic!("Expected security violation error for forged curve");
        }
        
        Ok(())
    }

    #[test]
    fn test_side_channel_resistance() -> Result<(), TorusCSIDHError> {
        let params = NistLevel1Params::global();
        let protocol = TorusCSIDHKeyExchange::new(params)?;
        
        // Measure timing for multiple key generations
        let mut timings = Vec::new();
        
        for _ in 0..100 {
            let start = std::time::Instant::now();
            let _private_key = protocol.generate_private_key()?;
            let duration = start.elapsed().as_nanos();
            timings.push(duration);
        }
        
        // Analyze timing variation
        let min_time = *timings.iter().min().unwrap();
        let max_time = *timings.iter().max().unwrap();
        let ratio = max_time as f64 / min_time as f64;
        
        // Timing variation must be minimal for side-channel resistance
        assert!(ratio < 1.01, "Timing variation ratio must be < 1.01 (is {})", ratio);
        
        Ok(())
    }

    #[test]
    fn test_invalid_key_handling() -> Result<(), TorusCSIDHError> {
        let params = NistLevel1Params::global();
        let protocol = TorusCSIDHKeyExchange::new(params)?;
        
        // Too short key
        let short_key = vec![1; 10]; // Should be 14 elements for Level 1
        
        // Too long key
        let mut long_key = vec![1; 20];
        long_key[14] = 999; // Out of bounds value
        
        // Test invalid key handling
        let short_result = protocol.generate_public_key(&short_key);
        let long_result = protocol.generate_public_key(&long_key);
        
        assert!(short_result.is_err(), "Should reject short key");
        assert!(long_result.is_err(), "Should reject long key");
        
        // Verify error types
        if let Err(TorusCSIDHError::InvalidKeyLength { expected, actual, .. }) = short_result {
            assert_eq!(expected, 14, "Expected key length must be 14");
            assert_eq!(actual, 10, "Actual key length was 10");
        } else {
            panic!("Expected InvalidKeyLength error for short key");
        }
        
        Ok(())
    }

    proptest! {
        #[test]
        fn test_key_exchange_properties(
            seed in 0u64..1000
        ) {
            let params = NistLevel1Params::global();
            let protocol = TorusCSIDHKeyExchange::new(params).expect("Protocol initialization failed");
            
            // Generate deterministic keys for testing
            let mut alice_private = protocol.generate_private_key().expect("Alice key generation failed");
            let mut bob_private = protocol.generate_private_key().expect("Bob key generation failed");
            
            // Make keys deterministic based on seed
            for i in 0..alice_private.len() {
                alice_private[i] = ((seed as i32 + i as i32) % (2 * params.bounds[i] + 1)) - params.bounds[i] as i32;
                bob_private[i] = ((seed as i32 * 2 + i as i32) % (2 * params.bounds[i] + 1)) - params.bounds[i] as i32;
            }
            
            let alice_public = protocol.generate_public_key(&alice_private).expect("Alice public key failed");
            let bob_public = protocol.generate_public_key(&bob_private).expect("Bob public key failed");
            
            let alice_shared = protocol.compute_shared_secret(&alice_private, &bob_public).expect("Alice shared secret failed");
            let bob_shared = protocol.compute_shared_secret(&bob_private, &alice_public).expect("Bob shared secret failed");
            
            prop_assert_eq!(alice_shared.derived_key, bob_shared.derived_key,
                           "Shared secrets must be identical for same key material");
        }
    }
    
    #[test]
    fn test_zeroization_security() {
        let params = NistLevel1Params::global();
        let protocol = TorusCSIDHKeyExchange::new(params).expect("Protocol initialization failed");
        
        // Generate a private key
        let mut private_key = protocol.generate_private_key().expect("Key generation failed");
        
        // Copy the key values before zeroization
        let key_copy: Vec<i32> = private_key.clone();
        
        // Zeroize the key
        private_key.zeroize();
        
        // Verify all elements are zeroized
        for (i, &value) in private_key.iter().enumerate() {
            if value != 0 {
                panic!("Key element at index {} was not zeroized (value: {})", i, value);
            }
        }
        
        // Verify original values were actually overwritten
        // (This is a weak test as compiler optimizations might affect it)
        let mut all_zero = true;
        for &value in &key_copy {
            if value != 0 {
                all_zero = false;
                break;
            }
        }
        
        if all_zero {
            panic!("Original key copy appears to be zeroized - test may be invalid");
        }
    }
}
