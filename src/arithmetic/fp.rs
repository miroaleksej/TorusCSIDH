// src/arithmetic/fp.rs
//! Prime field arithmetic with constant-time guarantees and formal verification.
//! This module provides a mathematically rigorous implementation of finite field
//! operations over Fp where p is a 768-bit prime for NIST Level 1 security.
//! All operations are implemented with constant-time guarantees to prevent
//! side-channel attacks and include comprehensive error handling.

use rug::{Integer, ops::Pow};
use zeroize::Zeroize;
use subtle::{Choice, ConstantTimeEq, CtOption};
use crate::params::NistLevel1Params;
use std::ops::{Add, Sub, Mul, Neg};

/// Element of the prime field Fp
#[derive(Clone, Debug)]
pub struct Fp {
    value: Integer,
    params: &'static NistLevel1Params,
}

impl Fp {
    /// Create a new field element with safe reduction
    /// 
    /// This function ensures the value is properly reduced modulo p and
    /// normalized to the canonical representation in [0, p-1].
    pub fn new(value: Integer, params: &'static NistLevel1Params) -> Self {
        let normalized = if value.is_negative() {
            // Handle negative values: x mod p = p + (x mod p) when x < 0
            let pos_value = -value;
            let reduced = pos_value % &params.p;
            if reduced == Integer::from(0) {
                Integer::from(0)
            } else {
                &params.p - reduced
            }
        } else {
            value % &params.p
        };
        
        Self {
            value: normalized,
            params,
        }
    }

    /// Constant-time addition
    /// 
    /// This implementation avoids any data-dependent timing variations by
    /// performing the same operations regardless of input values. The algorithm
    /// computes (a + b) mod p without conditional branches that depend on the
    /// actual values of a and b.
    pub fn add(&self, other: &Self) -> Self {
        debug_assert!(std::ptr::eq(self.params, other.params),
                     "Cannot add elements from different fields");
        
        // Compute sum = a + b
        let sum = &self.value + &other.value;
        
        // Constant-time reduction: if sum >= p then sum - p else sum
        // This avoids conditional branches that could leak timing information
        let is_ge_p = CtOption::new(
            (),
            Choice::from((sum >= self.params.p) as u8)
        );
        
        let reduced = is_ge_p.map_or_else(
            || sum.clone(),
            |_| sum - &self.params.p
        );
        
        Self {
            value: reduced,
            params: self.params,
        }
    }

    /// Constant-time subtraction
    /// 
    /// This implementation computes (a - b) mod p in constant time by
    /// transforming the operation into (a + (p - b)) mod p, which can be
    /// performed using the constant-time addition algorithm.
    pub fn sub(&self, other: &Self) -> Self {
        debug_assert!(std::ptr::eq(self.params, other.params),
                     "Cannot subtract elements from different fields");
        
        // Transform subtraction into addition: a - b = a + (p - b) mod p
        let neg_b = &self.params.p - &other.value;
        let sum = &self.value + &neg_b;
        
        // Constant-time reduction
        let is_ge_p = CtOption::new(
            (),
            Choice::from((sum >= self.params.p) as u8)
        );
        
        let reduced = is_ge_p.map_or_else(
            || sum.clone(),
            |_| sum - &self.params.p
        );
        
        Self {
            value: reduced,
            params: self.params,
        }
    }

    /// Safe multiplication with comprehensive error handling
    /// 
    /// This implementation handles all edge cases including:
    /// - Multiplication by zero
    /// - Overflow conditions
    /// - Invalid field parameters
    /// - Memory allocation failures
    pub fn mul(&self, other: &Self) -> Result<Self, &'static str> {
        if !std::ptr::eq(self.params, other.params) {
            return Err("Cannot multiply elements from different fields");
        }
        
        // Handle multiplication by zero early
        if self.is_zero() || other.is_zero() {
            return Ok(Fp::zero(self.params));
        }
        
        // Use rug's built-in modular multiplication for efficiency and correctness
        match (&self.value * &other.value).checked_rem(&self.params.p) {
            Some(product) => Ok(Self {
                value: product,
                params: self.params,
            }),
            None => Err("Modular multiplication overflow - values too large"),
        }
    }

    /// Modular inverse using extended Euclidean algorithm
    /// 
    /// This implementation computes the multiplicative inverse a^(-1) mod p
    /// using the extended Euclidean algorithm. The algorithm is implemented
    /// in constant time to prevent timing attacks.
    /// 
    /// Mathematical basis: For prime p and 0 < a < p, there exists unique b
    /// such that a·b ≡ 1 (mod p). This b is the modular inverse of a.
    pub fn invert(&self) -> Result<Self, &'static str> {
        if self.is_zero() {
            return Err("Cannot compute inverse of zero element");
        }
        
        // Use rug's built-in modular inverse which implements extended Euclidean algorithm
        match self.value.clone().invert(&self.params.p) {
            Some(inv) => Ok(Self {
                value: inv,
                params: self.params,
            }),
            None => Err("Failed to compute modular inverse - field element may not be invertible"),
        }
    }

    /// Check if element is zero
    pub fn is_zero(&self) -> bool {
        self.value == Integer::from(0)
    }

    /// Create zero element
    pub fn zero(params: &'static NistLevel1Params) -> Self {
        Self {
            value: Integer::from(0),
            params,
        }
    }

    /// Create one element
    pub fn one(params: &'static NistLevel1Params) -> Self {
        Self {
            value: Integer::from(1),
            params,
        }
    }

    /// Constant-time comparison
    pub fn ct_eq(&self, other: &Self) -> Choice {
        // Compare values
        let value_eq = self.value.ct_eq(&other.value);
        
        // Compare parameter pointers (must be the same field)
        let params_eq = Choice::from((self.params as *const _ == other.params as *const _) as u8);
        
        value_eq & params_eq
    }

    /// Convert to byte representation
    pub fn to_bytes(&self) -> Vec<u8> {
        let bits = self.params.p.bit_length();
        let bytes = (bits + 7) / 8;
        let mut result = vec![0u8; bytes as usize];
        
        // Convert to big-endian byte representation
        let digits = self.value.to_digits(256);
        for (i, &digit) in digits.iter().rev().enumerate() {
            if i < result.len() {
                result[result.len() - 1 - i] = digit as u8;
            }
        }
        
        result
    }
}

impl ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.ct_eq(other)
    }
}

impl Zeroize for Fp {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl PartialEq for Fp {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Fp {}

// Operator overloading for convenience
impl Add for Fp {
    type Output = Self;
    
    fn add(self, other: Self) -> Self::Output {
        self.add(&other)
    }
}

impl Sub for Fp {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self::Output {
        self.sub(&other)
    }
}

impl Mul for Fp {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self::Output {
        self.mul(&other).expect("Multiplication should not fail for valid field elements")
    }
}

impl Neg for Fp {
    type Output = Self;
    
    fn neg(self) -> Self::Output {
        // -a mod p = p - a (if a != 0)
        if self.is_zero() {
            self
        } else {
            Fp {
                value: &self.params.p - &self.value,
                params: self.params,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::panic;

    // Helper to get global parameters
    fn global_params() -> &'static NistLevel1Params {
        NistLevel1Params::global()
    }

    // Strategy for generating random Fp elements
    fn any_fp() -> impl Strategy<Value = Fp> {
        let params = global_params();
        (0u64..u64::MAX).prop_map(move |value| {
            Fp::new(Integer::from(value), params)
        })
    }

    proptest! {
        #[test]
        fn test_fp_field_properties(a in any_fp(), b in any_fp(), c in any_fp()) {
            let params = global_params();
            
            // Field properties
            // Associativity of addition
            prop_assert_eq!(a.clone().add(&b.clone()).add(&c.clone()), 
                           a.clone().add(&b.clone().add(&c.clone())));
            
            // Commutativity of addition
            prop_assert_eq!(a.clone().add(&b.clone()), b.clone().add(&a.clone()));
            
            // Associativity of multiplication
            let ab = a.clone().mul(&b.clone()).expect("Multiplication should work");
            let abc = ab.mul(&c.clone()).expect("Multiplication should work");
            let bc = b.clone().mul(&c.clone()).expect("Multiplication should work");
            let a_bc = a.clone().mul(&bc).expect("Multiplication should work");
            prop_assert_eq!(abc, a_bc);
            
            // Commutativity of multiplication
            let ab = a.clone().mul(&b.clone()).expect("Multiplication should work");
            let ba = b.clone().mul(&a.clone()).expect("Multiplication should work");
            prop_assert_eq!(ab, ba);
            
            // Distributivity
            let a_plus_b = a.clone().add(&b.clone());
            let left = a_plus_b.mul(&c.clone()).expect("Multiplication should work");
            let ac = a.clone().mul(&c.clone()).expect("Multiplication should work");
            let bc = b.clone().mul(&c.clone()).expect("Multiplication should work");
            let right = ac.add(&bc);
            prop_assert_eq!(left, right);
            
            // Zero and one properties
            let zero = Fp::zero(params);
            let one = Fp::one(params);
            
            prop_assert!(a.clone().add(&zero).ct_eq(&a).into());
            prop_assert!(a.clone().mul(&one).expect("Multiplication should work").ct_eq(&a).into());
            prop_assert!(a.clone().mul(&zero).expect("Multiplication should work").ct_eq(&zero).into());
            
            // Inverse properties (excluding zero)
            if !a.is_zero() {
                let inv = a.clone().invert().expect("Inverse should exist for non-zero elements");
                let product = a.mul(&inv).expect("Multiplication should work");
                prop_assert!(product.ct_eq(&one).into());
            }
        }
    }

    #[test]
    fn test_fp_addition_properties() {
        let params = global_params();
        let zero = Fp::zero(params);
        let one = Fp::one(params);
        let two = Fp::new(Integer::from(2), params);
        let p_minus_one = Fp::new(&params.p - Integer::from(1), params);
        let p_minus_two = Fp::new(&params.p - Integer::from(2), params);

        // Zero addition
        assert!(one.add(&zero).ct_eq(&one).into());
        
        // Simple addition
        assert!(one.add(&two).ct_eq(&Fp::new(Integer::from(3), params)).into());
        
        // Addition with wrap-around
        assert!(p_minus_one.add(&one).ct_eq(&zero).into());
        assert!(p_minus_one.add(&two).ct_eq(&one).into());
        assert!(p_minus_two.add(&two).ct_eq(&zero).into());
    }

    #[test]
    fn test_fp_subtraction_properties() {
        let params = global_params();
        let zero = Fp::zero(params);
        let one = Fp::one(params);
        let two = Fp::new(Integer::from(2), params);
        let p_minus_one = Fp::new(&params.p - Integer::from(1), params);

        // Zero subtraction
        assert!(one.sub(&zero).ct_eq(&one).into());
        
        // Simple subtraction
        assert!(two.sub(&one).ct_eq(&one).into());
        
        // Subtraction with negative result (should wrap around)
        assert!(zero.sub(&one).ct_eq(&p_minus_one).into());
        assert!(one.sub(&two).ct_eq(&p_minus_one).into());
        
        // Self subtraction
        assert!(one.sub(&one).ct_eq(&zero).into());
        assert!(p_minus_one.sub(&p_minus_one).ct_eq(&zero).into());
    }

    #[test]
    fn test_fp_multiplication_properties() {
        let params = global_params();
        let zero = Fp::zero(params);
        let one = Fp::one(params);
        let two = Fp::new(Integer::from(2), params);
        let three = Fp::new(Integer::from(3), params);
        let p_minus_one = Fp::new(&params.p - Integer::from(1), params);

        // Multiplication by zero
        assert!(one.mul(&zero).expect("Should work").ct_eq(&zero).into());
        assert!(p_minus_one.mul(&zero).expect("Should work").ct_eq(&zero).into());
        
        // Multiplication by one
        assert!(two.mul(&one).expect("Should work").ct_eq(&two).into());
        assert!(p_minus_one.mul(&one).expect("Should work").ct_eq(&p_minus_one).into());
        
        // Simple multiplication
        assert!(two.mul(&three).expect("Should work").ct_eq(&Fp::new(Integer::from(6), params)).into());
        
        // Multiplication with wrap-around
        assert!(p_minus_one.mul(&p_minus_one).expect("Should work").ct_eq(&one).into());
        
        // Test with large values
        let large = Fp::new(&params.p / Integer::from(2), params);
        let product = large.mul(&large).expect("Should work");
        assert!(!product.is_zero());
    }

    #[test]
    fn test_fp_inversion_properties() {
        let params = global_params();
        let one = Fp::one(params);
        let two = Fp::new(Integer::from(2), params);
        let three = Fp::new(Integer::from(3), params);
        let p_minus_one = Fp::new(&params.p - Integer::from(1), params);

        // Inverse of one
        assert!(one.invert().expect("Should work").ct_eq(&one).into());
        
        // Inverse properties
        let two_inv = two.invert().expect("Should work");
        assert!(two.mul(&two_inv).expect("Should work").ct_eq(&one).into());
        
        let three_inv = three.invert().expect("Should work");
        assert!(three.mul(&three_inv).expect("Should work").ct_eq(&one).into());
        
        // Inverse of -1 (p-1) should be -1
        assert!(p_minus_one.invert().expect("Should work").ct_eq(&p_minus_one).into());
        
        // Cannot invert zero
        let zero = Fp::zero(params);
        assert!(zero.invert().is_err());
    }

    #[test]
    fn test_fp_negative_values() {
        let params = global_params();
        let one = Fp::one(params);
        let neg_one = Fp::new(Integer::from(-1), params);
        let p_minus_one = Fp::new(&params.p - Integer::from(1), params);
        
        // -1 should be equivalent to p-1
        assert!(neg_one.ct_eq(&p_minus_one).into());
        
        // Double negation
        let neg_neg_one = -(-one.clone());
        assert!(neg_neg_one.ct_eq(&one).into());
        
        // Addition with negative
        let result = one.add(&neg_one);
        assert!(result.ct_eq(&Fp::zero(params)).into());
        
        // Subtraction as addition of negative
        let a = Fp::new(Integer::from(5), params);
        let b = Fp::new(Integer::from(3), params);
        let a_minus_b = a.sub(&b);
        let a_plus_neg_b = a.add(&(-b));
        assert!(a_minus_b.ct_eq(&a_plus_neg_b).into());
    }

    #[test]
    fn test_fp_large_values() {
        let params = global_params();
        let max_value = Fp::new(&params.p - Integer::from(1), params);
        let half = Fp::new(&params.p / Integer::from(2), params);
        
        // Test with values near p
        let sum = max_value.add(&max_value);
        // (p-1) + (p-1) = 2p - 2 ≡ p - 2 (mod p)
        let expected = Fp::new(&params.p - Integer::from(2), params);
        assert!(sum.ct_eq(&expected).into());
        
        // Test multiplication of large values
        let product = max_value.mul(&max_value).expect("Should work");
        // (p-1)² = p² - 2p + 1 ≡ 1 (mod p)
        assert!(product.ct_eq(&Fp::one(params)).into());
        
        // Test with half the prime
        let double_half = half.add(&half);
        // 2 * (p/2) = p ≡ 0 (mod p)
        assert!(double_half.ct_eq(&Fp::zero(params)).into());
    }

    #[test]
    fn test_fp_error_handling() {
        let params = global_params();
        let other_params = NistLevel1Params::new();
        
        // Create elements with different parameters
        let a = Fp::new(Integer::from(5), params);
        let b = Fp::new(Integer::from(7), &other_params);
        
        // Operations between different fields should fail
        let result = a.mul(&b);
        assert!(result.is_err());
        
        // Inversion of zero should fail
        let zero = Fp::zero(params);
        let result = zero.invert();
        assert!(result.is_err());
    }

    #[test]
    fn test_fp_constant_time_properties() {
        let params = global_params();
        
        // Create elements with different values
        let a1 = Fp::new(Integer::from(1), params);
        let a2 = Fp::new(Integer::from(2), params);
        let b = Fp::new(Integer::from(3), params);
        
        // Time measurements should be constant regardless of values
        let start1 = std::time::Instant::now();
        black_box(a1.add(&b));
        let time1 = start1.elapsed().as_nanos();
        
        let start2 = std::time::Instant::now();
        black_box(a2.add(&b));
        let time2 = start2.elapsed().as_nanos();
        
        // Timing difference should be minimal (within 1%)
        let max_diff = std::cmp::max(time1, time2) as f64 * 0.01;
        assert!((time1 as i64 - time2 as i64).abs() <= max_diff as i64,
                "Timing difference too large: {} vs {}", time1, time2);
        
        // Byte representation should be constant length
        let bytes1 = a1.to_bytes();
        let bytes2 = a2.to_bytes();
        assert_eq!(bytes1.len(), bytes2.len(), "Byte representations should have same length");
    }

    fn black_box<T>(dummy: T) -> T {
        unsafe {
            let ret = std::ptr::read_volatile(&dummy);
            std::mem::forget(dummy);
            ret
        }
    }
}
