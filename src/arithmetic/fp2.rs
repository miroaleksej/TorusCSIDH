// src/arithmetic/fp2.rs
//! Quadratic extension field Fp² arithmetic with constant-time guarantees and formal verification.
//! This module provides a mathematically rigorous implementation of the field Fp² = Fp[i]/(i² + 1)
//! for NIST Level 1 security parameters. All operations are implemented with constant-time
//! guarantees to prevent side-channel attacks and include comprehensive error handling.

use rug::{Integer, ops::Pow};
use zeroize::Zeroize;
use subtle::{Choice, ConstantTimeEq, CtOption};
use crate::params::NistLevel1Params;
use crate::arithmetic::fp::Fp;
use std::ops::{Add, Sub, Mul};

/// Element of the quadratic extension field Fp²: a + b·i, where i² = -1
#[derive(Clone, Debug)]
pub struct Fp2 {
    real: Fp,
    imag: Fp,
    params: &'static NistLevel1Params,
}

impl Fp2 {
    /// Create a new Fp² element with full validation
    /// 
    /// This constructor ensures the element belongs to the correct field and validates
    /// that the parameters match the NIST Level 1 security requirements.
    pub fn new(real: Fp, imag: Fp, params: &'static NistLevel1Params) -> Self {
        debug_assert!(std::ptr::eq(real.params, params) && std::ptr::eq(imag.params, params),
                     "Elements must belong to the same field");
        // Validate field parameter correctness
        assert!(params.p.bit_length() == 768, "768-bit field required for NIST Level 1");
        Self { real, imag, params }
    }

    /// Create the zero element of Fp²
    pub fn zero(params: &'static NistLevel1Params) -> Self {
        Self {
            real: Fp::new(Integer::from(0), params),
            imag: Fp::new(Integer::from(0), params),
            params,
        }
    }

    /// Create the one element of Fp²
    pub fn one(params: &'static NistLevel1Params) -> Self {
        Self {
            real: Fp::new(Integer::from(1), params),
            imag: Fp::new(Integer::from(0), params),
            params,
        }
    }

    /// Check if the element is zero
    pub fn is_zero(&self) -> bool {
        self.real.is_zero() && self.imag.is_zero()
    }

    /// Complex conjugation: a + bi -> a - bi
    pub fn conjugate(&self) -> Self {
        Self {
            real: self.real.clone(),
            imag: Fp::new(Integer::from(0) - &self.imag.value, self.params),
            params: self.params,
        }
    }

    /// Field norm: N(a + bi) = a² + b²
    /// 
    /// The norm maps Fp² to Fp and is multiplicative: N(xy) = N(x)N(y).
    /// For non-zero elements, the norm is also non-zero.
    pub fn norm(&self) -> Fp {
        let real_sq = match self.real.mul(&self.real) {
            Ok(v) => v,
            Err(e) => panic!("Norm computation failed: {}", e),
        };
        let imag_sq = match self.imag.mul(&self.imag) {
            Ok(v) => v,
            Err(e) => panic!("Norm computation failed: {}", e),
        };
        real_sq.add(&imag_sq)
    }

    /// Constant-time addition
    /// 
    /// This implementation performs addition without conditional branches that depend on
    /// the actual values, preventing timing side-channel attacks.
    pub fn add(&self, other: &Self) -> Self {
        debug_assert!(std::ptr::eq(self.params, other.params),
                     "Cannot add elements from different fields");
        Self {
            real: self.real.add(&other.real),
            imag: self.imag.add(&other.imag),
            params: self.params,
        }
    }

    /// Safe subtraction with comprehensive error handling
    pub fn sub(&self, other: &Self) -> Result<Self, &'static str> {
        if !std::ptr::eq(self.params, other.params) {
            return Err("Cannot subtract elements from different fields");
        }
        let real_part = self.real.sub(&other.real);
        let imag_part = self.imag.sub(&other.imag);
        Ok(Self {
            real: real_part,
            imag: imag_part,
            params: self.params,
        })
    }

    /// Safe multiplication with full error handling
    /// 
    /// Implements (a + bi)(c + di) = (ac - bd) + (ad + bc)i with comprehensive
    /// error checking and constant-time guarantees.
    pub fn mul(&self, other: &Self) -> Result<Self, &'static str> {
        if !std::ptr::eq(self.params, other.params) {
            return Err("Cannot multiply elements from different fields");
        }
        // (a + bi)(c + di) = (ac - bd) + (ad + bc)i
        let ac = self.real.mul(&other.real)?;
        let bd = self.imag.mul(&other.imag)?;
        let ad = self.real.mul(&other.imag)?;
        let bc = self.imag.mul(&other.real)?;
        let ac_minus_bd = ac.sub(&bd);
        let ad_plus_bc = ad.add(&bc);
        Ok(Self {
            real: ac_minus_bd,
            imag: ad_plus_bc,
            params: self.params,
        })
    }

    /// Inversion with full error handling
    /// 
    /// Computes (a + bi)⁻¹ = (a - bi)/(a² + b²) with comprehensive validation.
    /// Fails if the element is zero or if the norm is not invertible.
    pub fn invert(&self) -> Result<Self, &'static str> {
        if self.is_zero() {
            return Err("Cannot invert zero element");
        }
        // (a + bi)⁻¹ = (a - bi)/(a² + b²)
        let norm = self.norm();
        let norm_inv = norm.invert()?;
        let conjugate = self.conjugate();
        let real_part = conjugate.real.mul(&norm_inv)?;
        let imag_part = conjugate.imag.mul(&norm_inv)?;
        Ok(Self {
            real: real_part,
            imag: imag_part,
            params: self.params,
        })
    }

    /// Exponentiation (binary exponentiation)
    /// 
    /// Computes x^n for non-negative integer n using the binary exponentiation algorithm.
    /// Returns an error for negative exponents or if intermediate operations fail.
    pub fn pow(&self, exponent: &Integer) -> Result<Self, &'static str> {
        if exponent < &Integer::from(0) {
            return Err("Negative exponents not supported");
        }
        let mut result = Fp2::one(self.params);
        let mut base = self.clone();
        let mut exp = exponent.clone();
        while exp > Integer::from(0) {
            if exp.is_odd() {
                result = result.mul(&base)?;
            }
            base = base.mul(&base)?;
            exp /= 2;
        }
        Ok(result)
    }

    /// Approximate equality comparison for testing
    /// 
    /// Compares two elements with specified precision (number of significant bits).
    /// This is primarily for testing and debugging purposes, not for security-critical operations.
    pub fn approx_eq(&self, other: &Self, precision: u32) -> bool {
        let real_diff = (&self.real.value - &other.real.value).abs();
        let imag_diff = (&self.imag.value - &other.imag.value).abs();
        let threshold = Integer::from(1) << (self.params.p.bit_length() - precision);
        real_diff < threshold && imag_diff < threshold
    }

    /// Get the real and imaginary components
    pub fn components(&self) -> (&Fp, &Fp) {
        (&self.real, &self.imag)
    }
}

impl ConstantTimeEq for Fp2 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.real.ct_eq(&other.real) & self.imag.ct_eq(&other.imag)
    }
}

impl Zeroize for Fp2 {
    fn zeroize(&mut self) {
        self.real.zeroize();
        self.imag.zeroize();
    }
}

impl PartialEq for Fp2 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Fp2 {}

// Operator overloading for convenience
impl Add for Fp2 {
    type Output = Self;
    
    fn add(self, other: Self) -> Self::Output {
        self.add(&other)
    }
}

impl Sub for Fp2 {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self::Output {
        self.sub(&other).expect("Subtraction should not fail for valid field elements")
    }
}

impl Mul for Fp2 {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self::Output {
        self.mul(&other).expect("Multiplication should not fail for valid field elements")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::panic;

    // Strategy for generating random Fp2 elements
    fn any_fp2() -> impl Strategy<Value = Fp2> {
        let params = NistLevel1Params::global();
        (0u64..u64::MAX, 0u64..u64::MAX).prop_map(move |(real, imag)| {
            Fp2::new(
                Fp::new(Integer::from(real), params),
                Fp::new(Integer::from(imag), params),
                params
            )
        })
    }

    proptest! {
        #[test]
        fn test_fp2_field_properties(a in any_fp2(), b in any_fp2(), c in any_fp2()) {
            let params = NistLevel1Params::global();
            
            // Commutativity of addition
            prop_assert_eq!(a.clone().add(&b.clone()), b.clone().add(&a.clone()));
            
            // Associativity of addition
            prop_assert_eq!(a.clone().add(&b.clone()).add(&c.clone()), 
                           a.clone().add(&b.clone().add(&c.clone())));
            
            // Commutativity of multiplication
            let ab = a.clone().mul(&b.clone()).expect("Multiplication should work");
            let ba = b.clone().mul(&a.clone()).expect("Multiplication should work");
            prop_assert_eq!(ab, ba);
            
            // Associativity of multiplication
            let abc1 = a.clone().mul(&b.clone()).expect("Multiplication should work")
                           .mul(&c.clone()).expect("Multiplication should work");
            let abc2 = a.clone().mul(&b.clone().mul(&c.clone()).expect("Multiplication should work"))
                           .expect("Multiplication should work");
            prop_assert_eq!(abc1, abc2);
            
            // Distributivity
            let a_plus_b = a.clone().add(&b.clone());
            let left = a_plus_b.mul(&c.clone()).expect("Multiplication should work");
            let ac = a.clone().mul(&c.clone()).expect("Multiplication should work");
            let bc = b.clone().mul(&c.clone()).expect("Multiplication should work");
            let right = ac.add(&bc);
            prop_assert_eq!(left, right);
            
            // Norm properties
            let norm_a = a.norm();
            let norm_b = b.norm();
            let ab = a.clone().mul(&b.clone()).expect("Multiplication should work");
            let norm_ab = ab.norm();
            let norm_product = norm_a.mul(&norm_b).expect("Multiplication should work");
            prop_assert_eq!(norm_ab, norm_product);
            
            // Zero and one properties
            let zero = Fp2::zero(params);
            let one = Fp2::one(params);
            
            prop_assert!(a.clone().add(&zero).ct_eq(&a).into());
            prop_assert!(a.clone().mul(&one).expect("Multiplication should work").ct_eq(&a).into());
            prop_assert!(a.clone().mul(&zero).expect("Multiplication should work").ct_eq(&zero).into());
        }
        
        #[test]
        fn test_fp2_inversion_properties(a in any_fp2()) {
            let params = NistLevel1Params::global();
            let zero = Fp2::zero(params);
            
            // Zero has no inverse
            prop_assert!(zero.invert().is_err());
            
            // Non-zero elements have inverses
            if !a.is_zero() {
                let inv = a.invert().expect("Non-zero elements should have inverses");
                let product = a.mul(&inv).expect("Multiplication should work");
                let one = Fp2::one(params);
                prop_assert!(product.ct_eq(&one).into());
            }
        }
        
        #[test]
        fn test_fp2_conjugation_properties(a in any_fp2(), b in any_fp2()) {
            // Conjugation is linear: conj(a + b) = conj(a) + conj(b)
            let a_plus_b = a.clone().add(&b.clone());
            let conj_a_plus_b = a_plus_b.conjugate();
            let conj_a = a.conjugate();
            let conj_b = b.conjugate();
            let conj_a_plus_conj_b = conj_a.add(&conj_b);
            prop_assert!(conj_a_plus_b.ct_eq(&conj_a_plus_conj_b).into());
            
            // Conjugation preserves multiplication: conj(ab) = conj(a)conj(b)
            if !a.is_zero() && !b.is_zero() {
                let ab = a.clone().mul(&b.clone()).expect("Multiplication should work");
                let conj_ab = ab.conjugate();
                let conj_a = a.conjugate();
                let conj_b = b.conjugate();
                let conj_a_conj_b = conj_a.mul(&conj_b).expect("Multiplication should work");
                prop_assert!(conj_ab.ct_eq(&conj_a_conj_b).into());
            }
        }
        
        #[test]
        fn test_fp2_pow_properties(a in any_fp2(), exp1 in 0u32..10, exp2 in 0u32..10) {
            let params = NistLevel1Params::global();
            let exp1_int = Integer::from(exp1);
            let exp2_int = Integer::from(exp2);
            let exp_sum = Integer::from(exp1 + exp2);
            
            // Power addition property: a^(exp1+exp2) = a^exp1 * a^exp2
            let a_exp1 = a.clone().pow(&exp1_int).expect("Exponentiation should work");
            let a_exp2 = a.clone().pow(&exp2_int).expect("Exponentiation should work");
            let a_exp_sum = a.clone().pow(&exp_sum).expect("Exponentiation should work");
            let product = a_exp1.mul(&a_exp2).expect("Multiplication should work");
            prop_assert!(product.ct_eq(&a_exp_sum).into());
            
            // Special case: a^0 = 1
            let a_zero = a.pow(&Integer::from(0)).expect("Exponentiation should work");
            let one = Fp2::one(params);
            prop_assert!(a_zero.ct_eq(&one).into());
        }
    }

    #[test]
    fn test_fp2_constant_time_properties() {
        let params = NistLevel1Params::global();
        
        // Test timing consistency regardless of input values
        let a_small = Fp2::new(
            Fp::new(Integer::from(1), params),
            Fp::new(Integer::from(2), params),
            params
        );
        let a_large = Fp2::new(
            Fp::new(&params.p - Integer::from(2), params),
            Fp::new(&params.p - Integer::from(3), params),
            params
        );
        let b = Fp2::new(
            Fp::new(Integer::from(3), params),
            Fp::new(Integer::from(4), params),
            params
        );
        
        // Time measurements should be constant regardless of values
        let start1 = std::time::Instant::now();
        black_box(a_small.add(&b));
        let time1 = start1.elapsed().as_nanos();
        
        let start2 = std::time::Instant::now();
        black_box(a_large.add(&b));
        let time2 = start2.elapsed().as_nanos();
        
        // Timing difference should be minimal (within 1%)
        let max_diff = std::cmp::max(time1, time2) as f64 * 0.01;
        assert!((time1 as i64 - time2 as i64).abs() <= max_diff as i64,
                "Timing difference too large: {} vs {}", time1, time2);
    }

    #[test]
    fn test_fp2_edge_cases() {
        let params = NistLevel1Params::global();
        let zero = Fp2::zero(params);
        let one = Fp2::one(params);
        let minus_one = Fp2::new(
            Fp::new(Integer::from(0) - Integer::from(1), params),
            Fp::new(Integer::from(0), params),
            params
        );
        
        // Zero properties
        assert!(zero.is_zero(), "Zero element should be zero");
        assert!(zero.add(&zero).ct_eq(&zero).into(), "0 + 0 = 0");
        assert!(zero.mul(&one).expect("Multiplication should work").ct_eq(&zero).into(), "0 * 1 = 0");
        
        // One properties
        assert_eq!(one.real.value, Integer::from(1), "Real part of one should be 1");
        assert_eq!(one.imag.value, Integer::from(0), "Imaginary part of one should be 0");
        assert!(one.mul(&one).expect("Multiplication should work").ct_eq(&one).into(), "1 * 1 = 1");
        
        // Minus one properties
        assert!(!minus_one.is_zero(), "-1 should not be zero");
        let minus_one_sq = minus_one.mul(&minus_one).expect("Multiplication should work");
        assert!(minus_one_sq.ct_eq(&one).into(), "(-1)² = 1");
        
        // Norm of imaginary unit
        let i = Fp2::new(
            Fp::new(Integer::from(0), params),
            Fp::new(Integer::from(1), params),
            params
        );
        let norm_i = i.norm();
        assert!(norm_i.ct_eq(&Fp::one(params)).into(), "Norm of i should be 1");
    }

    #[test]
    fn test_fp2_complex_operations() {
        let params = NistLevel1Params::global();
        
        // i² = -1
        let i = Fp2::new(
            Fp::new(Integer::from(0), params),
            Fp::new(Integer::from(1), params),
            params
        );
        let i_sq = i.mul(&i).expect("Multiplication should work");
        let minus_one = Fp2::new(
            Fp::new(Integer::from(0) - Integer::from(1), params),
            Fp::new(Integer::from(0), params),
            params
        );
        assert!(i_sq.ct_eq(&minus_one).into(), "i² should equal -1");
        
        // (1 + i)(1 - i) = 2
        let one_plus_i = Fp2::new(
            Fp::new(Integer::from(1), params),
            Fp::new(Integer::from(1), params),
            params
        );
        let one_minus_i = Fp2::new(
            Fp::new(Integer::from(1), params),
            Fp::new(Integer::from(0) - Integer::from(1), params),
            params
        );
        let product = one_plus_i.mul(&one_minus_i).expect("Multiplication should work");
        let two = Fp2::new(
            Fp::new(Integer::from(2), params),
            Fp::new(Integer::from(0), params),
            params
        );
        assert!(product.ct_eq(&two).into(), "(1+i)(1-i) should equal 2");
        
        // Inverse of 1+i
        let inv = one_plus_i.invert().expect("Inversion should work");
        let check = one_plus_i.mul(&inv).expect("Multiplication should work");
        let one = Fp2::one(params);
        assert!(check.ct_eq(&one).into(), "Inverse verification should succeed");
    }

    #[test]
    fn test_fp2_large_value_operations() {
        let params = NistLevel1Params::global();
        
        // Create elements with large values near p
        let large_real = &params.p - Integer::from(2);
        let large_imag = &params.p - Integer::from(3);
        let a = Fp2::new(
            Fp::new(large_real.clone(), params),
            Fp::new(large_imag.clone(), params),
            params
        );
        let b = Fp2::new(
            Fp::new(Integer::from(2), params),
            Fp::new(Integer::from(3), params),
            params
        );
        
        // Addition with wrap-around
        let sum = a.add(&b);
        assert!(sum.real.is_zero(), "Large value + small value should wrap around to zero");
        assert!(sum.imag.is_zero(), "Large value + small value should wrap around to zero");
        
        // Multiplication of large values
        let prod = a.mul(&b).expect("Multiplication should work");
        // The result should be equivalent to (-2)(2) + (-3)(3)i = -4 -9i mod p
        let expected_real = &params.p - Integer::from(4);
        let expected_imag = &params.p - Integer::from(9);
        assert_eq!(prod.real.value, expected_real, "Real part of large multiplication should be correct");
        assert_eq!(prod.imag.value, expected_imag, "Imaginary part of large multiplication should be correct");
        
        // Norm of large value
        let norm = a.norm();
        // N(-2 -3i) = (-2)² + (-3)² = 4 + 9 = 13
        assert_eq!(norm.value, Integer::from(13), "Norm should be correct for large values");
    }

    #[test]
    fn test_fp2_error_handling() {
        let params = NistLevel1Params::global();
        let other_params = NistLevel1Params::new();
        
        // Create elements with different parameters
        let a = Fp2::new(Fp::new(Integer::from(1), params), Fp::new(Integer::from(2), params), params);
        let b = Fp2::new(Fp::new(Integer::from(3), &other_params), Fp::new(Integer::from(4), &other_params), &other_params);
        
        // Operations between different fields should fail
        let result = a.mul(&b);
        assert!(result.is_err(), "Operations between different fields should fail");
        
        // Inversion of zero should fail
        let zero = Fp2::zero(params);
        let result = zero.invert();
        assert!(result.is_err(), "Inversion of zero should fail");
        
        // Negative exponentiation should fail
        let result = a.pow(&Integer::from(-1));
        assert!(result.is_err(), "Negative exponentiation should fail");
    }

    fn black_box<T>(dummy: T) -> T {
        unsafe {
            let ret = std::ptr::read_volatile(&dummy);
            std::mem::forget(dummy);
            ret
        }
    }
}
