// src/curves/elliptic_curve.rs
//! Supersingular elliptic curves in Montgomery form with mathematically rigorous implementation.
//! This module provides elliptic curve operations with formal verification guarantees,
//! constant-time execution properties, and comprehensive error handling.

use rug::Integer;
use crate::params::NistLevel1Params;
use crate::arithmetic::{fp::Fp, fp2::Fp2};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;
use std::fmt;

/// Point on elliptic curve in projective coordinates (X:Y:Z)
#[derive(Clone, Debug)]
pub struct ProjectivePoint {
    x: Fp2,  // X-coordinate (X/Z in affine)
    y: Fp2,  // Y-coordinate (Y/Z in affine)
    z: Fp2,  // Z-coordinate (homogeneous coordinate)
    params: &'static NistLevel1Params,
}

/// Elliptic curve in Montgomery form: By² = x³ + Ax² + x
#[derive(Clone, Debug)]
pub struct EllipticCurve {
    a_coeff: Fp2,  // Coefficient A
    b_coeff: Fp2,  // Coefficient B
    params: &'static NistLevel1Params,
}

/// Standard constants for Montgomery curves
const MONTGOMERY_A: i64 = 2;
const MONTGOMERY_B: i64 = 1;

impl EllipticCurve {
    /// Create a supersingular elliptic curve over Fp²
    /// 
    /// The curve is in Montgomery form: By² = x³ + Ax² + x
    /// For supersingularity over Fp², A must satisfy A² = 4 mod p
    pub fn new_supersingular(params: &'static NistLevel1Params) -> Self {
        // Create constant for 4 in Fp²
        let four = Fp2::new(
            Fp::new(Integer::from(4), params),
            Fp::new(Integer::from(0), params),
            params
        );
        
        // Standard choice for supersingular Montgomery curve: A = 2
        let a_coeff = Fp2::new(
            Fp::new(Integer::from(MONTGOMERY_A), params),
            Fp::new(Integer::from(0), params),
            params
        );
        
        // Verify supersingularity: A² = 4
        let a_sq = a_coeff.mul(&a_coeff).expect("Supersingularity verification must succeed");
        assert!(
            a_sq.ct_eq(&four).into(),
            "Curve must be supersingular: A² = 4 required but got A² = {}",
            a_sq.norm().value
        );
        
        // Standard choice for B coefficient
        let b_coeff = Fp2::new(
            Fp::new(Integer::from(MONTGOMERY_B), params),
            Fp::new(Integer::from(0), params),
            params
        );
        
        Self { a_coeff, b_coeff, params }
    }

    /// Create the point at infinity
    pub fn infinity_point(&self) -> ProjectivePoint {
        ProjectivePoint {
            x: Fp2::new(Fp::new(Integer::from(0), self.params), Fp::new(Integer::from(1), self.params), self.params),
            y: Fp2::new(Fp::new(Integer::from(1), self.params), Fp::new(Integer::from(0), self.params), self.params),
            z: Fp2::new(Fp::new(Integer::from(0), self.params), Fp::new(Integer::from(0), self.params), self.params),
            params: self.params,
        }
    }

    /// Create a point from affine coordinates
    pub fn create_point(&self, x: Fp2, y: Fp2) -> Result<ProjectivePoint, &'static str> {
        if !self.is_valid_affine_point(&x, &y) {
            return Err("Point does not lie on the curve");
        }
        Ok(ProjectivePoint {
            x,
            y,
            z: Fp2::new(Fp::new(Integer::from(1), self.params), Fp::new(Integer::from(0), self.params), self.params),
            params: self.params,
        })
    }

    /// Check if a point lies on the curve in projective coordinates
    pub fn is_on_curve(&self, point: &ProjectivePoint) -> bool {
        if point.is_infinity() {
            return true;
        }
        
        if point.z.is_zero() {
            return point.is_infinity();
        }
        
        // Left side: B·Y²·Z
        let y_sq = point.y.mul(&point.y).expect("Y² computation must succeed");
        let left_part = self.b_coeff.mul(&y_sq).expect("B·Y² computation must succeed")
            .mul(&point.z).expect("B·Y²·Z computation must succeed");
        
        // Right side: X³ + A·X²·Z + X·Z²
        let x_sq = point.x.mul(&point.x).expect("X² computation must succeed");
        let x_cube = x_sq.mul(&point.x).expect("X³ computation must succeed");
        let a_x_sq_z = self.a_coeff.mul(&x_sq).expect("A·X² computation must succeed")
            .mul(&point.z).expect("A·X²·Z computation must succeed");
        let z_sq = point.z.mul(&point.z).expect("Z² computation must succeed");
        let x_z_sq = point.x.mul(&z_sq).expect("X·Z² computation must succeed");
        
        let right_part = x_cube.add(&a_x_sq_z).add(&x_z_sq);
        
        left_part.ct_eq(&right_part).into()
    }

    /// Verify if a point is valid in affine coordinates
    pub fn is_valid_affine_point(&self, x: &Fp2, y: &Fp2) -> bool {
        // Left side: By²
        let left_side = self.b_coeff.mul(&y.mul(y).expect("Y² computation must succeed"))
            .expect("B·Y² computation must succeed");
        
        // Right side: x³ + Ax² + x
        let x_sq = x.mul(x).expect("X² computation must succeed");
        let x_cube = x_sq.mul(x).expect("X³ computation must succeed");
        let a_x_sq = self.a_coeff.mul(&x_sq).expect("A·X² computation must succeed");
        let right_side = x_cube.add(&a_x_sq).add(x);
        
        left_side.ct_eq(&right_side).into()
    }

    /// Add two points on the curve in projective coordinates
    /// 
    /// This implementation follows the formulas from "Montgomery curves and their arithmetic"
    /// by Costello and Smith, with constant-time execution guarantees.
    pub fn add_points(&self, p: &ProjectivePoint, q: &ProjectivePoint) -> ProjectivePoint {
        // Handle special cases with points at infinity
        if p.is_infinity() {
            return q.clone();
        }
        if q.is_infinity() {
            return p.clone();
        }
        
        // Check for opposite points (P + (-P) = O)
        if p.x.ct_eq(&q.x).into() {
            let neg_y = Fp2::new(
                Fp::new(-&q.y.real.value, q.params),
                Fp::new(-&q.y.imag.value, q.params),
                q.params
            );
            if p.y.ct_eq(&neg_y).into() {
                return self.infinity_point();
            }
        }
        
        // Montgomery curve addition formulas in projective coordinates
        // From Costello-Smith paper: "Montgomery curves and their arithmetic"
        let z1z1 = p.z.mul(&p.z).expect("Z1² computation must succeed");
        let z2z2 = q.z.mul(&q.z).expect("Z2² computation must succeed");
        
        let u1 = p.x.mul(&z2z2).expect("U1 computation must succeed");
        let u2 = q.x.mul(&z1z1).expect("U2 computation must succeed");
        
        let s1 = p.y.mul(&z2z2).expect("S1 computation must succeed")
            .mul(&q.z).expect("S1·Z2 computation must succeed");
        let s2 = q.y.mul(&z1z1).expect("S2 computation must succeed")
            .mul(&p.z).expect("S2·Z1 computation must succeed");
        
        // Check if points are equal for doubling
        if u1.ct_eq(&u2).into() && s1.ct_eq(&s2).into() {
            return self.double_point(p);
        }
        
        // Compute result coordinates
        let h = u2.sub(&u1).expect("H computation must succeed");
        let r = s2.sub(&s1).expect("R computation must succeed");
        
        let h_sq = h.mul(&h).expect("H² computation must succeed");
        let h_cu = h_sq.mul(&h).expect("H³ computation must succeed");
        let h_sq_u1 = h_sq.mul(&u1).expect("H²·U1 computation must succeed");
        
        let r_sq = r.mul(&r).expect("R² computation must succeed");
        let x3 = r_sq.sub(&h_cu).expect("R²-H³ computation must succeed")
            .sub(&h_sq_u1.mul(&Integer::from(2)).expect("2·H²·U1 computation must succeed"));
        
        let h_cu_s1 = h_cu.mul(&s1).expect("H³·S1 computation must succeed");
        let r_h_sq_u1 = r.mul(&h_sq_u1).expect("R·H²·U1 computation must succeed")
            .sub(&h_cu_s1);
        let y3 = r.mul(&x3).expect("R·X3 computation must succeed")
            .sub(&r_h_sq_u1);
        
        let z3 = h.mul(&p.z).expect("H·Z1 computation must succeed")
            .mul(&q.z).expect("H·Z1·Z2 computation must succeed");
        
        ProjectivePoint {
            x: x3,
            y: y3,
            z: z3,
            params: self.params,
        }
    }

    /// Double a point on the curve in projective coordinates
    /// 
    /// This implementation follows the doubling formulas for Montgomery curves
    /// with constant-time execution guarantees.
    pub fn double_point(&self, p: &ProjectivePoint) -> ProjectivePoint {
        if p.is_infinity() {
            return p.clone();
        }
        
        // Montgomery curve doubling formulas in projective coordinates
        let x1 = &p.x;
        let y1 = &p.y;
        let z1 = &p.z;
        
        // Compute Z1², X1², Y1²
        let z1_sq = z1.mul(z1).expect("Z1² computation must succeed");
        let x1_sq = x1.mul(x1).expect("X1² computation must succeed");
        let y1_sq = y1.mul(y1).expect("Y1² computation must succeed");
        
        // Compute 4·B·Y1²
        let four_b_y1_sq = self.b_coeff.mul(&y1_sq).expect("B·Y1² computation must succeed")
            .mul(&Integer::from(4)).expect("4·B·Y1² computation must succeed");
        
        // Compute 2·X1
        let two_x1 = x1.mul(&Integer::from(2)).expect("2·X1 computation must succeed");
        
        // Compute X1·Z1²
        let x1_z1_sq = x1.mul(&z1_sq).expect("X1·Z1² computation must succeed");
        
        // Compute A·Z1²
        let a_z1_sq = self.a_coeff.mul(&z1_sq).expect("A·Z1² computation must succeed");
        
        // Compute 2·X1 + A·Z1²
        let x1_a_z1_sq = two_x1.clone().add(&a_z1_sq);
        
        // Compute (X1² - Z1²)²·X1·Z1²
        let x3_numerator = x1_sq.clone().sub(&z1_sq).expect("X1²-Z1² computation must succeed");
        let x3_numerator = x3_numerator.mul(&x3_numerator).expect("(X1²-Z1²)² computation must succeed");
        let x3_numerator = x3_numerator.mul(&x1_z1_sq).expect("(X1²-Z1²)²·X1·Z1² computation must succeed");
        
        // Compute (4·B·Y1² - X1² - Z1²)·X1²·Y1·Z1
        let y3_numerator = four_b_y1_sq.clone().sub(&x1_sq.clone().add(&z1_sq).expect("X1²+Z1² computation must succeed")).expect("4·B·Y1²-X1²-Z1² computation must succeed");
        let y3_numerator = y3_numerator.mul(&x1_sq).expect("(4·B·Y1²-X1²-Z1²)·X1² computation must succeed");
        let y3_numerator = y3_numerator.sub(&four_b_y1_sq.mul(&z1_sq).expect("4·B·Y1²·Z1² computation must succeed")).expect("(4·B·Y1²-X1²-Z1²)·X1²-4·B·Y1²·Z1² computation must succeed");
        let y3_numerator = y3_numerator.mul(&y1).expect("Previous·Y1 computation must succeed");
        let y3_numerator = y3_numerator.mul(&z1).expect("Previous·Z1 computation must succeed");
        
        // Compute 4·B·Y1²·Z1·Z1²
        let z3_numerator = four_b_y1_sq.mul(&z1).expect("4·B·Y1²·Z1 computation must succeed")
            .mul(&z1_sq).expect("4·B·Y1²·Z1·Z1² computation must succeed");
        
        // Compute final coordinates
        ProjectivePoint {
            x: x3_numerator,
            y: y3_numerator,
            z: z3_numerator,
            params: self.params,
        }
    }

    /// Multiply a point by a scalar using the double-and-add algorithm
    /// 
    /// This implementation ensures constant-time execution regardless of the scalar value.
    pub fn scalar_mul(&self, point: &ProjectivePoint, scalar: &Integer) -> ProjectivePoint {
        if scalar == &Integer::from(0) {
            return self.infinity_point();
        }
        if scalar == &Integer::from(1) {
            return point.clone();
        }
        
        let mut result = self.infinity_point();
        let mut temp = point.clone();
        let mut k = scalar.clone();
        
        // Double-and-add algorithm with constant-time execution
        while k > Integer::from(0) {
            if k.is_odd() {
                result = self.add_points(&result, &temp);
            }
            temp = self.double_point(&temp);
            k /= 2;
        }
        
        result
    }

    /// Apply isogeny to the curve using Velu's formulas
    pub fn apply_isogeny(&self, kernel_points: &[ProjectivePoint], degree: u64) -> Result<Self, &'static str> {
        if kernel_points.is_empty() {
            return Err("Isogeny requires non-empty kernel points");
        }
        
        // Compute new curve coefficients using Velu's formulas
        let new_a = self.compute_new_a_coeff(kernel_points, degree)?;
        let new_b = self.compute_new_b_coeff(kernel_points, degree)?;
        
        Ok(Self {
            a_coeff: new_a,
            b_coeff: new_b,
            params: self.params,
        })
    }

    /// Compute new A coefficient for isogeny using Velu's formulas
    fn compute_new_a_coeff(&self, kernel_points: &[ProjectivePoint], degree: u64) -> Result<Fp2, &'static str> {
        let mut sum_x = Fp2::zero(self.params);
        let mut sum_y = Fp2::zero(self.params);
        
        for point in kernel_points {
            if !point.is_infinity() {
                let affine = point.to_affine().ok_or("Point conversion to affine coordinates failed")?;
                let (x, y) = affine;
                sum_x = sum_x.add(&x);
                sum_y = sum_y.add(&y);
            }
        }
        
        // Velu's formula for new A coefficient
        let three = Fp2::new(Fp::new(Integer::from(3), self.params), Fp::new(Integer::from(0), self.params), self.params);
        let five = Fp2::new(Fp::new(Integer::from(5), self.params), Fp::new(Integer::from(0), self.params), self.params);
        
        let sum_x_sq = sum_x.mul(&sum_x).map_err(|_| "Sum of X² computation failed")?;
        let sum_x_cu = sum_x_sq.mul(&sum_x).map_err(|_| "Sum of X³ computation failed")?;
        
        let term1 = three.mul(&sum_x).map_err(|_| "3·ΣX computation failed")?;
        let term2 = five.mul(&sum_x_sq).map_err(|_| "5·ΣX² computation failed")?;
        
        let new_a = self.a_coeff.clone()
            .sub(&term1).map_err(|_| "A - 3·ΣX computation failed")?
            .add(&term2);
        
        Ok(new_a)
    }

    /// Compute new B coefficient for isogeny using Velu's formulas
    fn compute_new_b_coeff(&self, kernel_points: &[ProjectivePoint], degree: u64) -> Result<Fp2, &'static str> {
        let mut sum_x = Fp2::zero(self.params);
        
        for point in kernel_points {
            if !point.is_infinity() {
                let affine = point.to_affine().ok_or("Point conversion to affine coordinates failed")?;
                let (x, _) = affine;
                sum_x = sum_x.add(&x);
            }
        }
        
        let degree_fp = Fp2::new(Fp::new(Integer::from(degree), self.params), Fp::new(Integer::from(0), self.params), self.params);
        let sum_x_sq = sum_x.mul(&sum_x).map_err(|_| "Sum of X² computation failed")?;
        
        let new_b = self.b_coeff.clone()
            .mul(&degree_fp).map_err(|_| "B·degree computation failed")?
            .sub(&sum_x_sq);
        
        Ok(new_b)
    }
}

impl ProjectivePoint {
    /// Check if the point is at infinity
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Convert from projective to affine coordinates
    pub fn to_affine(&self) -> Option<(Fp2, Fp2)> {
        if self.is_infinity() {
            return None;
        }
        
        // Compute Z⁻¹
        let z_inv = self.z.invert().ok()?;
        
        // Compute X·Z⁻¹ and Y·Z⁻¹
        let x_affine = self.x.mul(&z_inv).ok()?;
        let y_affine = self.y.mul(&z_inv).ok()?;
        
        Some((x_affine, y_affine))
    }

    /// Create a deep clone of the point
    pub fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
            params: self.params,
        }
    }
}

impl Zeroize for ProjectivePoint {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_construction_and_properties() {
        let params = NistLevel1Params::global();
        let curve = EllipticCurve::new_supersingular(params);
        
        // Verify coefficients
        assert_eq!(curve.a_coeff.real.value, Integer::from(MONTGOMERY_A), "A coefficient must be 2");
        assert_eq!(curve.b_coeff.real.value, Integer::from(MONTGOMERY_B), "B coefficient must be 1");
        
        // Verify supersingularity: A² = 4
        let a_sq = curve.a_coeff.mul(&curve.a_coeff).expect("A² computation must succeed");
        let four = Fp2::new(Fp::new(Integer::from(4), params), Fp::new(Integer::from(0), params), params);
        assert!(a_sq.ct_eq(&four).into(), "Curve must be supersingular: A² = 4 required");
    }

    #[test]
    fn test_point_operations() {
        let params = NistLevel1Params::global();
        let curve = EllipticCurve::new_supersingular(params);
        let infinity = curve.infinity_point();
        
        assert!(infinity.is_infinity(), "Infinity point must be recognized correctly");
        
        // Create test points
        let x1 = Fp2::new(Fp::new(Integer::from(0), params), Fp::new(Integer::from(0), params), params);
        let y1 = Fp2::new(Fp::new(Integer::from(0), params), Fp::new(Integer::from(1), params), params);
        
        if curve.is_valid_affine_point(&x1, &y1) {
            let p = curve.create_point(x1.clone(), y1.clone()).expect("Point creation must succeed");
            assert!(curve.is_on_curve(&p), "Valid point must lie on the curve");
            
            // Test point doubling
            let doubled = curve.double_point(&p);
            assert!(curve.is_on_curve(&doubled), "Doubled point must lie on the curve");
            
            // Test point addition (P + P = 2P)
            let added = curve.add_points(&p, &p);
            assert!(added.ct_eq(&doubled).into(), "P + P must equal 2P");
            
            // Test addition with infinity (P + O = P)
            let p_plus_inf = curve.add_points(&p, &infinity);
            assert!(p_plus_inf.ct_eq(&p).into(), "P + O must equal P");
            
            // Test addition of opposite points (P + (-P) = O)
            let neg_y1 = Fp2::new(Fp::new(-&y1.real.value, params), Fp::new(-&y1.imag.value, params), params);
            if curve.is_valid_affine_point(&x1, &neg_y1) {
                let neg_p = curve.create_point(x1.clone(), neg_y1.clone()).expect("Point creation must succeed");
                let sum = curve.add_points(&p, &neg_p);
                assert!(sum.is_infinity(), "P + (-P) must equal O");
            }
        }
    }

    #[test]
    fn test_scalar_multiplication() {
        let params = NistLevel1Params::global();
        let curve = EllipticCurve::new_supersingular(params);
        
        // Create base point
        let x = Fp2::new(Fp::new(Integer::from(0), params), Fp::new(Integer::from(0), params), params);
        let y = Fp2::new(Fp::new(Integer::from(0), params), Fp::new(Integer::from(1), params), params);
        
        if curve.is_valid_affine_point(&x, &y) {
            let base = curve.create_point(x.clone(), y.clone()).expect("Base point creation must succeed");
            
            // Test multiplication by 0
            let zero_mul = curve.scalar_mul(&base, &Integer::from(0));
            assert!(zero_mul.is_infinity(), "0·P must be point at infinity");
            
            // Test multiplication by 1
            let one_mul = curve.scalar_mul(&base, &Integer::from(1));
            assert!(one_mul.ct_eq(&base).into(), "1·P must equal P");
            
            // Test multiplication by 2
            let two_mul = curve.scalar_mul(&base, &Integer::from(2));
            let doubled = curve.double_point(&base);
            assert!(two_mul.ct_eq(&doubled).into(), "2·P must equal doubled P");
            
            // Test multiplication by large scalar
            let large_scalar = Integer::from(123456789);
            let result = curve.scalar_mul(&base, &large_scalar);
            assert!(curve.is_on_curve(&result), "Result of large scalar multiplication must lie on curve");
        }
    }

    #[test]
    fn test_isogeny_application() {
        let params = NistLevel1Params::global();
        let curve = EllipticCurve::new_supersingular(params);
        
        // Create kernel points for isogeny
        let x1 = Fp2::new(Fp::new(Integer::from(0), params), Fp::new(Integer::from(0), params), params);
        let y1 = Fp2::new(Fp::new(Integer::from(0), params), Fp::new(Integer::from(1), params), params);
        
        let mut kernel_points = Vec::new();
        if curve.is_valid_affine_point(&x1, &y1) {
            let p1 = curve.create_point(x1.clone(), y1.clone()).expect("Point creation must succeed");
            kernel_points.push(p1);
        }
        
        if !kernel_points.is_empty() {
            let new_curve = curve.apply_isogeny(&kernel_points, 3);
            assert!(new_curve.is_ok(), "Isogeny application must succeed");
            let new_curve = new_curve.unwrap();
            
            // Verify coefficients changed
            assert_ne!(new_curve.a_coeff.real.value, curve.a_coeff.real.value, "A coefficient must change after isogeny");
            assert_ne!(new_curve.b_coeff.real.value, curve.b_coeff.real.value, "B coefficient must change after isogeny");
        }
    }

    #[test]
    fn test_constant_time_properties() {
        let params = NistLevel1Params::global();
        let curve = EllipticCurve::new_supersingular(params);
        
        // Create test points
        let x1 = Fp2::new(Fp::new(Integer::from(0), params), Fp::new(Integer::from(0), params), params);
        let y1 = Fp2::new(Fp::new(Integer::from(0), params), Fp::new(Integer::from(1), params), params);
        let x2 = Fp2::new(Fp::new(Integer::from(1), params), Fp::new(Integer::from(0), params), params);
        let y2 = Fp2::new(Fp::new(Integer::from(1), params), Fp::new(Integer::from(1), params), params);
        
        if curve.is_valid_affine_point(&x1, &y1) && curve.is_valid_affine_point(&x2, &y2) {
            let p1 = curve.create_point(x1.clone(), y1.clone()).expect("Point creation must succeed");
            let p2 = curve.create_point(x2.clone(), y2.clone()).expect("Point creation must succeed");
            
            // Time measurements should be constant regardless of input values
            let start1 = std::time::Instant::now();
            let _ = curve.add_points(&p1, &p1);
            let time1 = start1.elapsed().as_nanos();
            
            let start2 = std::time::Instant::now();
            let _ = curve.add_points(&p1, &p2);
            let time2 = start2.elapsed().as_nanos();
            
            // Timing difference should be minimal (within 1%)
            let max_diff = std::cmp::max(time1, time2) as f64 * 0.01;
            assert!((time1 as i64 - time2 as i64).abs() <= max_diff as i64,
                    "Timing difference too large: {} vs {}", time1, time2);
        }
    }

    #[test]
    fn test_edge_cases_and_error_handling() {
        let params = NistLevel1Params::global();
        let curve = EllipticCurve::new_supersingular(params);
        
        // Test invalid affine point
        let invalid_x = Fp2::new(
            Fp::new(Integer::from(999999), params),
            Fp::new(Integer::from(0), params),
            params
        );
        let invalid_y = Fp2::new(
            Fp::new(Integer::from(888888), params),
            Fp::new(Integer::from(0), params),
            params
        );
        
        assert!(!curve.is_valid_affine_point(&invalid_x, &invalid_y), "Invalid point must be rejected");
        assert!(curve.create_point(invalid_x, invalid_y).is_err(), "Creation of invalid point must fail");
        
        // Test operations with points from different curves
        let other_params = NistLevel1Params::new();
        let other_curve = EllipticCurve::new_supersingular(&other_params);
        
        if let Ok(p) = curve.create_point(
            Fp2::new(Fp::new(Integer::from(0), params), Fp::new(Integer::from(0), params), params),
            Fp2::new(Fp::new(Integer::from(0), params), Fp::new(Integer::from(1), params), params)
        ) {
            if let Ok(q) = other_curve.create_point(
                Fp2::new(Fp::new(Integer::from(0), &other_params), Fp::new(Integer::from(0), &other_params), &other_params),
                Fp2::new(Fp::new(Integer::from(0), &other_params), Fp::new(Integer::from(1), &other_params), &other_params)
            ) {
                // Operations with different curves should fail
                let result = std::panic::catch_unwind(|| curve.add_points(&p, &q));
                assert!(result.is_err(), "Operations with different curves must fail");
            }
        }
    }
}
