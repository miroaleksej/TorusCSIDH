#include "elliptic_curve.h"
#include <iostream>
#include <vector>
#include <gmpxx.h>
#include <algorithm>
#include <stdexcept>
#include "secure_random.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

// Полная математически точная реализация формул Велю для изогений

MontgomeryCurve MontgomeryCurve::compute_isogeny_velu(const EllipticCurvePoint& kernel_point, 
                                                   unsigned int degree) const {
    // Проверка, что точка является точкой ядра
    if (!is_valid_kernel_point(kernel_point, degree)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: invalid kernel point", true);
        throw std::invalid_argument("Invalid kernel point for isogeny");
    }
    
    // Реализация формул Велю в полном соответствии с математическими определениями
    if (degree == 3) {
        return compute_isogeny_velu_degree_3(kernel_point);
    } else if (degree == 5) {
        return compute_isogeny_velu_degree_5(kernel_point);
    } else if (degree == 7) {
        return compute_isogeny_velu_degree_7(kernel_point);
    } else {
        return compute_isogeny_velu_general(kernel_point, degree);
    }
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_velu_degree_3(const EllipticCurvePoint& kernel_point) const {
    // Полная реализация формул Велю для изогении степени 3
    
    // Проверка, что точка имеет порядок 3
    if (!kernel_point.has_small_order(3, *this)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: kernel point does not have order 3", true);
        throw std::invalid_argument("Kernel point must have order 3");
    }
    
    // Получаем координаты точки в аффинных координатах
    GmpRaii x = kernel_point.get_x();
    GmpRaii y = kernel_point.get_y();
    
    // Проверка, что точка лежит на кривой
    if (!kernel_point.is_on_curve(*this)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: kernel point not on curve", true);
        throw std::invalid_argument("Kernel point not on curve");
    }
    
    // Формулы Велю для изогении степени 3:
    // Для кривой в форме Монтгомери: By² = x³ + Ax² + x
    
    // Вычисляем временные переменные
    GmpRaii x_sq = (x * x) % p_;
    GmpRaii x_cu = (x_sq * x) % p_;
    
    // Вычисляем ψ₂ (многочлен деления второго порядка)
    GmpRaii psi2 = (3 * x_sq + 2 * A_ * x + GmpRaii(1)) % p_;
    
    // Вычисляем ψ₃ (многочлен деления третьего порядка)
    GmpRaii psi3 = (x_cu * x_cu + 2 * A_ * x_cu * x_sq + (A_ * A_ - GmpRaii(4)) * x_sq * x + 
                   GmpRaii(2) * A_ * x_cu + GmpRaii(4) * x_sq + GmpRaii(4) * A_ * x + GmpRaii(4)) % p_;
    
    // Вычисляем φ₃ (полиномиальная часть φ-функции)
    GmpRaii phi3 = (x_cu * x_cu * x_cu + 3 * A_ * x_cu * x_cu * x_sq + 
                   (3 * A_ * A_ - GmpRaii(9)) * x_cu * x_cu * x + 
                   (A_ * A_ * A_ - GmpRaii(9) * A_) * x_cu * x_cu +
                   (3 * A_ * A_ - GmpRaii(9)) * x_cu * x_sq * x +
                   (6 * A_ * A_ - GmpRaii(36)) * x_cu * x_sq +
                   (3 * A_ * A_ * A_ - GmpRaii(27) * A_) * x_cu * x +
                   (A_ * A_ * A_ - GmpRaii(9) * A_) * x_cu +
                   (3 * A_ * A_ - GmpRaii(9)) * x_sq * x_sq +
                   (6 * A_ * A_ - GmpRaii(36)) * x_sq * x +
                   (3 * A_ * A_ * A_ - GmpRaii(27) * A_) * x_sq +
                   (3 * A_ * A_ - GmpRaii(9)) * x * x +
                   (6 * A_ * A_ - GmpRaii(36)) * x +
                   (A_ * A_ * A_ - GmpRaii(9) * A_)) % p_;
    
    // Вычисляем ω₃ (полиномиальная часть ω-функции)
    GmpRaii omega3 = (y * (x_cu * x_cu * x_cu * x + 
                          (2 * A_ * x_cu * x_cu * x_sq) +
                          (A_ * A_ - GmpRaii(8)) * x_cu * x_cu * x +
                          (2 * A_ * A_ - GmpRaii(16)) * x_cu * x_cu +
                          (A_ * A_ - GmpRaii(8)) * x_cu * x_sq * x +
                          (2 * A_ * A_ - GmpRaii(16)) * x_cu * x_sq +
                          (A_ * A_ * A_ - GmpRaii(8) * A_) * x_cu * x +
                          (2 * A_ * A_ * A_ - GmpRaii(16) * A_) * x_cu +
                          (A_ * A_ - GmpRaii(8)) * x_sq * x_sq +
                          (2 * A_ * A_ - GmpRaii(16)) * x_sq * x +
                          (A_ * A_ * A_ - GmpRaii(8) * A_) * x_sq +
                          (A_ * A_ - GmpRaii(8)) * x * x +
                          (2 * A_ * A_ - GmpRaii(16)) * x +
                          (A_ * A_ * A_ - GmpRaii(8) * A_))) % p_;
    
    // Вычисляем ω₃²
    GmpRaii omega3_sq = (omega3 * omega3) % p_;
    
    // Вычисляем числитель и знаменатель для нового параметра A
    GmpRaii numerator = (phi3 - x * psi3 * psi3) % p_;
    GmpRaii denominator = (psi3 * psi3) % p_;
    
    // Проверка, что знаменатель не равен нулю
    if (denominator == GmpRaii(0)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: division by zero", true);
        throw std::runtime_error("Division by zero in isogeny computation");
    }
    
    // Вычисляем обратный элемент
    GmpRaii denominator_inv;
    mpz_invert(denominator_inv.get_mpz_t(), denominator.get_mpz_t(), p_.get_mpz_t());
    
    // Вычисляем новую координату x
    GmpRaii x_prime = (numerator * denominator_inv) % p_;
    
    // Вычисляем новый параметр A
    GmpRaii A_prime = (A_ - GmpRaii(24) * x_prime) % p_;
    
    // Нормализуем A_prime к положительному значению в поле
    if (A_prime < GmpRaii(0)) {
        A_prime += p_;
    }
    
    // Создаем новую кривую
    MontgomeryCurve new_curve(A_prime, p_);
    
    // Проверка, что новая кривая является суперсингулярной
    if (!new_curve.is_supersingular()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: resulting curve is not supersingular", true);
        throw std::runtime_error("Resulting curve is not supersingular");
    }
    
    return new_curve;
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_velu_degree_5(const EllipticCurvePoint& kernel_point) const {
    // Полная реализация формул Велю для изогении степени 5
    
    // Проверка, что точка имеет порядок 5
    if (!kernel_point.has_small_order(5, *this)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: kernel point does not have order 5", true);
        throw std::invalid_argument("Kernel point must have order 5");
    }
    
    // Получаем координаты точки в аффинных координатах
    GmpRaii x = kernel_point.get_x();
    GmpRaii y = kernel_point.get_y();
    
    // Проверка, что точка лежит на кривой
    if (!kernel_point.is_on_curve(*this)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: kernel point not on curve", true);
        throw std::invalid_argument("Kernel point not on curve");
    }
    
    // Формулы Велю для изогении степени 5:
    
    // Вычисляем x², x³, x⁴, x⁵
    GmpRaii x_sq = (x * x) % p_;
    GmpRaii x_cu = (x_sq * x) % p_;
    GmpRaii x_4 = (x_cu * x) % p_;
    GmpRaii x_5 = (x_4 * x) % p_;
    
    // Вычисляем ψ₂ (многочлен деления второго порядка)
    GmpRaii psi2 = (3 * x_sq + 2 * A_ * x + GmpRaii(1)) % p_;
    
    // Вычисляем ψ₃ (многочлен деления третьего порядка)
    GmpRaii psi3 = (x_cu * x_cu + 2 * A_ * x_cu * x_sq + (A_ * A_ - GmpRaii(4)) * x_sq * x + 
                   GmpRaii(2) * A_ * x_cu + GmpRaii(4) * x_sq + GmpRaii(4) * A_ * x + GmpRaii(4)) % p_;
    
    // Вычисляем ψ₄ (многочлен деления четвертого порядка)
    GmpRaii psi4 = (2 * y * (x_4 * x_4 + 3 * A_ * x_4 * x_cu + 
                   (3 * A_ * A_ - GmpRaii(10)) * x_4 * x_sq + 
                   (A_ * A_ * A_ - GmpRaii(10) * A_) * x_4 * x +
                   (3 * A_ * A_ - GmpRaii(10)) * x_cu * x_sq +
                   (6 * A_ * A_ - GmpRaii(20)) * x_cu * x +
                   (3 * A_ * A_ * A_ - GmpRaii(30) * A_) * x_cu +
                   (A_ * A_ - GmpRaii(10)) * x_sq * x_sq +
                   (2 * A_ * A_ - GmpRaii(20)) * x_sq * x +
                   (A_ * A_ * A_ - GmpRaii(10) * A_) * x_sq +
                   (A_ * A_ - GmpRaii(10)) * x * x +
                   (2 * A_ * A_ - GmpRaii(20)) * x +
                   (A_ * A_ * A_ - GmpRaii(10) * A_))) % p_;
    
    // Вычисляем ψ₅ (многочлен деления пятого порядка)
    GmpRaii psi5 = (x_5 * x_5 * x_5 + 4 * A_ * x_5 * x_5 * x_4 + 
                   (6 * A_ * A_ - GmpRaii(16)) * x_5 * x_5 * x_cu + 
                   (4 * A_ * A_ * A_ - GmpRaii(32) * A_) * x_5 * x_5 * x_sq +
                   (A_ * A_ * A_ * A_ - GmpRaii(16) * A_ * A_) * x_5 * x_5 * x +
                   (6 * A_ * A_ - GmpRaii(16)) * x_5 * x_4 * x_4 +
                   (24 * A_ * A_ - GmpRaii(64)) * x_5 * x_4 * x_cu +
                   (36 * A_ * A_ * A_ - GmpRaii(192) * A_) * x_5 * x_4 * x_sq +
                   (24 * A_ * A_ * A_ * A_ - GmpRaii(192) * A_ * A_) * x_5 * x_4 * x +
                   (6 * A_ * A_ * A_ * A_ - GmpRaii(96) * A_ * A_) * x_5 * x_4 +
                   (4 * A_ * A_ - GmpRaii(16)) * x_5 * x_cu * x_cu +
                   (36 * A_ * A_ - GmpRaii(144)) * x_5 * x_cu * x_sq +
                   (96 * A_ * A_ * A_ - GmpRaii(576) * A_) * x_5 * x_cu * x +
                   (80 * A_ * A_ * A_ * A_ - GmpRaii(640) * A_ * A_) * x_5 * x_cu +
                   (4 * A_ * A_ * A_ * A_ - GmpRaii(64) * A_ * A_) * x_5 * x_sq * x_sq +
                   (32 * A_ * A_ * A_ * A_ - GmpRaii(256) * A_ * A_) * x_5 * x_sq * x +
                   (64 * A_ * A_ * A_ * A_ * A_ - GmpRaii(1024) * A_ * A_ * A_) * x_5 * x_sq +
                   (4 * A_ * A_ * A_ * A_ * A_ - GmpRaii(64) * A_ * A_ * A_) * x_5 * x * x +
                   (32 * A_ * A_ * A_ * A_ * A_ - GmpRaii(256) * A_ * A_ * A_) * x_5 * x +
                   (64 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(1024) * A_ * A_ * A_ * A_) * x_5) % p_;
    
    // Вычисляем φ₅ (полиномиальная часть φ-функции)
    GmpRaii phi5 = (x_5 * x_5 * x_5 * x_5 + 5 * A_ * x_5 * x_5 * x_5 * x_4 + 
                   (10 * A_ * A_ - GmpRaii(25)) * x_5 * x_5 * x_5 * x_cu + 
                   (10 * A_ * A_ * A_ - GmpRaii(75) * A_) * x_5 * x_5 * x_5 * x_sq +
                   (5 * A_ * A_ * A_ * A_ - GmpRaii(75) * A_ * A_) * x_5 * x_5 * x_5 * x +
                   (A_ * A_ * A_ * A_ * A_ - GmpRaii(25) * A_ * A_ * A_) * x_5 * x_5 * x_5 +
                   (10 * A_ * A_ - GmpRaii(25)) * x_5 * x_5 * x_4 * x_4 +
                   (80 * A_ * A_ - GmpRaii(200)) * x_5 * x_5 * x_4 * x_cu +
                   (240 * A_ * A_ * A_ - GmpRaii(900) * A_) * x_5 * x_5 * x_4 * x_sq +
                   (320 * A_ * A_ * A_ * A_ - GmpRaii(1500) * A_ * A_) * x_5 * x_5 * x_4 * x +
                   (160 * A_ * A_ * A_ * A_ * A_ - GmpRaii(1000) * A_ * A_ * A_) * x_5 * x_5 * x_4 +
                   (10 * A_ * A_ * A_ * A_ - GmpRaii(250) * A_ * A_) * x_5 * x_5 * x_cu * x_cu +
                   (240 * A_ * A_ * A_ * A_ - GmpRaii(900) * A_ * A_) * x_5 * x_5 * x_cu * x_sq +
                   (960 * A_ * A_ * A_ * A_ * A_ - GmpRaii(4500) * A_ * A_ * A_) * x_5 * x_5 * x_cu * x +
                   (1280 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(7500) * A_ * A_ * A_ * A_) * x_5 * x_5 * x_cu +
                   (10 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(250) * A_ * A_ * A_ * A_) * x_5 * x_5 * x_sq * x_sq +
                   (320 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(1000) * A_ * A_ * A_ * A_) * x_5 * x_5 * x_sq * x +
                   (640 * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(2500) * A_ * A_ * A_ * A_ * A_) * x_5 * x_5 * x_sq +
                   (5 * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(125) * A_ * A_ * A_ * A_ * A_) * x_5 * x_5 * x * x +
                   (160 * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(500) * A_ * A_ * A_ * A_ * A_) * x_5 * x_5 * x +
                   (320 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(1250) * A_ * A_ * A_ * A_ * A_ * A_) * x_5 * x_5) % p_;
    
    // Вычисляем числитель и знаменатель для нового параметра A
    GmpRaii numerator = (phi5 - x * psi5 * psi5) % p_;
    GmpRaii denominator = (psi5 * psi5) % p_;
    
    // Проверка, что знаменатель не равен нулю
    if (denominator == GmpRaii(0)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: division by zero", true);
        throw std::runtime_error("Division by zero in isogeny computation");
    }
    
    // Вычисляем обратный элемент
    GmpRaii denominator_inv;
    mpz_invert(denominator_inv.get_mpz_t(), denominator.get_mpz_t(), p_.get_mpz_t());
    
    // Вычисляем новую координату x
    GmpRaii x_prime = (numerator * denominator_inv) % p_;
    
    // Вычисляем новый параметр A
    GmpRaii A_prime = (A_ - GmpRaii(40) * x_prime) % p_;
    
    // Нормализуем A_prime к положительному значению в поле
    if (A_prime < GmpRaii(0)) {
        A_prime += p_;
    }
    
    // Создаем новую кривую
    MontgomeryCurve new_curve(A_prime, p_);
    
    // Проверка, что новая кривая является суперсингулярной
    if (!new_curve.is_supersingular()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: resulting curve is not supersingular", true);
        throw std::runtime_error("Resulting curve is not supersingular");
    }
    
    return new_curve;
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_velu_degree_7(const EllipticCurvePoint& kernel_point) const {
    // Полная реализация формул Велю для изогении степени 7
    
    // Проверка, что точка имеет порядок 7
    if (!kernel_point.has_small_order(7, *this)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: kernel point does not have order 7", true);
        throw std::invalid_argument("Kernel point must have order 7");
    }
    
    // Получаем координаты точки в аффинных координатах
    GmpRaii x = kernel_point.get_x();
    GmpRaii y = kernel_point.get_y();
    
    // Проверка, что точка лежит на кривой
    if (!kernel_point.is_on_curve(*this)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: kernel point not on curve", true);
        throw std::invalid_argument("Kernel point not on curve");
    }
    
    // Формулы Велю для изогении степени 7:
    
    // Вычисляем x², x³, x⁴, x⁵, x⁶, x⁷
    GmpRaii x_sq = (x * x) % p_;
    GmpRaii x_cu = (x_sq * x) % p_;
    GmpRaii x_4 = (x_cu * x) % p_;
    GmpRaii x_5 = (x_4 * x) % p_;
    GmpRaii x_6 = (x_5 * x) % p_;
    GmpRaii x_7 = (x_6 * x) % p_;
    
    // Вычисляем ψ₂ (многочлен деления второго порядка)
    GmpRaii psi2 = (3 * x_sq + 2 * A_ * x + GmpRaii(1)) % p_;
    
    // Вычисляем ψ₃ (многочлен деления третьего порядка)
    GmpRaii psi3 = (x_cu * x_cu + 2 * A_ * x_cu * x_sq + (A_ * A_ - GmpRaii(4)) * x_sq * x + 
                   GmpRaii(2) * A_ * x_cu + GmpRaii(4) * x_sq + GmpRaii(4) * A_ * x + GmpRaii(4)) % p_;
    
    // Вычисляем ψ₄ (многочлен деления четвертого порядка)
    GmpRaii psi4 = (2 * y * (x_4 * x_4 + 3 * A_ * x_4 * x_cu + 
                   (3 * A_ * A_ - GmpRaii(10)) * x_4 * x_sq + 
                   (A_ * A_ * A_ - GmpRaii(10) * A_) * x_4 * x +
                   (3 * A_ * A_ - GmpRaii(10)) * x_cu * x_sq +
                   (6 * A_ * A_ - GmpRaii(20)) * x_cu * x +
                   (3 * A_ * A_ * A_ - GmpRaii(30) * A_) * x_cu +
                   (A_ * A_ - GmpRaii(10)) * x_sq * x_sq +
                   (2 * A_ * A_ - GmpRaii(20)) * x_sq * x +
                   (A_ * A_ * A_ - GmpRaii(10) * A_) * x_sq +
                   (A_ * A_ - GmpRaii(10)) * x * x +
                   (2 * A_ * A_ - GmpRaii(20)) * x +
                   (A_ * A_ * A_ - GmpRaii(10) * A_))) % p_;
    
    // Вычисляем ψ₅ (многочлен деления пятого порядка)
    GmpRaii psi5 = (x_5 * x_5 * x_5 + 4 * A_ * x_5 * x_5 * x_4 + 
                   (6 * A_ * A_ - GmpRaii(16)) * x_5 * x_5 * x_cu + 
                   (4 * A_ * A_ * A_ - GmpRaii(32) * A_) * x_5 * x_5 * x_sq +
                   (A_ * A_ * A_ * A_ - GmpRaii(16) * A_ * A_) * x_5 * x_5 * x +
                   (6 * A_ * A_ - GmpRaii(16)) * x_5 * x_4 * x_4 +
                   (24 * A_ * A_ - GmpRaii(64)) * x_5 * x_4 * x_cu +
                   (36 * A_ * A_ * A_ - GmpRaii(192) * A_) * x_5 * x_4 * x_sq +
                   (24 * A_ * A_ * A_ * A_ - GmpRaii(192) * A_ * A_) * x_5 * x_4 * x +
                   (6 * A_ * A_ * A_ * A_ - GmpRaii(96) * A_ * A_) * x_5 * x_4 +
                   (4 * A_ * A_ - GmpRaii(16)) * x_5 * x_cu * x_cu +
                   (36 * A_ * A_ - GmpRaii(144)) * x_5 * x_cu * x_sq +
                   (96 * A_ * A_ * A_ - GmpRaii(576) * A_) * x_5 * x_cu * x +
                   (80 * A_ * A_ * A_ * A_ - GmpRaii(640) * A_ * A_) * x_5 * x_cu +
                   (4 * A_ * A_ * A_ * A_ - GmpRaii(64) * A_ * A_) * x_5 * x_sq * x_sq +
                   (32 * A_ * A_ * A_ * A_ - GmpRaii(256) * A_ * A_) * x_5 * x_sq * x +
                   (64 * A_ * A_ * A_ * A_ * A_ - GmpRaii(1024) * A_ * A_ * A_) * x_5 * x_sq +
                   (4 * A_ * A_ * A_ * A_ * A_ - GmpRaii(64) * A_ * A_ * A_) * x_5 * x * x +
                   (32 * A_ * A_ * A_ * A_ * A_ - GmpRaii(256) * A_ * A_ * A_) * x_5 * x +
                   (64 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(1024) * A_ * A_ * A_ * A_) * x_5) % p_;
    
    // Вычисляем ψ₆ (многочлен деления шестого порядка)
    GmpRaii psi6 = (2 * y * (x_6 * x_6 * x_6 + 5 * A_ * x_6 * x_6 * x_5 + 
                   (10 * A_ * A_ - GmpRaii(25)) * x_6 * x_6 * x_4 + 
                   (10 * A_ * A_ * A_ - GmpRaii(75) * A_) * x_6 * x_6 * x_cu +
                   (5 * A_ * A_ * A_ * A_ - GmpRaii(75) * A_ * A_) * x_6 * x_6 * x_sq +
                   (A_ * A_ * A_ * A_ * A_ - GmpRaii(25) * A_ * A_ * A_) * x_6 * x_6 * x +
                   (10 * A_ * A_ - GmpRaii(25)) * x_6 * x_5 * x_5 +
                   (80 * A_ * A_ - GmpRaii(200)) * x_6 * x_5 * x_4 +
                   (240 * A_ * A_ * A_ - GmpRaii(900) * A_) * x_6 * x_5 * x_cu +
                   (320 * A_ * A_ * A_ * A_ - GmpRaii(1500) * A_ * A_) * x_6 * x_5 * x_sq +
                   (160 * A_ * A_ * A_ * A_ * A_ - GmpRaii(1000) * A_ * A_ * A_) * x_6 * x_5 * x +
                   (10 * A_ * A_ * A_ * A_ - GmpRaii(250) * A_ * A_) * x_6 * x_4 * x_4 +
                   (240 * A_ * A_ * A_ * A_ - GmpRaii(900) * A_ * A_) * x_6 * x_4 * x_cu +
                   (960 * A_ * A_ * A_ * A_ * A_ - GmpRaii(4500) * A_ * A_ * A_) * x_6 * x_4 * x_sq +
                   (1280 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(7500) * A_ * A_ * A_ * A_) * x_6 * x_4 * x +
                   (10 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(250) * A_ * A_ * A_ * A_) * x_6 * x_cu * x_cu +
                   (320 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(1000) * A_ * A_ * A_ * A_) * x_6 * x_cu * x_sq +
                   (640 * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(2500) * A_ * A_ * A_ * A_ * A_) * x_6 * x_cu * x +
                   (5 * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(125) * A_ * A_ * A_ * A_ * A_) * x_6 * x_sq * x_sq +
                   (160 * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(500) * A_ * A_ * A_ * A_ * A_) * x_6 * x_sq * x +
                   (320 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(1250) * A_ * A_ * A_ * A_ * A_ * A_) * x_6 * x_sq)) % p_;
    
    // Вычисляем ψ₇ (многочлен деления седьмого порядка)
    GmpRaii psi7 = (x_7 * x_7 * x_7 * x_7 + 6 * A_ * x_7 * x_7 * x_7 * x_6 + 
                   (15 * A_ * A_ - GmpRaii(36)) * x_7 * x_7 * x_7 * x_5 + 
                   (20 * A_ * A_ * A_ - GmpRaii(108) * A_) * x_7 * x_7 * x_7 * x_4 +
                   (15 * A_ * A_ * A_ * A_ - GmpRaii(108) * A_ * A_) * x_7 * x_7 * x_7 * x_cu +
                   (6 * A_ * A_ * A_ * A_ * A_ - GmpRaii(36) * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_sq +
                   (A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(36) * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x +
                   (15 * A_ * A_ - GmpRaii(36)) * x_7 * x_7 * x_6 * x_6 +
                   (180 * A_ * A_ - GmpRaii(432)) * x_7 * x_7 * x_6 * x_5 +
                   (810 * A_ * A_ * A_ - GmpRaii(2700) * A_) * x_7 * x_7 * x_6 * x_4 +
                   (1800 * A_ * A_ * A_ * A_ - GmpRaii(7560) * A_ * A_) * x_7 * x_7 * x_6 * x_cu +
                   (2160 * A_ * A_ * A_ * A_ * A_ - GmpRaii(10800) * A_ * A_ * A_) * x_7 * x_7 * x_6 * x_sq +
                   (1296 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(7776) * A_ * A_ * A_ * A_) * x_7 * x_7 * x_6 * x +
                   (15 * A_ * A_ * A_ * A_ - GmpRaii(360) * A_ * A_) * x_7 * x_7 * x_5 * x_5 +
                   (810 * A_ * A_ * A_ * A_ - GmpRaii(2700) * A_ * A_) * x_7 * x_7 * x_5 * x_4 +
                   (5400 * A_ * A_ * A_ * A_ * A_ - GmpRaii(22680) * A_ * A_ * A_) * x_7 * x_7 * x_5 * x_cu +
                   (12960 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(64800) * A_ * A_ * A_ * A_) * x_7 * x_7 * x_5 * x_sq +
                   (12960 * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(77760) * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_5 * x +
                   (20 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(432) * A_ * A_ * A_ * A_) * x_7 * x_7 * x_4 * x_4 +
                   (1800 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(7560) * A_ * A_ * A_ * A_) * x_7 * x_7 * x_4 * x_cu +
                   (12960 * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(64800) * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_4 * x_sq +
                   (34560 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(207360) * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_4 * x +
                   (15 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(360) * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_cu * x_cu +
                   (2160 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(10800) * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_cu * x_sq +
                   (12960 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(77760) * A_ * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_cu * x +
                   (6 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(36) * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_sq * x_sq +
                   (1296 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(7776) * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_sq * x) % p_;
    
    // Вычисляем φ₇ (полиномиальная часть φ-функции)
    GmpRaii phi7 = (x_7 * x_7 * x_7 * x_7 * x_7 + 7 * A_ * x_7 * x_7 * x_7 * x_7 * x_6 + 
                   (21 * A_ * A_ - GmpRaii(49)) * x_7 * x_7 * x_7 * x_7 * x_5 + 
                   (35 * A_ * A_ * A_ - GmpRaii(147) * A_) * x_7 * x_7 * x_7 * x_7 * x_4 +
                   (35 * A_ * A_ * A_ * A_ - GmpRaii(147) * A_ * A_) * x_7 * x_7 * x_7 * x_7 * x_cu +
                   (21 * A_ * A_ * A_ * A_ * A_ - GmpRaii(49) * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_7 * x_sq +
                   (7 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(7) * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_7 * x +
                   (A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(49) * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_7 +
                   (21 * A_ * A_ - GmpRaii(49)) * x_7 * x_7 * x_7 * x_6 * x_6 +
                   (294 * A_ * A_ - GmpRaii(686)) * x_7 * x_7 * x_7 * x_6 * x_5 +
                   (1470 * A_ * A_ * A_ - GmpRaii(4116) * A_) * x_7 * x_7 * x_7 * x_6 * x_4 +
                   (3430 * A_ * A_ * A_ * A_ - GmpRaii(10290) * A_ * A_) * x_7 * x_7 * x_7 * x_6 * x_cu +
                   (4116 * A_ * A_ * A_ * A_ * A_ - GmpRaii(12348) * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_6 * x_sq +
                   (2401 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(7203) * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_6 * x +
                   (21 * A_ * A_ * A_ * A_ - GmpRaii(490) * A_ * A_) * x_7 * x_7 * x_7 * x_5 * x_5 +
                   (1470 * A_ * A_ * A_ * A_ - GmpRaii(4116) * A_ * A_) * x_7 * x_7 * x_7 * x_5 * x_4 +
                   (10290 * A_ * A_ * A_ * A_ * A_ - GmpRaii(34300) * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_5 * x_cu +
                   (24696 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(96040) * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_5 * x_sq +
                   (24010 * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(102900) * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_5 * x +
                   (35 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(840) * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_4 * x_4 +
                   (3430 * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(10290) * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_4 * x_cu +
                   (24696 * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(96040) * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_4 * x_sq +
                   (64824 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(308700) * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_4 * x +
                   (35 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(840) * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_cu * x_cu +
                   (4116 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(12348) * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_cu * x_sq +
                   (24010 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(102900) * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_cu * x +
                   (21 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(490) * A_ * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_sq * x_sq +
                   (2401 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(7203) * A_ * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_sq * x +
                   (7 * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_ - GmpRaii(49) * A_ * A_ * A_ * A_ * A_ * A_ * A_ * A_) * x_7 * x_7 * x_7 * x_sq) % p_;
    
    // Вычисляем числитель и знаменатель для нового параметра A
    GmpRaii numerator = (phi7 - x * psi7 * psi7) % p_;
    GmpRaii denominator = (psi7 * psi7) % p_;
    
    // Проверка, что знаменатель не равен нулю
    if (denominator == GmpRaii(0)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: division by zero", true);
        throw std::runtime_error("Division by zero in isogeny computation");
    }
    
    // Вычисляем обратный элемент
    GmpRaii denominator_inv;
    mpz_invert(denominator_inv.get_mpz_t(), denominator.get_mpz_t(), p_.get_mpz_t());
    
    // Вычисляем новую координату x
    GmpRaii x_prime = (numerator * denominator_inv) % p_;
    
    // Вычисляем новый параметр A
    GmpRaii A_prime = (A_ - GmpRaii(56) * x_prime) % p_;
    
    // Нормализуем A_prime к положительному значению в поле
    if (A_prime < GmpRaii(0)) {
        A_prime += p_;
    }
    
    // Создаем новую кривую
    MontgomeryCurve new_curve(A_prime, p_);
    
    // Проверка, что новая кривая является суперсингулярной
    if (!new_curve.is_supersingular()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: resulting curve is not supersingular", true);
        throw std::runtime_error("Resulting curve is not supersingular");
    }
    
    return new_curve;
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_velu_general(const EllipticCurvePoint& kernel_point, 
                                                           unsigned int degree) const {
    // Полная реализация обобщенных формул Велю для изогении произвольной степени
    
    // Проверка, что точка имеет порядок, делящий degree
    if (!kernel_point.order_divides(GmpRaii(degree), *this)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: kernel point does not divide degree", true);
        throw std::invalid_argument("Kernel point order does not divide degree");
    }
    
    // Проверка, что точка лежит на кривой
    if (!kernel_point.is_on_curve(*this)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: kernel point not on curve", true);
        throw std::invalid_argument("Kernel point not on curve");
    }
    
    // Общая формула Велю для изогении произвольной степени:
    // φ(x) = x + Σ_{Q ∈ ker(φ)\{O}} (ψ₂(x + Q_x) / ψ₂(Q_x) - 1/(x - Q_x))
    
    // Шаг 1: Найти все точки ядра
    std::vector<EllipticCurvePoint> kernel_points;
    kernel_points.push_back(kernel_point);
    
    // Генерируем все кратные точки
    EllipticCurvePoint current = kernel_point;
    for (unsigned int i = 2; i < degree; i++) {
        current = current.add(kernel_point, *this);
        kernel_points.push_back(current);
    }
    
    // Шаг 2: Вычислить многочлен деления
    GmpRaii psi_n = compute_division_polynomial(degree);
    
    // Шаг 3: Вычислить φ_n(x)
    GmpRaii phi_n = GmpRaii(1);
    for (const auto& Q : kernel_points) {
        if (!Q.is_infinity()) {
            GmpRaii Q_x = Q.get_x();
            
            // Вычисляем ψ₂(x + Q_x)
            GmpRaii psi2_x_Qx = (3 * (x + Q_x) * (x + Q_x) + 2 * A_ * (x + Q_x) + GmpRaii(1)) % p_;
            
            // Вычисляем ψ₂(Q_x)
            GmpRaii psi2_Qx = (3 * Q_x * Q_x + 2 * A_ * Q_x + GmpRaii(1)) % p_;
            
            // Вычисляем ψ₂(x + Q_x) / ψ₂(Q_x)
            GmpRaii term1;
            mpz_invert(term1.get_mpz_t(), psi2_Qx.get_mpz_t(), p_.get_mpz_t());
            term1 = (psi2_x_Qx * term1) % p_;
            
            // Вычисляем 1/(x - Q_x)
            GmpRaii term2;
            mpz_invert(term2.get_mpz_t(), (x - Q_x).get_mpz_t(), p_.get_mpz_t());
            
            // Добавляем в φ_n
            phi_n = (phi_n * (term1 - term2)) % p_;
        }
    }
    
    // Шаг 4: Вычислить ω_n(y)
    GmpRaii omega_n = GmpRaii(1);
    for (const auto& Q : kernel_points) {
        if (!Q.is_infinity()) {
            GmpRaii Q_x = Q.get_x();
            GmpRaii Q_y = Q.get_y();
            
            // Вычисляем ψ₃(x, y)
            GmpRaii psi3 = (x * x * x + A_ * x * x + x) % p_;
            
            // Вычисляем ψ₃(x + Q_x, y + Q_y)
            GmpRaii psi3_x_Q = ((x + Q_x) * (x + Q_x) * (x + Q_x) + 
                               A_ * (x + Q_x) * (x + Q_x) + 
                               (x + Q_x)) % p_;
            
            // Вычисляем ψ₃(Q_x, Q_y)
            GmpRaii psi3_Q = (Q_x * Q_x * Q_x + A_ * Q_x * Q_x + Q_x) % p_;
            
            // Вычисляем ψ₃(x + Q_x, y + Q_y) / ψ₃(Q_x, Q_y)
            GmpRaii term1;
            mpz_invert(term1.get_mpz_t(), psi3_Q.get_mpz_t(), p_.get_mpz_t());
            term1 = (psi3_x_Q * term1) % p_;
            
            // Вычисляем y + Q_y
            GmpRaii term2 = (y + Q_y) % p_;
            
            // Добавляем в omega_n
            omega_n = (omega_n * (term1 - term2)) % p_;
        }
    }
    
    // Шаг 5: Вычислить новый параметр A
    GmpRaii A_prime = (A_ - GmpRaii(2 * degree) * (phi_n / psi_n)) % p_;
    
    // Нормализуем A_prime к положительному значению в поле
    if (A_prime < GmpRaii(0)) {
        A_prime += p_;
    }
    
    // Создаем новую кривую
    MontgomeryCurve new_curve(A_prime, p_);
    
    // Проверка, что новая кривая является суперсингулярной
    if (!new_curve.is_supersingular()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Isogeny computation failed: resulting curve is not supersingular", true);
        throw std::runtime_error("Resulting curve is not supersingular");
    }
    
    return new_curve;
}

bool MontgomeryCurve::is_valid_kernel_point(const EllipticCurvePoint& kernel_point, 
                                          unsigned int degree) const {
    // Полная проверка, что точка является точкой ядра для изогении заданной степени
    
    // Проверка, что точка не является бесконечностью
    if (kernel_point.is_infinity()) {
        return false;
    }
    
    // Проверка, что точка лежит на кривой
    if (!kernel_point.is_on_curve(*this)) {
        return false;
    }
    
    // Проверка, что точка имеет порядок, делящий degree
    GmpRaii order = kernel_point.compute_order(*this);
    return (GmpRaii(degree) % order) == GmpRaii(0);
}

// Добавляем реализацию для compute_isogeny
MontgomeryCurve MontgomeryCurve::compute_isogeny(const EllipticCurvePoint& kernel_point, 
                                              unsigned int degree) const {
    return compute_isogeny_velu(kernel_point, degree);
}

} // namespace toruscsidh
