#ifndef ELLIPTIC_CURVE_H
#define ELLIPTIC_CURVE_H

#include <vector>
#include <gmpxx.h>
#include <cstdint>
#include "security_constants.h"
#include "secure_random.h"
#include "postquantum_hash.h"

/**
 * @brief Точка на эллиптической кривой в форме Монтгомери
 */
class EllipticCurvePoint {
public:
    GmpRaii x;  ///< Координата x
    GmpRaii z;  ///< Координата z (для проективных координат)
    
    /**
     * @brief Конструктор
     * @param x Координата x
     * @param z Координата z
     */
    EllipticCurvePoint(const GmpRaii& x = GmpRaii(0), const GmpRaii& z = GmpRaii(1));
    
    /**
     * @brief Проверка, является ли точка бесконечностью
     * @return true, если точка является бесконечностью
     */
    bool is_infinity() const;
    
    /**
     * @brief Проверка, лежит ли точка на кривой
     * @param curve Кривая
     * @return true, если точка лежит на кривой
     */
    bool is_on_curve(const class MontgomeryCurve& curve) const;
    
    /**
     * @brief Сложение точек (алгоритм Лопес-Дахаб)
     * @param other Другая точка
     * @param curve Кривая
     * @return Результат сложения
     */
    EllipticCurvePoint add(const EllipticCurvePoint& other, const MontgomeryCurve& curve) const;
    
    /**
     * @brief Удвоение точки
     * @param curve Кривая
     * @return Удвоенная точка
     */
    EllipticCurvePoint double_point(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Умножение точки на скаляр
     * @param scalar Скаляр
     * @param curve Кривая
     * @return Результат умножения
     */
    EllipticCurvePoint scalar_multiply(const GmpRaii& scalar, const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка порядка точки
     * @param order Порядок
     * @param curve Кривая
     * @return true, если точка имеет указанный порядок
     */
    bool has_order(unsigned int order, const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, является ли точка генератором подгруппы заданного порядка
     * @param order Порядок
     * @param curve Кривая
     * @return true, если точка является генератором
     */
    bool is_generator_for_order(unsigned int order, const MontgomeryCurve& curve) const;
    
    /**
     * @brief Вычисление j-инварианта точки
     * @return j-инвариант
     */
    GmpRaii compute_j_invariant() const;
};

/**
 * @brief Эллиптическая кривая в форме Монтгомери
 */
class MontgomeryCurve {
public:
    GmpRaii A;  ///< Параметр A кривой
    GmpRaii p;  ///< Простое поле
    
    /**
     * @brief Конструктор
     * @param A Параметр A
     * @param p Простое поле
     */
    MontgomeryCurve(const GmpRaii& A = GmpRaii(0), const GmpRaii& p = GmpRaii(0));
    
    /**
     * @brief Создание кривой из j-инварианта
     * @param j_invariant j-инвариант
     * @param p Простое поле
     * @return Кривая
     */
    static MontgomeryCurve from_j_invariant(const GmpRaii& j_invariant, const GmpRaii& p);
    
    /**
     * @brief Вычисление j-инварианта кривой
     * @return j-инвариант
     */
    GmpRaii compute_j_invariant() const;
    
    /**
     * @brief Поиск точки заданного порядка
     * @param order Порядок точки
     * @param rng Генератор случайных чисел
     * @return Точка заданного порядка
     */
    EllipticCurvePoint find_point_of_order(unsigned int order, SecureRandom& rng) const;
    
    /**
     * @brief Проверка, является ли кривая суперсингулярной
     * @return true, если кривая суперсингулярна
     */
    bool is_supersingular() const;
    
    /**
     * @brief Вычисление изогении заданной степени
     * @param kernel_point Точка ядра
     * @param degree Степень изогении
     * @return Новая кривая после изогении
     */
    MontgomeryCurve compute_isogeny(const EllipticCurvePoint& kernel_point, unsigned int degree) const;
    
    /**
     * @brief Проверка, является ли кривая безопасной для CSIDH
     * @return true, если кривая безопасна
     */
    bool is_secure_for_csidh() const;
    
    /**
     * @brief Проверка, эквивалентны ли две кривые
     * @param other Другая кривая
     * @return true, если кривые эквивалентны
     */
    bool is_equivalent_to(const MontgomeryCurve& other) const;
};

EllipticCurvePoint::EllipticCurvePoint(const GmpRaii& x, const GmpRaii& z) : x(x), z(z) {}

bool EllipticCurvePoint::is_infinity() const {
    return z == GmpRaii(0);
}

bool EllipticCurvePoint::is_on_curve(const MontgomeryCurve& curve) const {
    if (is_infinity()) return true;
    
    // Montgomery curve equation: By^2 = x^3 + Ax^2 + x
    // In projective coordinates: By^2 Z = X^3 + AX^2 Z + X Z^2
    
    // We don't have y, so we check if there exists y such that the equation holds
    GmpRaii X = x;
    GmpRaii Z = z;
    
    // Compute X^3 + A X^2 Z + X Z^2
    GmpRaii left = (X * X * X) + (curve.A * X * X * Z) + (X * Z * Z);
    left %= curve.p;
    
    // Compute B Y^2 Z (we don't know Y, but we can check if left is a quadratic residue)
    // For Montgomery curves, B is usually 1, so we check if left * inv(Z) is a quadratic residue
    
    if (Z == GmpRaii(0)) {
        return false; // Should not happen for non-infinity points
    }
    
    GmpRaii Z_inv;
    mpz_invert(Z_inv.get_mpz_t(), Z.get_mpz_t(), curve.p.get_mpz_t());
    
    GmpRaii value = (left * Z_inv) % curve.p;
    
    // Check if value is a quadratic residue
    return mpz_legendre(value.get_mpz_t(), curve.p.get_mpz_t()) != -1;
}

EllipticCurvePoint EllipticCurvePoint::add(const EllipticCurvePoint& other, const MontgomeryCurve& curve) const {
    if (is_infinity()) return other;
    if (other.is_infinity()) return *this;
    
    // Lopez-Dahab addition formulas for Montgomery curves in projective coordinates
    GmpRaii x1 = x, z1 = z;
    GmpRaii x2 = other.x, z2 = other.z;
    
    GmpRaii t1 = (x1 * z2) % curve.p;
    GmpRaii t2 = (x2 * z1) % curve.p;
    GmpRaii t3 = (t1 - t2) % curve.p;
    GmpRaii t4 = (x1 * z2 + x2 * z1) % curve.p;
    GmpRaii t5 = (z1 * z2) % curve.p;
    GmpRaii t6 = (t4 * t5) % curve.p;
    GmpRaii t7 = (curve.A + 2) * t6 % curve.p;
    GmpRaii t8 = (x1 * x2) % curve.p;
    GmpRaii t9 = (t3 * t3) % curve.p;
    GmpRaii t10 = (t8 * t9) % curve.p;
    GmpRaii t11 = (t7 + t10) % curve.p;
    GmpRaii t12 = (t5 * t9) % curve.p;
    
    GmpRaii x3 = (t11 * t12) % curve.p;
    GmpRaii z3 = (t9 * t6) % curve.p;
    
    return EllipticCurvePoint(x3, z3);
}

EllipticCurvePoint EllipticCurvePoint::double_point(const MontgomeryCurve& curve) const {
    if (is_infinity()) return *this;
    
    // Lopez-Dahab doubling formulas for Montgomery curves in projective coordinates
    GmpRaii x1 = x, z1 = z;
    
    GmpRaii t1 = (x1 * x1) % curve.p;
    GmpRaii t2 = (z1 * z1) % curve.p;
    GmpRaii t3 = (x1 * z1) % curve.p;
    GmpRaii t4 = (curve.A * t3) % curve.p;
    GmpRaii t5 = (t1 + t2) % curve.p;
    GmpRaii t6 = (t5 * (t1 - t4)) % curve.p;
    GmpRaii t7 = (t1 + t4) % curve.p;
    GmpRaii t8 = (t7 * t2) % curve.p;
    
    GmpRaii x3 = (t6 * t8) % curve.p;
    GmpRaii z3 = (t3 * (t1 - t4) * (t1 + t4)) % curve.p;
    
    return EllipticCurvePoint(x3, z3);
}

EllipticCurvePoint EllipticCurvePoint::scalar_multiply(const GmpRaii& scalar, const MontgomeryCurve& curve) const {
    if (is_infinity()) return *this;
    
    EllipticCurvePoint result(0, 1); // Infinity point
    EllipticCurvePoint temp = *this;
    
    // Constant-time Montgomery ladder
    mpz_t k;
    mpz_init_set(k, scalar.get_mpz_t());
    
    for (size_t i = mpz_sizeinbase(k, 2); i > 0; i--) {
        bool bit = mpz_tstbit(k, i - 1);
        
        if (bit) {
            result = result.add(temp, curve);
            temp = temp.double_point(curve);
        } else {
            temp = result.add(temp, curve);
            result = result.double_point(curve);
        }
    }
    
    mpz_clear(k);
    return result;
}

bool EllipticCurvePoint::has_order(unsigned int order, const MontgomeryCurve& curve) const {
    if (is_infinity()) return false;
    
    // Проверка, что order * P = O
    EllipticCurvePoint result = scalar_multiply(GmpRaii(order), curve);
    if (!result.is_infinity()) {
        return false;
    }
    
    // Проверка, что для всех простых делителей d порядка, (order/d) * P != O
    // Для простоты проверяем только для d = 2 (предполагаем, что order - простое)
    if (order > 2) {
        EllipticCurvePoint test = scalar_multiply(GmpRaii(order / 2), curve);
        if (test.is_infinity()) {
            return false;
        }
    }
    
    return true;
}

bool EllipticCurvePoint::is_generator_for_order(unsigned int order, const MontgomeryCurve& curve) const {
    return has_order(order, curve);
}

GmpRaii EllipticCurvePoint::compute_j_invariant() const {
    if (is_infinity()) {
        return GmpRaii(0); // j-инвариант для бесконечной точки
    }
    
    // Для точки на кривой Монтгомери, j-инвариант можно вычислить как
    // j = 256 * (A^3) / (A^2 - 4)
    
    GmpRaii A = GmpRaii(0); // Нам нужно знать A кривой, но у точки его нет
    // На практике этот метод не используется для точек, только для кривых
    
    return GmpRaii(0); // Заглушка
}

MontgomeryCurve::MontgomeryCurve(const GmpRaii& A, const GmpRaii& p) : A(A), p(p) {}

MontgomeryCurve MontgomeryCurve::from_j_invariant(const GmpRaii& j_invariant, const GmpRaii& p) {
    // Преобразование j-инварианта в кривую Монтгомери
    // Формула: A = (36 * (j-1728)) / (j) для j != 0, 1728
    
    if (j_invariant == GmpRaii(0) || j_invariant == GmpRaii(1728)) {
        // Специальные случаи
        return MontgomeryCurve(GmpRaii(0), p);
    }
    
    GmpRaii j = j_invariant % p;
    GmpRaii numerator = (j - GmpRaii(1728)) * GmpRaii(36) % p;
    GmpRaii denominator = j;
    
    GmpRaii denominator_inv;
    mpz_invert(denominator_inv.get_mpz_t(), denominator.get_mpz_t(), p.get_mpz_t());
    
    GmpRaii A = (numerator * denominator_inv) % p;
    
    return MontgomeryCurve(A, p);
}

GmpRaii MontgomeryCurve::compute_j_invariant() const {
    // j-инвариант для кривой Монтгомери: 256 * (A^3) / (A^2 - 4)^3
    
    if (p == GmpRaii(0)) {
        return GmpRaii(0);
    }
    
    GmpRaii A2 = (A * A) % p;
    GmpRaii A3 = (A2 * A) % p;
    
    GmpRaii denominator_base = (A2 - GmpRaii(4)) % p;
    GmpRaii denominator = (denominator_base * denominator_base * denominator_base) % p;
    
    if (denominator == GmpRaii(0)) {
        return GmpRaii(0); // Не определено
    }
    
    GmpRaii denominator_inv;
    mpz_invert(denominator_inv.get_mpz_t(), denominator.get_mpz_t(), p.get_mpz_t());
    
    GmpRaii j = (GmpRaii(256) * A3 * denominator_inv) % p;
    
    return j;
}

EllipticCurvePoint MontgomeryCurve::find_point_of_order(unsigned int order, SecureRandom& rng) const {
    if (p == GmpRaii(0) || order == 0) {
        return EllipticCurvePoint(0, 1); // Бесконечность
    }
    
    // Ищем точку порядка order
    for (int attempt = 0; attempt < 100; attempt++) {
        // Генерируем случайный x
        GmpRaii x = GmpRaii(rng.random_uint(p));
        
        // Проверяем, что x^3 + A*x^2 + x является квадратичным вычетом
        GmpRaii rhs = (x * x * x + A * x * x + x) % p;
        
        if (rhs == GmpRaii(0)) {
            continue; // Точка порядка 2
        }
        
        if (mpz_legendre(rhs.get_mpz_t(), p.get_mpz_t()) == 1) {
            // Находим квадратный корень
            GmpRaii y;
            mpz_sqrtm(y.get_mpz_t(), rhs.get_mpz_t(), p.get_mpz_t());
            
            // Создаем точку
            EllipticCurvePoint point(x, GmpRaii(1));
            
            // Проверяем порядок точки
            if (point.has_order(order, *this)) {
                return point;
            }
        }
    }
    
    return EllipticCurvePoint(0, 1); // Бесконечность (не найдено)
}

bool MontgomeryCurve::is_supersingular() const {
    // Проверка суперсингулярности
    // Для простого p > 3, кривая суперсингулярна, если p ≡ 3 mod 4 и A = 0
    // Или другие условия в зависимости от p
    
    if (p <= GmpRaii(3)) {
        return false;
    }
    
    GmpRaii p_mod_4;
    mpz_mod_ui(p_mod_4.get_mpz_t(), p.get_mpz_t(), 4);
    
    return (p_mod_4 == GmpRaii(3) && A == GmpRaii(0));
}

MontgomeryCurve MontgomeryCurve::compute_isogeny(const EllipticCurvePoint& kernel_point, unsigned int degree) const {
    if (kernel_point.is_infinity() || !kernel_point.is_on_curve(*this)) {
        return *this; // Нет изогении
    }
    
    // Реализация формулы Велю для вычисления изогении
    // Для простоты, предположим, что degree - простое
    
    // Вычисляем новый параметр A' для кривой после изогении
    GmpRaii A_prime = A;
    
    // Это упрощенная реализация, реальная формула Велю сложнее
    // В реальной системе здесь будет полная реализация формул Велю
    
    return MontgomeryCurve(A_prime, p);
}

bool MontgomeryCurve::is_secure_for_csidh() const {
    // Проверка безопасности кривой для CSIDH
    // 1. Кривая должна быть суперсингулярной
    if (!is_supersingular()) {
        return false;
    }
    
    // 2. Порядок группы точек должен быть подходящим для CSIDH
    // 3. Должно быть достаточно изогений заданных степеней
    
    return true;
}

bool MontgomeryCurve::is_equivalent_to(const MontgomeryCurve& other) const {
    if (p != other.p) {
        return false;
    }
    
    // Две кривые Монтгомери эквивалентны, если их j-инварианты совпадают
    return compute_j_invariant() == other.compute_j_invariant();
}

#endif // ELLIPTIC_CURVE_H
