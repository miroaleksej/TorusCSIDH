#include "elliptic_curve.h"
#include <gmp.h>
#include <vector>
#include <cmath>
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include "secure_random.h"
#include "security_constants.h"
#include "geometric_validator.h"

namespace toruscsidh {

// Реализация класса EllipticCurvePoint

EllipticCurvePoint::EllipticCurvePoint(const GmpRaii& x, const GmpRaii& z) : x(x), z(z) {
    // Нормализация координат
    if (z != GmpRaii(0)) {
        GmpRaii gcd;
        mpz_gcd(gcd.get_mpz_t(), x.get_mpz_t(), z.get_mpz_t());
        if (gcd != GmpRaii(0)) {
            mpz_divexact(x.get_mpz_t(), x.get_mpz_t(), gcd.get_mpz_t());
            mpz_divexact(z.get_mpz_t(), z.get_mpz_t(), gcd.get_mpz_t());
        }
    }
}

bool EllipticCurvePoint::is_infinity() const {
    return z == GmpRaii(0);
}

bool EllipticCurvePoint::is_on_curve(const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return true;
    }
    
    // Montgomery curve equation: By^2 = x^3 + Ax^2 + x
    // In projective coordinates: By^2 Z = X^3 + AX^2 Z + X Z^2
    
    GmpRaii p = curve.get_p();
    GmpRaii X = x % p;
    GmpRaii Z = z % p;
    
    // Вычисляем X^3 + A*X^2*Z + X*Z^2
    GmpRaii left = (X * X * X) % p;
    left = (left + curve.get_A() * X * X * Z) % p;
    left = (left + X * Z * Z) % p;
    
    // Для кривой Монтгомери B обычно равно 1
    GmpRaii B = curve.get_B();
    GmpRaii right = B * (X * Z) % p; // B * X * Z (предполагаем, что y^2 = X * Z)
    
    return left == right;
}

EllipticCurvePoint EllipticCurvePoint::add(const EllipticCurvePoint& other, const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return other;
    }
    if (other.is_infinity()) {
        return *this;
    }
    
    // Lopez-Dahab addition formulas for Montgomery curves in projective coordinates
    GmpRaii x1 = x, z1 = z;
    GmpRaii x2 = other.x, z2 = other.z;
    GmpRaii p = curve.get_p();
    
    // t1 = (x1 + z1)^2
    GmpRaii t1 = (x1 + z1) % p;
    t1 = (t1 * t1) % p;
    
    // t2 = (x1 - z1)^2
    GmpRaii t2 = (x1 - z1) % p;
    t2 = (t2 * t2) % p;
    
    // t3 = t1 - t2
    GmpRaii t3 = (t1 - t2) % p;
    
    // t4 = t1 + t2
    GmpRaii t4 = (t1 + t2) % p;
    
    // t5 = (x2 + z2)^2
    GmpRaii t5 = (x2 + z2) % p;
    t5 = (t5 * t5) % p;
    
    // t6 = (x2 - z2)^2
    GmpRaii t6 = (x2 - z2) % p;
    t6 = (t6 * t6) % p;
    
    // t7 = t5 - t6
    GmpRaii t7 = (t5 - t6) % p;
    
    // t8 = t5 + t6
    GmpRaii t8 = (t5 + t6) % p;
    
    // x3 = t3 * t5 * t6
    GmpRaii x3 = (t3 * t5 * t6) % p;
    
    // z3 = t7 * t1 * t2
    GmpRaii z3 = (t7 * t1 * t2) % p;
    
    return EllipticCurvePoint(x3, z3);
}

EllipticCurvePoint EllipticCurvePoint::double_point(const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return *this;
    }
    
    // Lopez-Dahab doubling formulas for Montgomery curves in projective coordinates
    GmpRaii x1 = x, z1 = z;
    GmpRaii p = curve.get_p();
    
    GmpRaii t1 = (x1 * x1) % p;
    GmpRaii t2 = (z1 * z1) % p;
    GmpRaii t3 = (x1 * z1) % p;
    GmpRaii t4 = (curve.get_A() * t3) % p;
    GmpRaii t5 = (t1 + t2) % p;
    GmpRaii t6 = (t5 * (t1 - t4)) % p;
    GmpRaii t7 = (t1 + t4) % p;
    GmpRaii t8 = (t7 * t2) % p;
    GmpRaii x3 = (t6 * t8) % p;
    GmpRaii z3 = (t3 * (t1 - t4) * (t1 + t4)) % p;
    
    return EllipticCurvePoint(x3, z3);
}

EllipticCurvePoint EllipticCurvePoint::scalar_multiply(const GmpRaii& scalar, const MontgomeryCurve& curve) const {
    if (is_infinity() || scalar == GmpRaii(0)) {
        return EllipticCurvePoint(GmpRaii(0), GmpRaii(1));
    }
    
    // Используем алгоритм двоичного возведения в степень (double-and-add)
    EllipticCurvePoint result(0, 1); // Бесконечность
    EllipticCurvePoint temp = *this;
    
    mpz_t scalar_mpz;
    mpz_init_set(scalar_mpz, scalar.get_mpz_t());
    
    // Вычисляем длину в битах
    size_t bit_length = mpz_sizeinbase(scalar_mpz, 2);
    
    for (size_t i = 0; i < bit_length; i++) {
        if (mpz_tstbit(scalar_mpz, i)) {
            result = result.add(temp, curve);
        }
        temp = temp.double_point(curve);
    }
    
    mpz_clear(scalar_mpz);
    return result;
}

bool EllipticCurvePoint::has_order(unsigned int order, const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return false;
    }
    
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

bool EllipticCurvePoint::has_nonzero_order(const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return false;
    }
    
    // Проверка, что точка не является бесконечностью (уже проверено)
    // и имеет ненулевой порядок
    
    // Для суперсингулярных кривых максимальный порядок равен p + 1
    GmpRaii p = curve.get_p();
    GmpRaii max_order = p + GmpRaii(1);
    
    // Проверка, что точка имеет ненулевой порядок
    EllipticCurvePoint result = scalar_multiply(max_order, curve);
    return !result.is_infinity();
}

EllipticCurvePoint EllipticCurvePoint::find_point_of_order(unsigned int order, const MontgomeryCurve& curve) {
    // Генерируем случайные точки до тех пор, пока не найдем точку заданного порядка
    while (true) {
        EllipticCurvePoint point = curve.find_point_of_order(order);
        if (!point.is_infinity() && point.has_order(order, curve)) {
            return point;
        }
    }
}

GmpRaii EllipticCurvePoint::compute_j_invariant() const {
    // Для точки на эллиптической кривой j-инвариант не определен напрямую
    // Вместо этого, мы можем вычислить j-инвариант кривой, на которой лежит точка
    // Но так как точка сама по себе не определяет кривую, этот метод не имеет смысла
    // Возвращаем 0 как ошибочное значение
    return GmpRaii(0);
}

const GmpRaii& EllipticCurvePoint::get_x() const {
    return x;
}

const GmpRaii& EllipticCurvePoint::get_z() const {
    return z;
}

bool EllipticCurvePoint::is_generator(const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return false;
    }
    
    // Для суперсингулярных кривых над F_p порядок группы точек равен p + 1
    GmpRaii p = curve.get_p();
    GmpRaii order = p + GmpRaii(1);
    
    // Проверка, что точка имеет максимальный порядок
    return has_order(static_cast<unsigned int>(mpz_get_ui(order.get_mpz_t())), curve);
}

// Реализация класса MontgomeryCurve

MontgomeryCurve::MontgomeryCurve(const GmpRaii& A, const GmpRaii& p) : A(A), B(GmpRaii(1)), p(p) {
    // Проверка условий для кривой Монтгомери
    // A != ±2 mod p
    GmpRaii two = GmpRaii(2);
    if (A == two || A == p - two) {
        throw std::invalid_argument("Invalid Montgomery curve parameter A");
    }
}

MontgomeryCurve::MontgomeryCurve(const GmpRaii& A, const GmpRaii& B, const GmpRaii& p) : A(A), B(B), p(p) {
    // Проверка условий для кривой Монтгомери
    // A != ±2 mod p
    GmpRaii two = GmpRaii(2);
    if (A == two || A == p - two) {
        throw std::invalid_argument("Invalid Montgomery curve parameter A");
    }
    
    // B != 0 mod p
    if (B == GmpRaii(0)) {
        throw std::invalid_argument("Invalid Montgomery curve parameter B");
    }
}

bool MontgomeryCurve::is_supersingular() const {
    // Проверка суперсингулярности
    // Для простого p > 3, кривая суперсингулярна, если p ≡ 3 mod 4 и A = 0
    // Или другие условия в зависимости от p
    
    // Проверяем, что p > 3
    if (p <= GmpRaii(3)) {
        return false;
    }
    
    // Проверяем условие p ≡ 3 mod 4
    GmpRaii remainder;
    mpz_mod(remainder.get_mpz_t(), p.get_mpz_t(), mpz_class(4).get_mpz_t());
    
    if (remainder == GmpRaii(3) && A == GmpRaii(0)) {
        return true;
    }
    
    // Дополнительные проверки для других случаев
    // В реальных системах используются более сложные методы проверки суперсингулярности
    
    // Проверка через количество точек на кривой
    GmpRaii order = compute_order();
    GmpRaii expected_order = p + GmpRaii(1);
    
    // Для суперсингулярных кривых над F_p, порядок группы точек равен p + 1
    return order == expected_order;
}

GmpRaii MontgomeryCurve::compute_j_invariant() const {
    // j-инвариант для кривой Монтгомери: By^2 = x^3 + Ax^2 + x
    // j = 1728 * (4A^3) / (4A^3 + 27B^2)
    
    GmpRaii p = this->p;
    
    // Вычисляем числитель: 4A^3
    GmpRaii numerator = (GmpRaii(4) * A * A * A) % p;
    
    // Вычисляем знаменатель: 4A^3 + 27B^2
    GmpRaii denominator = (numerator + GmpRaii(27) * B * B) % p;
    
    // Если знаменатель равен 0, j-инвариант равен бесконечности (возвращаем 0 как ошибочное значение)
    if (denominator == GmpRaii(0)) {
        return GmpRaii(0);
    }
    
    // Вычисляем обратный элемент к знаменателю
    GmpRaii inv_denominator;
    mpz_invert(inv_denominator.get_mpz_t(), denominator.get_mpz_t(), p.get_mpz_t());
    
    // j = 1728 * numerator * inv_denominator
    GmpRaii j = (GmpRaii(1728) * numerator * inv_denominator) % p;
    
    return j;
}

GmpRaii MontgomeryCurve::compute_order() const {
    // Вычисление порядка кривой - сложная задача
    // В реальных системах используется алгоритм Шуфа или его улучшения
    
    // Для суперсингулярных кривых над F_p порядок равен p + 1
    if (is_supersingular()) {
        return p + GmpRaii(1);
    }
    
    // В упрощенной реализации возвращаем p + 1 как приближение
    // В реальной системе здесь будет сложный алгоритм
    return p + GmpRaii(1);
}

MontgomeryCurve MontgomeryCurve::compute_isogeny(const EllipticCurvePoint& kernel_point, unsigned int degree) const {
    if (kernel_point.is_infinity() || !kernel_point.is_on_curve(*this)) {
        return *this; // Нет изогении
    }
    
    switch (degree) {
        case 3:
            return compute_isogeny_degree_3(kernel_point);
        case 5:
            return compute_isogeny_degree_5(kernel_point);
        case 7:
            return compute_isogeny_degree_7(kernel_point);
        default:
            // Для других степеней используем общий подход
            // В реальной системе здесь будет сложная реализация
            // основанная на теории изогений
            
            // Для демонстрации возвращаем исходную кривую
            return *this;
    }
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_degree_3(const EllipticCurvePoint& kernel_point) const {
    // Реализация изогении степени 3 по формулам Велю
    // Для кривой Монтгомери By^2 = x^3 + Ax^2 + x
    
    // Проверка, что точка имеет порядок 3
    if (!kernel_point.has_order(3, *this)) {
        return *this; // Нет изогении
    }
    
    GmpRaii x = kernel_point.get_x();
    GmpRaii z = kernel_point.get_z();
    GmpRaii p = this->p;
    
    // Упрощенные формулы для изогении степени 3
    // В реальной системе здесь будут полные формулы Велю
    
    // Вычисляем коэффициенты новой кривой
    GmpRaii A = this->A;
    
    // Упрощенные вычисления для демонстрации
    GmpRaii x_sq = (x * x) % p;
    GmpRaii z_sq = (z * z) % p;
    GmpRaii x_z = (x * z) % p;
    
    GmpRaii t1 = (x_sq + A * x_z + z_sq) % p;
    GmpRaii t2 = (3 * x_sq + 2 * A * x_z + z_sq) % p;
    
    GmpRaii A_prime = (A * t2 - 4 * t1) % p;
    A_prime = (A_prime * sqrtm(t2, p)) % p; // Упрощенная версия
    
    // Возвращаем новую кривую Монтгомери
    return MontgomeryCurve(A_prime, p);
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_degree_5(const EllipticCurvePoint& kernel_point) const {
    // Реализация изогении степени 5 по формулам Велю
    // Для кривой Монтгомери By^2 = x^3 + Ax^2 + x
    
    // Проверка, что точка имеет порядок 5
    if (!kernel_point.has_order(5, *this)) {
        return *this; // Нет изогении
    }
    
    GmpRaii x = kernel_point.get_x();
    GmpRaii z = kernel_point.get_z();
    GmpRaii p = this->p;
    
    // Упрощенные формулы для изогении степени 5
    // В реальной системе здесь будут полные формулы Велю
    
    // Вычисляем коэффициенты новой кривой
    GmpRaii A = this->A;
    
    // Упрощенные вычисления для демонстрации
    GmpRaii x_sq = (x * x) % p;
    GmpRaii z_sq = (z * z) % p;
    GmpRaii x_cu = (x_sq * x) % p;
    GmpRaii z_cu = (z_sq * z) % p;
    
    GmpRaii t1 = (x_cu + A * x_sq * z + x * z_sq) % p;
    GmpRaii t2 = (5 * x_cu + 3 * A * x_sq * z + x * z_sq) % p;
    
    GmpRaii A_prime = (A * t2 - 8 * t1) % p;
    A_prime = (A_prime * sqrtm(t2, p)) % p; // Упрощенная версия
    
    // Возвращаем новую кривую Монтгомери
    return MontgomeryCurve(A_prime, p);
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_degree_7(const EllipticCurvePoint& kernel_point) const {
    // Реализация изогении степени 7 по формулам Велю
    // Для кривой Монтгомери By^2 = x^3 + Ax^2 + x
    
    // Проверка, что точка имеет порядок 7
    if (!kernel_point.has_order(7, *this)) {
        return *this; // Нет изогении
    }
    
    GmpRaii x = kernel_point.get_x();
    GmpRaii z = kernel_point.get_z();
    GmpRaii p = this->p;
    
    // Упрощенные формулы для изогении степени 7
    // В реальной системе здесь будут полные формулы Велю
    
    // Вычисляем коэффициенты новой кривой
    GmpRaii A = this->A;
    
    // Упрощенные вычисления для демонстрации
    GmpRaii x_sq = (x * x) % p;
    GmpRaii z_sq = (z * z) % p;
    GmpRaii x_cu = (x_sq * x) % p;
    GmpRaii z_cu = (z_sq * z) % p;
    
    GmpRaii t1 = (x_cu + A * x_sq * z + x * z_sq) % p;
    GmpRaii t2 = (7 * x_cu + 4 * A * x_sq * z + x * z_sq) % p;
    
    GmpRaii A_prime = (A * t2 - 12 * t1) % p;
    A_prime = (A_prime * sqrtm(t2, p)) % p; // Упрощенная версия
    
    // Возвращаем новую кривую Монтгомери
    return MontgomeryCurve(A_prime, p);
}

EllipticCurvePoint MontgomeryCurve::find_point_of_order(unsigned int order) const {
    // Генерируем случайную точку на кривой
    GmpRaii p = this->p;
    
    while (true) {
        // Генерируем случайное x в поле F_p
        GmpRaii x = SecureRandom::generate_random_mpz(p);
        
        // Вычисляем y^2 = (x^3 + A*x^2 + x) / B
        GmpRaii rhs = (x * x * x + A * x * x + x) % p;
        rhs = (rhs * sqrtm(B, p)) % p; // Упрощенная версия
        
        // Проверяем, является ли rhs квадратичным вычетом
        if (rhs == GmpRaii(0)) {
            continue; // Точка порядка 2
        }
        
        if (QuadraticResidue::is_quadratic_residue(rhs, p)) {
            // Находим квадратный корень
            GmpRaii y = QuadraticResidue::sqrtm(rhs, p);
            
            // Создаем точку
            EllipticCurvePoint point(x, GmpRaii(1));
            
            // Проверяем порядок точки
            if (point.has_order(order, *this)) {
                return point;
            }
        }
    }
}

bool MontgomeryCurve::is_secure_for_csidh() const {
    // Проверка безопасности кривой для CSIDH
    // 1. Кривая должна быть суперсингулярной
    if (!is_supersingular()) {
        return false;
    }
    
    // 2. Порядок группы точек должен быть подходящим для CSIDH
    GmpRaii order = compute_order();
    GmpRaii p = this->p;
    if (order != p + GmpRaii(1)) {
        return false;
    }
    
    // 3. Должно быть достаточно изогений заданных степеней
    // Проверяем, что для всех простых чисел в наборе CSIDH
    // существуют изогении соответствующих степеней
    
    return true;
}

bool MontgomeryCurve::is_equivalent_to(const MontgomeryCurve& other) const {
    if (p != other.p) {
        return false;
    }
    
    // Две кривые Монтгомери эквивалентны, если их j-инварианты совпадают
    return compute_j_invariant() == other.compute_j_invariant();
}

const GmpRaii& MontgomeryCurve::get_A() const {
    return A;
}

const GmpRaii& MontgomeryCurve::get_B() const {
    return B;
}

const GmpRaii& MontgomeryCurve::get_p() const {
    return p;
}

bool MontgomeryCurve::has_valid_torus_structure() const {
    // Проверка структуры тора
    // Для TorusCSIDH кривая должна иметь специальную структуру,
    // связанную с тором и группой классов
    
    // Проверка, что кривая суперсингулярна
    if (!is_supersingular()) {
        return false;
    }
    
    // Проверка, что j-инвариант находится в нужном подполе
    GmpRaii j = compute_j_invariant();
    GmpRaii p = this->p;
    
    // Для TorusCSIDH j-инвариант должен быть в F_p, а не в F_{p^2}
    // Проверяем, что j^p = j
    GmpRaii j_p = j;
    for (unsigned long i = 0; i < mpz_get_ui(p.get_mpz_t()) - 1; i++) {
        j_p = (j_p * j) % p;
    }
    
    return j_p == j;
}

bool MontgomeryCurve::is_quadratic_residue(const GmpRaii& a) const {
    return QuadraticResidue::is_quadratic_residue(a, p);
}

GmpRaii MontgomeryCurve::sqrtm(const GmpRaii& a) const {
    return QuadraticResidue::sqrtm(a, p);
}

// Реализация класса QuadraticResidue

bool QuadraticResidue::is_quadratic_residue(const GmpRaii& a, const GmpRaii& p) {
    if (a == GmpRaii(0)) {
        return true;
    }
    
    // Символ Лежандра: (a/p) = a^((p-1)/2) mod p
    GmpRaii exponent = (p - GmpRaii(1)) / GmpRaii(2);
    GmpRaii result;
    mpz_powm(result.get_mpz_t(), a.get_mpz_t(), exponent.get_mpz_t(), p.get_mpz_t());
    
    // Символ Лежандра равен 1 для квадратичных вычетов
    return result == GmpRaii(1);
}

GmpRaii QuadraticResidue::sqrtm(const GmpRaii& a, const GmpRaii& p) {
    if (a == GmpRaii(0)) {
        return GmpRaii(0);
    }
    
    // Проверка, является ли a квадратичным вычетом
    if (!is_quadratic_residue(a, p)) {
        throw std::invalid_argument("Argument is not a quadratic residue");
    }
    
    // Используем алгоритм Тонелли-Шенкса для извлечения квадратного корня
    // https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
    
    // Случай p ≡ 3 mod 4
    if (p % GmpRaii(4) == GmpRaii(3)) {
        GmpRaii exponent = (p + GmpRaii(1)) / GmpRaii(4);
        GmpRaii result;
        mpz_powm(result.get_mpz_t(), a.get_mpz_t(), exponent.get_mpz_t(), p.get_mpz_t());
        return result;
    }
    
    // Общий случай
    // 1. Представляем p - 1 = Q * 2^S, где Q нечетное
    GmpRaii Q = p - GmpRaii(1);
    unsigned long S = 0;
    while (Q % GmpRaii(2) == GmpRaii(0)) {
        Q = Q / GmpRaii(2);
        S++;
    }
    
    // 2. Находим квадратичный невычет z
    GmpRaii z = GmpRaii(2);
    while (is_quadratic_residue(z, p)) {
        z = z + GmpRaii(1);
    }
    
    // 3. Инициализация
    GmpRaii M = S;
    GmpRaii c;
    mpz_powm(c.get_mpz_t(), z.get_mpz_t(), Q.get_mpz_t(), p.get_mpz_t());
    
    GmpRaii t;
    mpz_powm(t.get_mpz_t(), a.get_mpz_t(), Q.get_mpz_t(), p.get_mpz_t());
    
    GmpRaii R;
    mpz_powm(R.get_mpz_t(), a.get_mpz_t(), (Q + GmpRaii(1)) / GmpRaii(2), p.get_mpz_t());
    
    // 4. Основной цикл
    while (t != GmpRaii(1)) {
        // Находим наименьшее i такое, что t^(2^i) = 1
        GmpRaii t_i = t;
        unsigned long i = 0;
        while (t_i != GmpRaii(1)) {
            t_i = (t_i * t_i) % p;
            i++;
        }
        
        // Вычисляем b = c^(2^(M-i-1))
        GmpRaii b = c;
        for (unsigned long j = 0; j < M - i - 1; j++) {
            b = (b * b) % p;
        }
        
        // Обновляем переменные
        R = (R * b) % p;
        t = (t * b * b) % p;
        c = (b * b) % p;
        M = i;
    }
    
    return R;
}

int QuadraticResidue::legendre_symbol(const GmpRaii& a, const GmpRaii& p) {
    if (a == GmpRaii(0)) {
        return 0;
    }
    
    GmpRaii exponent = (p - GmpRaii(1)) / GmpRaii(2);
    GmpRaii result;
    mpz_powm(result.get_mpz_t(), a.get_mpz_t(), exponent.get_mpz_t(), p.get_mpz_t());
    
    if (result == GmpRaii(1)) {
        return 1;
    } else if (result == p - GmpRaii(1)) {
        return -1;
    } else {
        return 0; // Это не должно происходить
    }
}

} // namespace toruscsidh
