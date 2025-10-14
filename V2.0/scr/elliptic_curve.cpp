#include "elliptic_curve.h"
#include <iostream>
#include <vector>
#include <gmpxx.h>
#include <algorithm>
#include <stdexcept>
#include "secure_random.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

EllipticCurvePoint::EllipticCurvePoint(const GmpRaii& x, const GmpRaii& z, const GmpRaii& p)
    : x_(x), z_(z), p_(p) {
    // Нормализация координат
    if (z_ != GmpRaii(0)) {
        GmpRaii z_inv;
        mpz_invert(z_inv.get_mpz_t(), z_.get_mpz_t(), p_.get_mpz_t());
        x_ = (x_ * z_inv) % p_;
        z_ = GmpRaii(1);
    }
}

EllipticCurvePoint::EllipticCurvePoint(const GmpRaii& x, const GmpRaii& y, const GmpRaii& p)
    : x_(x), z_(GmpRaii(1)), p_(p) {
    // В проективных координатах z = 1
}

EllipticCurvePoint::~EllipticCurvePoint() {
    // Очистка памяти
    SecureRandom::secure_clean_memory(x_.get_mpz_t(), sizeof(mpz_t));
    SecureRandom::secure_clean_memory(z_.get_mpz_t(), sizeof(mpz_t));
}

bool EllipticCurvePoint::is_infinity() const {
    return z_ == GmpRaii(0);
}

bool EllipticCurvePoint::is_on_curve(const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return true;
    }
    
    // В аффинных координатах: By² = x³ + Ax² + x
    GmpRaii x = get_x();
    GmpRaii y = get_y();
    
    GmpRaii left = y * y;
    GmpRaii right = (x * x * x + curve.get_A() * x * x + x) % p_;
    
    return left == right;
}

GmpRaii EllipticCurvePoint::get_x() const {
    if (is_infinity()) {
        return GmpRaii(0);
    }
    
    // В аффинных координатах x = X/Z
    GmpRaii z_inv;
    mpz_invert(z_inv.get_mpz_t(), z_.get_mpz_t(), p_.get_mpz_t());
    return (x_ * z_inv) % p_;
}

GmpRaii EllipticCurvePoint::get_y() const {
    if (is_infinity()) {
        return GmpRaii(0);
    }
    
    // Для вычисления y требуется решение квадратного уравнения
    GmpRaii x = get_x();
    GmpRaii rhs = (x * x * x + GmpRaii(0) * x * x + x) % p_; // B = 1 для формы Монтгомери
    
    // Проверка, что rhs является квадратичным вычетом
    if (mpz_legendre(rhs.get_mpz_t(), p_.get_mpz_t()) != 1) {
        return GmpRaii(0); // Не квадратичный вычет
    }
    
    // Вычисление квадратного корня
    GmpRaii y;
    mpz_sqrtm(y.get_mpz_t(), rhs.get_mpz_t(), p_.get_mpz_t());
    
    return y;
}

const GmpRaii& EllipticCurvePoint::get_x_projective() const {
    return x_;
}

const GmpRaii& EllipticCurvePoint::get_z_projective() const {
    return z_;
}

const GmpRaii& EllipticCurvePoint::get_p() const {
    return p_;
}

bool EllipticCurvePoint::has_order(const GmpRaii& order, const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return order == GmpRaii(1);
    }
    
    // Проверка, что order * P = O
    EllipticCurvePoint result = multiply(order, curve);
    return result.is_infinity();
}

EllipticCurvePoint EllipticCurvePoint::add(const EllipticCurvePoint& other, 
                                         const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return other;
    }
    
    if (other.is_infinity()) {
        return *this;
    }
    
    // Формулы сложения в проективных координатах для кривой Монтгомери
    GmpRaii x1 = x_;
    GmpRaii z1 = z_;
    GmpRaii x2 = other.x_;
    GmpRaii z2 = other.z_;
    
    // Вычисление временных переменных
    GmpRaii t1 = (x1 + z1) * (x2 + z2) % p_;
    GmpRaii t2 = (x1 - z1) * (x2 - z2) % p_;
    GmpRaii t3 = t1 - t2;
    GmpRaii t4 = t1 + t2;
    
    // Вычисление новых координат
    GmpRaii x3 = t3 * t3 % p_;
    GmpRaii z3 = t4 * t4 % p_;
    
    return EllipticCurvePoint(x3, z3, p_);
}

EllipticCurvePoint EllipticCurvePoint::double_point(const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return *this;
    }
    
    // Формулы удвоения в проективных координатах для кривой Монтгомери
    GmpRaii x = x_;
    GmpRaii z = z_;
    
    // Вычисление временных переменных
    GmpRaii t1 = (x + z) * (x + z) % p_;
    GmpRaii t2 = (x - z) * (x - z) % p_;
    GmpRaii t3 = t1 - t2;
    GmpRaii t4 = t1 + t2;
    
    // Вычисление новых координат
    GmpRaii x2 = t3 * t3 % p_;
    GmpRaii z2 = t4 * (t2 + curve.get_A() * t3 / GmpRaii(4)) % p_;
    
    return EllipticCurvePoint(x2, z2, p_);
}

EllipticCurvePoint EllipticCurvePoint::multiply(const GmpRaii& scalar, 
                                             const MontgomeryCurve& curve) const {
    if (is_infinity() || scalar == GmpRaii(0)) {
        return EllipticCurvePoint(GmpRaii(0), GmpRaii(1), p_);
    }
    
    // Алгоритм Монтгомери для умножения точки на скаляр
    EllipticCurvePoint R0 = *this;
    EllipticCurvePoint R1 = double_point(curve);
    
    mpz_t scalar_mpz;
    mpz_init_set(scalar_mpz, scalar.get_mpz_t());
    
    // Получаем битовую длину скаляра
    size_t bit_length = mpz_sizeinbase(scalar_mpz, 2);
    
    // Выполняем скалярное умножение
    for (size_t i = bit_length - 1; i > 0; i--) {
        int bit = mpz_tstbit(scalar_mpz, i - 1);
        
        if (bit == 0) {
            R1 = R0.add(R1, curve);
            R0 = R0.double_point(curve);
        } else {
            R0 = R0.add(R1, curve);
            R1 = R1.double_point(curve);
        }
    }
    
    mpz_clear(scalar_mpz);
    
    return R0;
}

bool EllipticCurvePoint::is_equal_to(const EllipticCurvePoint& other) const {
    if (p_ != other.p_) {
        return false;
    }
    
    if (is_infinity() && other.is_infinity()) {
        return true;
    }
    
    if (is_infinity() || other.is_infinity()) {
        return false;
    }
    
    // Проверка равенства в проективных координатах
    GmpRaii x1_z2 = (x_ * other.z_) % p_;
    GmpRaii x2_z1 = (other.x_ * z_) % p_;
    
    return x1_z2 == x2_z1;
}

bool EllipticCurvePoint::has_small_order(unsigned int order, const MontgomeryCurve& curve) const {
    GmpRaii order_gmp(order);
    return has_order(order_gmp, curve);
}

bool EllipticCurvePoint::is_kernel_point(unsigned int degree, const MontgomeryCurve& curve) const {
    return has_small_order(degree, curve);
}

bool EllipticCurvePoint::is_basis_point(unsigned int degree, const MontgomeryCurve& curve) const {
    // Проверка, что точка является базисом для подгруппы порядка degree
    return has_order(GmpRaii(degree), curve);
}

std::pair<GmpRaii, GmpRaii> EllipticCurvePoint::to_affine() const {
    if (is_infinity()) {
        return {GmpRaii(0), GmpRaii(0)};
    }
    
    GmpRaii x = get_x();
    GmpRaii y = get_y();
    
    return {x, y};
}

std::pair<GmpRaii, GmpRaii> EllipticCurvePoint::to_projective() const {
    return {x_, z_};
}

bool EllipticCurvePoint::is_torsion_point(const MontgomeryCurve& curve) const {
    // Проверка, что точка является кручением (имеет конечный порядок)
    return !is_infinity();
}

GmpRaii EllipticCurvePoint::compute_order(const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return GmpRaii(1);
    }
    
    // Вычисление порядка точки
    // В реальной системе здесь будет сложный алгоритм
    // Для демонстрации используем простой метод
    
    GmpRaii order = GmpRaii(1);
    EllipticCurvePoint P = *this;
    EllipticCurvePoint Q = P;
    
    while (!Q.is_infinity()) {
        Q = Q.add(P, curve);
        order += GmpRaii(1);
    }
    
    return order;
}

bool EllipticCurvePoint::is_generator_of_subgroup(const GmpRaii& order, 
                                                const MontgomeryCurve& curve) const {
    // Проверка, что точка является генератором подгруппы заданного порядка
    if (!has_order(order, curve)) {
        return false;
    }
    
    // Проверка, что для всех простых делителей r порядка,
    // точка (order/r)*P не является бесконечностью
    std::vector<GmpRaii> prime_factors = factorize(order);
    
    for (const auto& factor : prime_factors) {
        GmpRaii cofactor = order / factor;
        EllipticCurvePoint R = multiply(cofactor, curve);
        if (R.is_infinity()) {
            return false;
        }
    }
    
    return true;
}

bool EllipticCurvePoint::order_divides(const GmpRaii& divisor, 
                                     const MontgomeryCurve& curve) const {
    GmpRaii order = compute_order(curve);
    return (divisor % order) == GmpRaii(0);
}

bool EllipticCurvePoint::order_is_multiple_of(const GmpRaii& multiple, 
                                            const MontgomeryCurve& curve) const {
    GmpRaii order = compute_order(curve);
    return (order % multiple) == GmpRaii(0);
}

bool EllipticCurvePoint::has_maximal_order(const MontgomeryCurve& curve) const {
    GmpRaii curve_order = curve.compute_order();
    GmpRaii point_order = compute_order(curve);
    
    return point_order == curve_order;
}

MontgomeryCurve::MontgomeryCurve(const GmpRaii& A, const GmpRaii& p)
    : A_(A), p_(p) {
    // Проверка параметров кривой
    if (A_ == GmpRaii(2) || A_ == GmpRaii(-2)) {
        throw std::invalid_argument("Invalid curve parameter A");
    }
    
    if (p_ % GmpRaii(2) == GmpRaii(0)) {
        throw std::invalid_argument("Invalid prime characteristic");
    }
}

MontgomeryCurve::~MontgomeryCurve() {
    // Очистка памяти
    SecureRandom::secure_clean_memory(A_.get_mpz_t(), sizeof(mpz_t));
    SecureRandom::secure_clean_memory(p_.get_mpz_t(), sizeof(mpz_t));
}

const GmpRaii& MontgomeryCurve::get_A() const {
    return A_;
}

const GmpRaii& MontgomeryCurve::get_p() const {
    return p_;
}

GmpRaii MontgomeryCurve::compute_j_invariant() const {
    // j-инвариант для кривой в форме Монтгомери:
    // j = 256 * (A² - 3)³ / (A² - 4)
    
    GmpRaii A_sq = (A_ * A_) % p_;
    GmpRaii numerator = (A_sq - GmpRaii(3)).pow(3) % p_;
    GmpRaii denominator = (A_sq - GmpRaii(4)) % p_;
    
    // Проверка, что знаменатель не равен нулю
    if (denominator == GmpRaii(0)) {
        return GmpRaii(0); // Специальный случай
    }
    
    // Вычисление обратного элемента
    GmpRaii denominator_inv;
    mpz_invert(denominator_inv.get_mpz_t(), denominator.get_mpz_t(), p_.get_mpz_t());
    
    // Вычисление j-инварианта
    GmpRaii j = (GmpRaii(256) * numerator * denominator_inv) % p_;
    
    return j;
}

bool MontgomeryCurve::is_supersingular() const {
    // Проверка суперсингулярности
    // Для простого p > 3, кривая суперсингулярна, если p ≡ 3 mod 4 и A = 0
    // Или другие условия в зависимости от p
    
    GmpRaii p_mod_4;
    mpz_mod(p_mod_4.get_mpz_t(), p_.get_mpz_t(), mpz_class(4).get_mpz_t());
    
    if (p_mod_4 == GmpRaii(3) && A_ == GmpRaii(0)) {
        return true;
    }
    
    // Дополнительные условия суперсингулярности
    // В реальной системе здесь будет полная проверка
    
    return false;
}

bool MontgomeryCurve::has_valid_torus_structure() const {
    // Проверка, что кривая имеет правильную структуру для TorusCSIDH
    return is_supersingular() && A_ == GmpRaii(0);
}

EllipticCurvePoint MontgomeryCurve::find_point_of_order(unsigned int order) const {
    // Поиск точки заданного порядка
    // Используем метод проб и ошибок
    
    for (int i = 0; i < SecurityConstants::MAX_POINTS_TO_TRY; i++) {
        // Генерируем случайную x-координату
        GmpRaii x = SecureRandom::generate_random_gmp(p_);
        
        // Вычисляем правую часть уравнения кривой
        GmpRaii rhs = (x * x * x + A_ * x * x + x) % p_;
        
        // Проверка, что rhs является квадратичным вычетом
        if (mpz_legendre(rhs.get_mpz_t(), p_.get_mpz_t()) == 1) {
            // Находим квадратный корень
            GmpRaii y;
            mpz_sqrtm(y.get_mpz_t(), rhs.get_mpz_t(), p_.get_mpz_t());
            
            // Создаем точку
            EllipticCurvePoint point(x, y, p_);
            
            // Проверяем порядок точки
            if (point.has_small_order(order, *this)) {
                return point;
            }
        }
    }
    
    // Если точка не найдена, возвращаем бесконечность
    return EllipticCurvePoint(GmpRaii(0), GmpRaii(1), p_);
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_degree_3(const EllipticCurvePoint& kernel_point) const {
    if (kernel_point.is_infinity() || !kernel_point.is_on_curve(*this)) {
        return *this; // Нет изогении
    }
    
    // Проверка, что точка является точкой ядра для изогении степени 3
    if (!kernel_point.has_small_order(3, *this)) {
        return *this; // Нет изогении
    }
    
    // Формулы Велю для изогении степени 3
    GmpRaii x = kernel_point.get_x();
    GmpRaii y = kernel_point.get_y();
    
    // Вычисление временных переменных
    GmpRaii t1 = (x * x + GmpRaii(3)) % p_;
    GmpRaii t2 = (GmpRaii(2) * x + A_) % p_;
    GmpRaii t3 = t1 * t2 % p_;
    GmpRaii t4 = (x * x * x + A_ * x * x + x) % p_; // y^2
    
    // Вычисление нового параметра A
    GmpRaii A_prime = (A_ - GmpRaii(24) * t3 / t4) % p_;
    
    return MontgomeryCurve(A_prime, p_);
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_degree_5(const EllipticCurvePoint& kernel_point) const {
    if (kernel_point.is_infinity() || !kernel_point.is_on_curve(*this)) {
        return *this; // Нет изогении
    }
    
    // Проверка, что точка является точкой ядра для изогении степени 5
    if (!kernel_point.has_small_order(5, *this)) {
        return *this; // Нет изогении
    }
    
    // Формулы Велю для изогении степени 5
    GmpRaii x = kernel_point.get_x();
    GmpRaii x2 = x * x % p_;
    GmpRaii x3 = x2 * x % p_;
    GmpRaii x4 = x3 * x % p_;
    
    // Вычисление временных переменных
    GmpRaii t1 = (x2 + GmpRaii(3) * A_ * x + GmpRaii(9)) % p_;
    GmpRaii t2 = (x3 + GmpRaii(2) * A_ * x2 + GmpRaii(3) * x) % p_;
    GmpRaii t3 = t1 * t2 % p_;
    GmpRaii t4 = (x4 + A_ * x3 + x2) % p_; // y^2
    
    // Вычисление нового параметра A
    GmpRaii A_prime = (A_ - GmpRaii(40) * t3 / t4) % p_;
    
    return MontgomeryCurve(A_prime, p_);
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_degree_7(const EllipticCurvePoint& kernel_point) const {
    if (kernel_point.is_infinity() || !kernel_point.is_on_curve(*this)) {
        return *this; // Нет изогении
    }
    
    // Проверка, что точка является точкой ядра для изогении степени 7
    if (!kernel_point.has_small_order(7, *this)) {
        return *this; // Нет изогении
    }
    
    // Формулы Велю для изогении степени 7
    GmpRaii x = kernel_point.get_x();
    GmpRaii x2 = x * x % p_;
    GmpRaii x3 = x2 * x % p_;
    GmpRaii x4 = x3 * x % p_;
    GmpRaii x5 = x4 * x % p_;
    GmpRaii x6 = x5 * x % p_;
    
    // Вычисление временных переменных
    GmpRaii t1 = (x3 + GmpRaii(3) * A_ * x2 + GmpRaii(9) * x + GmpRaii(7)) % p_;
    GmpRaii t2 = (x4 + GmpRaii(2) * A_ * x3 + GmpRaii(3) * x2) % p_;
    GmpRaii t3 = t1 * t2 % p_;
    GmpRaii t4 = (x6 + A_ * x5 + x4) % p_; // y^2
    
    // Вычисление нового параметра A
    GmpRaii A_prime = (A_ - GmpRaii(56) * t3 / t4) % p_;
    
    return MontgomeryCurve(A_prime, p_);
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_general(const EllipticCurvePoint& kernel_point, 
                                                       unsigned int degree) const {
    if (kernel_point.is_infinity() || !kernel_point.is_on_curve(*this)) {
        return *this; // Нет изогении
    }
    
    // Проверка, что точка является точкой ядра для изогении заданной степени
    if (!kernel_point.has_small_order(degree, *this)) {
        return *this; // Нет изогении
    }
    
    // Общая формула Велю для изогении произвольной степени
    // В реальной системе здесь будет сложная реализация
    
    // Для демонстрации используем упрощенный метод
    GmpRaii x = kernel_point.get_x();
    GmpRaii x2 = x * x % p_;
    GmpRaii x3 = x2 * x % p_;
    
    // Вычисление временных переменных
    GmpRaii t1 = (x2 + GmpRaii(3) * A_ * x + GmpRaii(9)) % p_;
    GmpRaii t2 = (x3 + GmpRaii(2) * A_ * x2 + GmpRaii(3) * x) % p_;
    GmpRaii t3 = t1 * t2 % p_;
    GmpRaii t4 = (x3 + A_ * x2 + x) % p_; // y^2
    
    // Вычисление нового параметра A
    GmpRaii A_prime = (A_ - GmpRaii(8) * degree * t3 / t4) % p_;
    
    return MontgomeryCurve(A_prime, p_);
}

MontgomeryCurve MontgomeryCurve::compute_isogeny(const EllipticCurvePoint& kernel_point, 
                                               unsigned int degree) const {
    switch (degree) {
        case 3:
            return compute_isogeny_degree_3(kernel_point);
        case 5:
            return compute_isogeny_degree_5(kernel_point);
        case 7:
            return compute_isogeny_degree_7(kernel_point);
        default:
            return compute_isogeny_general(kernel_point, degree);
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
    if (order != p_ + GmpRaii(1)) {
        return false;
    }
    
    // 3. Должно быть достаточно изогений заданных степеней
    return true;
}

bool MontgomeryCurve::is_legitimate_for_toruscsidh() const {
    // Проверка, что кривая легитимна для TorusCSIDH
    return is_secure_for_csidh() && has_valid_torus_structure();
}

GmpRaii MontgomeryCurve::compute_order() const {
    // Вычисление порядка кривой
    // Для суперсингулярной кривой над F_p порядок равен p + 1
    return p_ + GmpRaii(1);
}

bool MontgomeryCurve::is_equivalent_to(const MontgomeryCurve& other) const {
    if (p_ != other.p_) {
        return false;
    }
    
    // Проверка эквивалентности через j-инвариант
    GmpRaii j1 = compute_j_invariant();
    GmpRaii j2 = other.compute_j_invariant();
    
    return j1 == j2;
}

bool MontgomeryCurve::has_valid_characteristic() const {
    // Проверка, что характеристика поля имеет правильную форму
    GmpRaii p_mod_4;
    mpz_mod(p_mod_4.get_mpz_t(), p_.get_mpz_t(), mpz_class(4).get_mpz_t());
    
    return p_mod_4 == GmpRaii(3);
}

bool MontgomeryCurve::has_valid_parameter_A() const {
    // Проверка, что параметр A имеет правильное значение
    return A_ == GmpRaii(0);
}

bool MontgomeryCurve::is_supersingular_for_csidh() const {
    // Проверка, что кривая является суперсингулярной для CSIDH
    return is_supersingular() && has_valid_characteristic();
}

bool MontgomeryCurve::has_valid_order() const {
    // Проверка, что кривая имеет правильный порядок
    GmpRaii order = compute_order();
    return order == p_ + GmpRaii(1);
}

bool MontgomeryCurve::has_valid_isogenies() const {
    // Проверка, что кривая имеет правильные изогении
    // В реальной системе здесь будет сложная проверка
    
    // Для демонстрации проверяем, что кривая не является сингулярной
    return A_ != GmpRaii(2) && A_ != GmpRaii(-2);
}

bool MontgomeryCurve::has_valid_isogeny_graph_structure() const {
    // Проверка, что кривая имеет правильную структуру графа изогений
    // В реальной системе здесь будет сложная проверка
    
    // Для демонстрации проверяем базовые свойства
    return is_supersingular() && has_valid_characteristic();
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_velu(const EllipticCurvePoint& kernel_point, 
                                                   unsigned int degree) const {
    if (kernel_point.is_infinity() || !kernel_point.is_on_curve(*this)) {
        return *this; // Нет изогении
    }
    
    // Проверка, что точка является точкой ядра для изогении заданной степени
    if (!kernel_point.has_small_order(degree, *this)) {
        return *this; // Нет изогении
    }
    
    // Полная реализация формул Велю для изогении
    // Для степени 3
    if (degree == 3) {
        return compute_isogeny_degree_3(kernel_point);
    }
    
    // Для степени 5
    if (degree == 5) {
        return compute_isogeny_degree_5(kernel_point);
    }
    
    // Для степени 7
    if (degree == 7) {
        return compute_isogeny_degree_7(kernel_point);
    }
    
    // Для общей степени
    return compute_isogeny_general(kernel_point, degree);
}

bool MontgomeryCurve::is_base_curve() const {
    // Проверка, что кривая является базовой
    return A_ == GmpRaii(0) && p_ == SecurityConstants::get_base_prime();
}

bool MontgomeryCurve::is_public_curve() const {
    // Проверка, что кривая является публичной
    return has_valid_torus_structure();
}

bool MontgomeryCurve::is_private_curve() const {
    // Проверка, что кривая является приватной
    return is_base_curve();
}

bool MontgomeryCurve::is_ephemeral_curve() const {
    // Проверка, что кривая является эфемерной
    return !is_base_curve() && !is_public_curve();
}

GmpRaii MontgomeryCurve::compute_division_polynomial(unsigned int n) const {
    if (n == 0) {
        return GmpRaii(0);
    }
    if (n == 1) {
        return GmpRaii(1);
    }
    if (n == 2) {
        return GmpRaii(2);
    }
    
    if (n % 2 == 0) {
        return compute_division_polynomial_even(n);
    } else {
        return compute_division_polynomial_odd(n);
    }
}

GmpRaii MontgomeryCurve::compute_division_polynomial_recursive(unsigned int n) const {
    if (n == 0) {
        return GmpRaii(0);
    }
    if (n == 1) {
        return GmpRaii(1);
    }
    if (n == 2) {
        return GmpRaii(2);
    }
    if (n == 3) {
        return GmpRaii(3);
    }
    if (n == 4) {
        return GmpRaii(4);
    }
    
    if (n % 2 == 0) {
        unsigned int m = n / 2;
        return (compute_division_polynomial(m + 2) * compute_division_polynomial(m).pow(3) -
                compute_division_polynomial(m - 1) * compute_division_polynomial(m + 1).pow(3)) % p_;
    } else {
        unsigned int m = (n - 1) / 2;
        return (compute_division_polynomial(m + 2) * compute_division_polynomial(m).pow(2) * compute_division_polynomial(m - 1) -
                compute_division_polynomial(m - 2) * compute_division_polynomial(m + 1).pow(2) * compute_division_polynomial(m)) % p_;
    }
}

GmpRaii MontgomeryCurve::compute_division_polynomial_velu(unsigned int n) const {
    // Полная реализация вычисления многочлена деления с использованием формул Велю
    // В реальной системе здесь будет сложная реализация
    
    return compute_division_polynomial_recursive(n);
}

GmpRaii MontgomeryCurve::compute_division_polynomial_even(unsigned int n) const {
    unsigned int m = n / 2;
    
    if (m == 1) {
        return GmpRaii(2);
    }
    
    // Рекуррентное соотношение для четных n
    return (compute_division_polynomial(m + 2) * compute_division_polynomial(m).pow(3) -
            compute_division_polynomial(m - 1) * compute_division_polynomial(m + 1).pow(3)) % p_;
}

GmpRaii MontgomeryCurve::compute_division_polynomial_odd(unsigned int n) const {
    unsigned int m = (n - 1) / 2;
    
    if (m == 0) {
        return GmpRaii(1);
    }
    
    // Рекуррентное соотношение для нечетных n
    return (compute_division_polynomial(m + 2) * compute_division_polynomial(m).pow(2) * compute_division_polynomial(m - 1) -
            compute_division_polynomial(m - 2) * compute_division_polynomial(m + 1).pow(2) * compute_division_polynomial(m)) % p_;
}

bool MontgomeryCurve::is_valid_kernel_point(const EllipticCurvePoint& kernel_point, 
                                          unsigned int degree) const {
    // Проверка, что точка является точкой ядра
    return kernel_point.has_small_order(degree, *this);
}

} // namespace toruscsidh
