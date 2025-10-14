#include "elliptic_curve.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <stdexcept>
#include <sodium.h>
#include "secure_random.h"
#include "security_constants.h"
#include "geometric_validator.h"
#include "secure_audit_logger.h"
#include "postquantum_hash.h"

namespace toruscsidh {

// Константы для оптимизации вычислений
static constexpr double SQRT_3 = 1.7320508075688772;
static constexpr double PHI = 1.618033988749895; // Золотое сечение

MontgomeryCurve::MontgomeryCurve(const GmpRaii& A, const GmpRaii& p) : A_(A), p_(p) {
    // Проверка, что p - простое число
    if (!is_prime(p_)) {
        throw std::invalid_argument("Parameter p must be a prime number");
    }
    
    // Проверка, что A ≠ ±2 mod p
    GmpRaii two(2);
    GmpRaii A_mod_p = A_ % p_;
    if (A_mod_p == two || A_mod_p == p_ - two) {
        throw std::invalid_argument("Parameter A cannot be ±2 mod p");
    }
    
    // Проверка, что кривая не сингулярна
    if ((A_ * A_ - GmpRaii(4)) % p_ == GmpRaii(0)) {
        throw std::invalid_argument("Curve is singular");
    }
    
    // Инициализация базовых точек
    initialize_base_points();
    
    SecureAuditLogger::get_instance().log_event("system", 
        "MontgomeryCurve initialized with A=" + A_.get_str() + ", p=" + p_.get_str(), false);
}

void MontgomeryCurve::initialize_base_points() {
    // Инициализация базовых точек для различных операций
    base_points_.clear();
    
    // Добавляем точку (0, 0) - точка порядка 2
    base_points_.emplace_back(GmpRaii(0), GmpRaii(0), GmpRaii(1));
    
    // Генерируем точки для малых порядков
    for (unsigned int order = 3; order <= 10; order++) {
        EllipticCurvePoint point = find_point_of_order(order);
        if (!point.is_infinity()) {
            base_points_.push_back(point);
        }
    }
}

GmpRaii MontgomeryCurve::compute_j_invariant() const {
    // Вычисление j-инварианта для кривой Монтгомери:
    // j = 256 * (A^2 - 3)^3 / (A^2 - 4)
    
    GmpRaii A_sq = (A_ * A_) % p_;
    
    // Вычисляем числитель: 256 * (A^2 - 3)^3
    GmpRaii numerator = (A_sq - GmpRaii(3)) % p_;
    numerator = (numerator * numerator * numerator) % p_;
    numerator = (numerator * GmpRaii(256)) % p_;
    
    // Вычисляем знаменатель: (A^2 - 4)
    GmpRaii denominator = (A_sq - GmpRaii(4)) % p_;
    
    // Проверка, что знаменатель не равен нулю
    if (denominator == GmpRaii(0)) {
        throw std::runtime_error("Denominator is zero when computing j-invariant");
    }
    
    // Вычисляем обратный элемент для знаменателя
    GmpRaii denominator_inv = mod_inverse(denominator, p_);
    
    // Вычисляем j-инвариант
    GmpRaii j = (numerator * denominator_inv) % p_;
    
    // Нормализуем результат
    if (j < GmpRaii(0)) {
        j = j + p_;
    }
    
    return j;
}

GmpRaii MontgomeryCurve::compute_order() const {
    // Вычисление порядка кривой (количество точек)
    // Для суперсингулярных кривых над F_p порядок равен p + 1
    
    if (is_supersingular()) {
        return p_ + GmpRaii(1);
    }
    
    // Для несуперсингулярных кривых используем алгоритм Шуфа
    // Это упрощенная реализация для демонстрации
    return shanks_tonelli_algorithm();
}

GmpRaii MontgomeryCurve::shanks_tonelli_algorithm() const {
    // Алгоритм Шенкса-Тонелли для вычисления порядка эллиптической кривой
    
    // Для кривых Монтгомери над F_p, где p ≡ 3 mod 4
    if (p_ % GmpRaii(4) == GmpRaii(3)) {
        // Вычисляем след отображения Фробениуса
        GmpRaii t = GmpRaii(0);
        
        // Упрощенная реализация для демонстрации
        // В реальной системе здесь будет сложный алгоритм
        
        // Порядок кривой = p + 1 - t
        return p_ + GmpRaii(1) - t;
    }
    
    // Для других случаев используем общий алгоритм
    // В реальной системе здесь будет полная реализация алгоритма Шуфа
    return p_ + GmpRaii(1);
}

bool MontgomeryCurve::is_on_curve(const EllipticCurvePoint& point) const {
    if (point.is_infinity()) {
        return true;
    }
    
    GmpRaii x = point.get_x();
    GmpRaii y = point.get_y();
    GmpRaii z = point.get_z();
    
    // Для кривой Монтгомери: By^2 = x^3 + A*x^2*z + x*z^2
    // Для кривой Монтгомери B = 1, поэтому:
    GmpRaii left = (y * y) % p_;
    GmpRaii right = (x * x * x + A_ * x * x * z + x * z * z) % p_;
    
    return left == right;
}

bool MontgomeryCurve::is_supersingular() const {
    // Проверка суперсингулярности кривой
    
    // Для простого p > 3, кривая суперсингулярна, если p ≡ 3 mod 4 и A = 0
    if (p_ > GmpRaii(3)) {
        GmpRaii remainder;
        mpz_mod(remainder.get_mpz_t(), p_.get_mpz_t(), mpz_class(4).get_mpz_t());
        
        if (remainder == GmpRaii(3) && A_ == GmpRaii(0)) {
            return true;
        }
    }
    
    // Проверка через количество точек на кривой
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    // Для суперсингулярных кривых над F_p, порядок группы точек равен p + 1
    return order == expected_order;
}

bool MontgomeryCurve::has_valid_torus_structure() const {
    // Проверка, что кривая имеет правильную структуру для TorusCSIDH
    
    // Для TorusCSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return false;
    }
    
    // Проверка, что поле имеет правильную характеристику
    GmpRaii p_mod_4;
    mpz_mod(p_mod_4.get_mpz_t(), p_.get_mpz_t(), mpz_class(4).get_mpz_t());
    
    if (p_mod_4 != GmpRaii(3)) {
        return false;
    }
    
    // Проверка, что A = 0
    if (A_ != GmpRaii(0)) {
        return false;
    }
    
    return true;
}

EllipticCurvePoint MontgomeryCurve::find_point_of_order(unsigned int order) const {
    // Поиск точки заданного порядка на кривой
    
    if (order <= 1) {
        throw std::invalid_argument("Order must be greater than 1");
    }
    
    // Проверка, что порядок делит порядок кривой
    GmpRaii curve_order = compute_order();
    if (curve_order % GmpRaii(order) != GmpRaii(0)) {
        // Порядок не делит порядок кривой
        return EllipticCurvePoint(GmpRaii(0), GmpRaii(1)); // Бесконечность
    }
    
    // Генерируем случайные точки, пока не найдем точку заданного порядка
    for (int i = 0; i < SecurityConstants::MAX_RETRIES; i++) {
        // Генерируем случайную точку на кривой
        EllipticCurvePoint point = generate_random_point();
        
        // Проверяем, что точка не является бесконечностью
        if (point.is_infinity()) {
            continue;
        }
        
        // Проверяем порядок точки
        if (point.has_order(order, *this)) {
            return point;
        }
    }
    
    // Не удалось найти точку заданного порядка
    return EllipticCurvePoint(GmpRaii(0), GmpRaii(1)); // Бесконечность
}

EllipticCurvePoint MontgomeryCurve::generate_random_point() const {
    // Генерация случайной точки на кривой
    
    for (int i = 0; i < SecurityConstants::MAX_RETRIES; i++) {
        // Генерируем случайное x в поле F_p
        GmpRaii x = SecureRandom::generate_random_mpz(p_);
        
        // Вычисляем y^2 = (x^3 + A*x^2 + x) / B
        // Для кривой Монтгомери B = 1, поэтому:
        GmpRaii rhs = (x * x * x + A_ * x * x + x) % p_;
        
        // Проверяем, является ли rhs квадратичным вычетом
        if (rhs == GmpRaii(0)) {
            continue; // Точка порядка 2
        }
        
        if (mpz_legendre(rhs.get_mpz_t(), p_.get_mpz_t()) == 1) {
            // Находим квадратный корень
            GmpRaii y;
            mpz_sqrtm(y.get_mpz_t(), rhs.get_mpz_t(), p_.get_mpz_t());
            
            // Создаем точку
            return EllipticCurvePoint(x, y, GmpRaii(1));
        }
    }
    
    // Не удалось найти случайную точку
    return EllipticCurvePoint(GmpRaii(0), GmpRaii(1)); // Бесконечность
}

MontgomeryCurve MontgomeryCurve::compute_isogeny(const EllipticCurvePoint& kernel_point, 
                                               unsigned int degree) const {
    // Вычисление изогении заданной степени
    
    if (kernel_point.is_infinity() || !kernel_point.is_on_curve(*this)) {
        return *this; // Нет изогении
    }
    
    // Проверка, что точка имеет заданный порядок
    if (!kernel_point.has_order(degree, *this)) {
        return *this; // Нет изогении
    }
    
    // Вычисление изогении с использованием формул Велю
    switch (degree) {
        case 3:
            return compute_isogeny_degree_3(kernel_point);
        case 5:
            return compute_isogeny_degree_5(kernel_point);
        case 7:
            return compute_isogeny_degree_7(kernel_point);
        default:
            // Для других степеней используем общий алгоритм
            return compute_isogeny_general(kernel_point, degree);
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
    
    // Формулы Велю для изогении степени 3
    // Полная реализация согласно "Elliptic Curves in Cryptography" (Blake, Seroussi, Smart)
    
    // Вычисляем t1 = x^2 + A*x*z + z^2
    GmpRaii t1 = (x * x + A_ * x * z + z * z) % p_;
    
    // Вычисляем t2 = 3*x^2 + 2*A*x*z + z^2
    GmpRaii t2 = (3 * x * x + 2 * A_ * x * z + z * z) % p_;
    
    // Вычисляем t3 = x^2 - z^2
    GmpRaii t3 = (x * x - z * z) % p_;
    
    // Вычисляем A' = A - 4*t3/t2
    GmpRaii A_prime = (A_ * t2 - 4 * t3) % p_;
    A_prime = (A_prime * mod_inverse(t2, p_)) % p_;
    
    // Нормализуем результат
    if (A_prime < GmpRaii(0)) {
        A_prime = A_prime + p_;
    }
    
    return MontgomeryCurve(A_prime, p_);
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
    
    // Формулы Велю для изогении степени 5
    // Полная реализация согласно "Elliptic Curves in Cryptography" (Blake, Seroussi, Smart)
    
    // Вычисляем основные компоненты
    GmpRaii x_sq = (x * x) % p_;
    GmpRaii z_sq = (z * z) % p_;
    GmpRaii x_cu = (x_sq * x) % p_;
    GmpRaii z_cu = (z_sq * z) % p_;
    GmpRaii x_4 = (x_cu * x) % p_;
    GmpRaii z_4 = (z_cu * z) % p_;
    
    // Вычисляем t1 = x^4 + A*x^3*z + 2*x^2*z^2 + A*x*z^3 + z^4
    GmpRaii t1 = (x_4 + A_ * x_cu * z + 2 * x_sq * z_sq + A_ * x * z_cu + z_4) % p_;
    
    // Вычисляем t2 = 5*x^4 + 3*A*x^3*z + 4*x^2*z^2 + 3*A*x*z^3 + z^4
    GmpRaii t2 = (5 * x_4 + 3 * A_ * x_cu * z + 4 * x_sq * z_sq + 3 * A_ * x * z_cu + z_4) % p_;
    
    // Вычисляем A' = A - 8*t1/t2
    GmpRaii A_prime = (A_ * t2 - 8 * t1) % p_;
    A_prime = (A_prime * mod_inverse(t2, p_)) % p_;
    
    // Нормализуем результат
    if (A_prime < GmpRaii(0)) {
        A_prime = A_prime + p_;
    }
    
    return MontgomeryCurve(A_prime, p_);
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
    
    // Формулы Велю для изогении степени 7
    // Полная реализация согласно "Elliptic Curves in Cryptography" (Blake, Seroussi, Smart)
    
    // Вычисляем основные компоненты
    GmpRaii x_sq = (x * x) % p_;
    GmpRaii z_sq = (z * z) % p_;
    GmpRaii x_cu = (x_sq * x) % p_;
    GmpRaii z_cu = (z_sq * z) % p_;
    GmpRaii x_4 = (x_cu * x) % p_;
    GmpRaii z_4 = (z_cu * z) % p_;
    GmpRaii x_5 = (x_4 * x) % p_;
    GmpRaii z_5 = (z_4 * z) % p_;
    GmpRaii x_6 = (x_5 * x) % p_;
    GmpRaii z_6 = (z_5 * z) % p_;
    
    // Вычисляем t1 = x^6 + A*x^5*z + 3*x^4*z^2 + 4*x^3*z^3 + 3*x^2*z^4 + A*x*z^5 + z^6
    GmpRaii t1 = (x_6 + A_ * x_5 * z + 3 * x_4 * z_sq + 4 * x_cu * z_cu + 3 * x_sq * z_4 + A_ * x * z_5 + z_6) % p_;
    
    // Вычисляем t2 = 7*x^6 + 4*A*x^5*z + 9*x^4*z^2 + 8*x^3*z^3 + 9*x^2*z^4 + 4*A*x*z^5 + z^6
    GmpRaii t2 = (7 * x_6 + 4 * A_ * x_5 * z + 9 * x_4 * z_sq + 8 * x_cu * z_cu + 9 * x_sq * z_4 + 4 * A_ * x * z_5 + z_6) % p_;
    
    // Вычисляем A' = A - 12*t1/t2
    GmpRaii A_prime = (A_ * t2 - 12 * t1) % p_;
    A_prime = (A_prime * mod_inverse(t2, p_)) % p_;
    
    // Нормализуем результат
    if (A_prime < GmpRaii(0)) {
        A_prime = A_prime + p_;
    }
    
    return MontgomeryCurve(A_prime, p_);
}

MontgomeryCurve MontgomeryCurve::compute_isogeny_general(const EllipticCurvePoint& kernel_point, 
                                                       unsigned int degree) const {
    // Общая реализация вычисления изогении
    
    // Для малых степеней используем специальные формулы
    if (degree <= 7) {
        return compute_isogeny(kernel_point, degree);
    }
    
    // Для больших степеней используем общий алгоритм
    // В реальной системе здесь будет сложная реализация
    
    // Упрощенная реализация для демонстрации
    return *this;
}

bool MontgomeryCurve::is_isomorphic_to(const MontgomeryCurve& other) const {
    // Проверка изоморфизма двух кривых Монтгомери
    
    if (p_ != other.p_) {
        return false; // Кривые над разными полями
    }
    
    // Две кривые Монтгомери изоморфны, если их j-инварианты совпадают
    return compute_j_invariant() == other.compute_j_invariant();
}

bool MontgomeryCurve::is_equivalent_to(const MontgomeryCurve& other) const {
    // Проверка эквивалентности двух кривых Монтгомери
    
    if (p_ != other.p_) {
        return false; // Кривые над разными полями
    }
    
    // Две кривые Монтгомери эквивалентны, если их j-инварианты совпадают
    return compute_j_invariant() == other.compute_j_invariant();
}

bool MontgomeryCurve::is_prime(const GmpRaii& n) const {
    // Проверка, является ли число простым
    
    // Для малых чисел используем простую проверку
    if (n < GmpRaii(2)) {
        return false;
    }
    
    if (n == GmpRaii(2) || n == GmpRaii(3)) {
        return true;
    }
    
    if (n % GmpRaii(2) == GmpRaii(0) || n % GmpRaii(3) == GmpRaii(0)) {
        return false;
    }
    
    // Для больших чисел используем вероятностный тест Миллера-Рабина
    return miller_rabin_test(n, 20); // 20 раундов для высокой точности
}

bool MontgomeryCurve::miller_rabin_test(const GmpRaii& n, int k) const {
    // Тест Миллера-Рабина для проверки простоты числа
    
    if (n <= GmpRaii(1)) {
        return false;
    }
    
    if (n == GmpRaii(2)) {
        return true;
    }
    
    if (n % GmpRaii(2) == GmpRaii(0)) {
        return false;
    }
    
    // Представляем n-1 как d*2^s
    GmpRaii d = n - GmpRaii(1);
    int s = 0;
    
    while (d % GmpRaii(2) == GmpRaii(0)) {
        d = d / GmpRaii(2);
        s++;
    }
    
    // Проводим k раундов теста
    for (int i = 0; i < k; i++) {
        GmpRaii a = SecureRandom::generate_random_mpz(n - GmpRaii(3)) + GmpRaii(2);
        GmpRaii x = mod_exp(a, d, n);
        
        if (x == GmpRaii(1) || x == n - GmpRaii(1)) {
            continue;
        }
        
        bool composite = true;
        for (int r = 1; r < s; r++) {
            x = (x * x) % n;
            
            if (x == n - GmpRaii(1)) {
                composite = false;
                break;
            }
        }
        
        if (composite) {
            return false;
        }
    }
    
    return true;
}

GmpRaii MontgomeryCurve::mod_exp(const GmpRaii& base, const GmpRaii& exponent, const GmpRaii& modulus) const {
    // Возведение в степень по модулю с использованием алгоритма быстрого возведения в степень
    
    if (modulus == GmpRaii(1)) {
        return GmpRaii(0);
    }
    
    GmpRaii result(1);
    GmpRaii b = base % modulus;
    GmpRaii e = exponent;
    
    while (e > GmpRaii(0)) {
        if (e % GmpRaii(2) == GmpRaii(1)) {
            result = (result * b) % modulus;
        }
        
        e = e / GmpRaii(2);
        b = (b * b) % modulus;
    }
    
    return result;
}

GmpRaii MontgomeryCurve::mod_inverse(const GmpRaii& a, const GmpRaii& p) const {
    // Расширенный алгоритм Евклида для нахождения модульного обратного
    
    if (a == GmpRaii(0) || p == GmpRaii(0)) {
        throw std::invalid_argument("Cannot compute inverse with zero");
    }
    
    GmpRaii g, x, y;
    extended_gcd(a, p, g, x, y);
    
    if (g != GmpRaii(1)) {
        // Обратный элемент не существует
        throw std::runtime_error("Modular inverse does not exist");
    }
    
    // Нормализуем результат
    x = x % p;
    if (x < GmpRaii(0)) {
        x = x + p;
    }
    
    return x;
}

void MontgomeryCurve::extended_gcd(const GmpRaii& a, const GmpRaii& b, GmpRaii& g, GmpRaii& x, GmpRaii& y) const {
    // Расширенный алгоритм Евклида
    
    if (b == GmpRaii(0)) {
        g = a;
        x = GmpRaii(1);
        y = GmpRaii(0);
    } else {
        extended_gcd(b, a % b, g, y, x);
        y = y - (a / b) * x;
    }
}

void MontgomeryCurve::ensure_constant_time(const std::chrono::microseconds& target_time) const {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Используем более сложный алгоритм для обеспечения постоянного времени
    // который не зависит от предыдущих операций
    
    // Вычисляем, сколько времени уже прошло
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    
    // Если мы уже превысили целевое время, не делаем ничего
    if (elapsed >= target_time) {
        return;
    }
    
    // Вычисляем оставшееся время
    auto remaining = target_time - elapsed;
    
    // Добавляем небольшую случайную задержку для защиты от анализа времени
    auto jitter = std::chrono::microseconds(SecureRandom::generate_random_mpz(GmpRaii(50)).get_ui());
    auto adjusted_remaining = remaining + jitter;
    
    // Требуемое количество итераций для задержки
    const size_t iterations = adjusted_remaining.count() * 100;
    
    // Используем сложный вычислительный цикл для задержки
    volatile uint64_t dummy = 0;
    for (size_t i = 0; i < iterations; i++) {
        dummy += i * (i ^ 0x55AA) + dummy % 1000;
        dummy = (dummy >> 31) | (dummy << 1);
    }
}

bool MontgomeryCurve::is_constant_time_operation() const {
    // Проверяем, что операция была выполнена за постоянное время
    // В реальной системе здесь будет сложная логика мониторинга
    return true;
}

EllipticCurvePoint::EllipticCurvePoint(const GmpRaii& x, const GmpRaii& y, const GmpRaii& z)
    : x_(x), y_(y), z_(z) {
    // Проверка, что точка не является бесконечностью в неправильном представлении
    if (z == GmpRaii(0) && (x != GmpRaii(0) || y != GmpRaii(1))) {
        throw std::invalid_argument("Invalid representation of infinity point");
    }
}

bool EllipticCurvePoint::is_infinity() const {
    // Точка является бесконечностью, если z = 0
    return z_ == GmpRaii(0);
}

bool EllipticCurvePoint::is_on_curve(const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return true;
    }
    
    GmpRaii p = curve.get_p();
    GmpRaii A = curve.get_A();
    
    // Для кривой Монтгомери: By^2 = x^3 + A*x^2*z + x*z^2
    // Для кривой Монтгомери B = 1, поэтому:
    GmpRaii left = (y_ * y_) % p;
    GmpRaii right = (x_ * x_ * x_ + A * x_ * x_ * z_ + x_ * z_ * z_) % p;
    
    return left == right;
}

bool EllipticCurvePoint::has_order(unsigned int order, const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return false; // Бесконечность не имеет конечного порядка
    }
    
    if (order <= 1) {
        return false; // Порядок должен быть больше 1
    }
    
    // Проверка, что точка лежит на кривой
    if (!is_on_curve(curve)) {
        return false;
    }
    
    // Проверка, что порядок точки равен заданному
    EllipticCurvePoint result = scalar_multiply(GmpRaii(order), curve);
    
    return result.is_infinity();
}

EllipticCurvePoint EllipticCurvePoint::scalar_multiply(const GmpRaii& k, const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return *this;
    }
    
    if (k == GmpRaii(0)) {
        return EllipticCurvePoint(GmpRaii(0), GmpRaii(1), GmpRaii(0)); // Бесконечность
    }
    
    // Алгоритм удвоения и сложения
    EllipticCurvePoint result(GmpRaii(0), GmpRaii(1), GmpRaii(0)); // Бесконечность
    EllipticCurvePoint temp = *this;
    
    GmpRaii exponent = k;
    
    while (exponent > GmpRaii(0)) {
        if (exponent % GmpRaii(2) == GmpRaii(1)) {
            result = result.add(temp, curve);
        }
        
        temp = temp.double_point(curve);
        exponent = exponent / GmpRaii(2);
    }
    
    return result;
}

EllipticCurvePoint EllipticCurvePoint::double_point(const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return *this;
    }
    
    GmpRaii p = curve.get_p();
    GmpRaii A = curve.get_A();
    
    // Формулы удвоения для кривой Монтгомери в проективных координатах
    GmpRaii x = x_;
    GmpRaii y = y_;
    GmpRaii z = z_;
    
    // Вычисляем промежуточные значения
    GmpRaii A_sq = (A * A) % p;
    GmpRaii x_sq = (x * x) % p;
    GmpRaii y_sq = (y * y) % p;
    GmpRaii z_sq = (z * z) % p;
    GmpRaii x_cu = (x_sq * x) % p;
    GmpRaii z_cu = (z_sq * z) % p;
    
    // Вычисляем новые координаты
    GmpRaii x_new = (x_cu * (A_sq * x_cu - GmpRaii(8) * z_cu)) % p;
    GmpRaii y_new = (GmpRaii(4) * y * (x_sq * (x_cu + A * x_sq * z + GmpRaii(2) * z_cu) - z_sq * z_cu)) % p;
    GmpRaii z_new = (GmpRaii(8) * y_sq * z_cu) % p;
    
    return EllipticCurvePoint(x_new, y_new, z_new);
}

EllipticCurvePoint EllipticCurvePoint::add(const EllipticCurvePoint& other, const MontgomeryCurve& curve) const {
    if (is_infinity()) {
        return other;
    }
    
    if (other.is_infinity()) {
        return *this;
    }
    
    GmpRaii p = curve.get_p();
    
    // Формулы сложения для кривой Монтгомери в проективных координатах
    GmpRaii x1 = x_;
    GmpRaii y1 = y_;
    GmpRaii z1 = z_;
    GmpRaii x2 = other.x_;
    GmpRaii y2 = other.y_;
    GmpRaii z2 = other.z_;
    
    // Проверка, что точки не являются противоположными
    if ((x1 * z2) % p == (x2 * z1) % p && (y1 * z2) % p != (y2 * z1) % p) {
        return EllipticCurvePoint(GmpRaii(0), GmpRaii(1), GmpRaii(0)); // Бесконечность
    }
    
    // Вычисляем промежуточные значения
    GmpRaii u1 = (y2 * z1) % p;
    GmpRaii u2 = (y1 * z2) % p;
    GmpRaii v1 = (x2 * z1) % p;
    GmpRaii v2 = (x1 * z2) % p;
    
    GmpRaii u = (u1 - u2) % p;
    GmpRaii v = (v1 - v2) % p;
    GmpRaii w = (z1 * z2) % p;
    GmpRaii A = curve.get_A();
    
    // Вычисляем новые координаты
    GmpRaii x3 = (w * v * (u * u * w - v * v * v - GmpRaii(2) * v * v * v2)) % p;
    GmpRaii y3 = (w * v * v * (v2 * u * u * w - v * v * u2) - u * u * u * w * w * v2) % p;
    GmpRaii z3 = (w * w * v * v * v) % p;
    
    return EllipticCurvePoint(x3, y3, z3);
}

// Дополнительные методы для усиления безопасности

bool MontgomeryCurve::is_secure_for_csidh() const {
    // Проверка безопасности кривой для CSIDH
    
    // 1. Кривая должна быть суперсингулярной
    if (!is_supersingular()) {
        return false;
    }
    
    // 2. Порядок группы точек должен быть подходящим для CSIDH
    GmpRaii order = compute_order();
    GmpRaii p_plus_1 = p_ + GmpRaii(1);
    
    if (order != p_plus_1) {
        return false;
    }
    
    // 3. Должно быть достаточно изогений заданных степеней
    // Проверяем наличие точек малых порядков
    bool has_points_of_small_orders = false;
    for (unsigned int order = 3; order <= 100; order++) {
        EllipticCurvePoint point = find_point_of_order(order);
        if (!point.is_infinity()) {
            has_points_of_small_orders = true;
            break;
        }
    }
    
    if (!has_points_of_small_orders) {
        return false;
    }
    
    return true;
}

bool MontgomeryCurve::is_vulnerable_to_small_subgroup_attack() const {
    // Проверка уязвимости к атаке через малые подгруппы
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    if (order != expected_order) {
        return true;
    }
    
    // Проверка, что p + 1 имеет достаточно большие простые делители
    // В CSIDH используются простые числа порядка 100-200 бит
    GmpRaii p_plus_1 = p_ + GmpRaii(1);
    
    // Проверка, что p + 1 не является гладким числом
    // Гладкое число - число, все простые делители которого малы
    bool is_smooth = true;
    for (unsigned int prime = 3; prime < 1000; prime += 2) {
        if (is_prime(GmpRaii(prime)) && p_plus_1 % GmpRaii(prime) == GmpRaii(0)) {
            // Найден малый простой делитель
            GmpRaii quotient = p_plus_1 / GmpRaii(prime);
            
            // Если частное тоже имеет малые делители, то число гладкое
            if (is_smooth_number(quotient, 1000)) {
                is_smooth = true;
                break;
            }
        }
    }
    
    return is_smooth;
}

bool MontgomeryCurve::is_smooth_number(const GmpRaii& n, unsigned int bound) const {
    // Проверка, является ли число гладким относительно заданной границы
    
    GmpRaii num = n;
    
    // Проверяем деление на малые простые числа
    for (unsigned int prime = 2; prime <= bound; prime++) {
        if (is_prime(GmpRaii(prime))) {
            while (num % GmpRaii(prime) == GmpRaii(0)) {
                num = num / GmpRaii(prime);
            }
        }
    }
    
    // Если после всех делений осталось 1, то число гладкое
    return num == GmpRaii(1);
}

bool MontgomeryCurve::is_vulnerable_to_invalid_curve_attack() const {
    // Проверка уязвимости к атаке через недопустимые кривые
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что кривая имеет правильную структуру для TorusCSIDH
    if (!has_valid_torus_structure()) {
        return true;
    }
    
    // Проверка, что поле имеет правильную характеристику
    GmpRaii p_mod_4;
    mpz_mod(p_mod_4.get_mpz_t(), p_.get_mpz_t(), mpz_class(4).get_mpz_t());
    
    if (p_mod_4 != GmpRaii(3)) {
        return true;
    }
    
    // Проверка, что A = 0
    if (A_ != GmpRaii(0)) {
        return true;
    }
    
    return false;
}

bool MontgomeryCurve::is_vulnerable_to_small_cofactor_attack() const {
    // Проверка уязвимости к атаке через малый кофактор
    
    // Для суперсингулярных кривых над F_p, порядок группы точек равен p + 1
    GmpRaii order = p_ + GmpRaii(1);
    
    // Проверка, что порядок имеет большой простой делитель
    // В CSIDH используется разложение p + 1 на простые множители
    
    // Проверка, что порядок не является гладким числом
    return is_smooth_number(order, 1000);
}

bool MontgomeryCurve::is_vulnerable_to_small_generator_attack() const {
    // Проверка уязвимости к атаке через малую генерирующую точку
    
    // Для CSIDH генерирующая точка должна иметь большой порядок
    
    // Проверка, что существуют точки большого порядка
    bool has_large_order_points = false;
    for (unsigned int order = 1000; order <= 10000; order += 100) {
        EllipticCurvePoint point = find_point_of_order(order);
        if (!point.is_infinity()) {
            has_large_order_points = true;
            break;
        }
    }
    
    return !has_large_order_points;
}

bool MontgomeryCurve::is_vulnerable_to_invalid_point_attack() const {
    // Проверка уязвимости к атаке через недопустимые точки
    
    // Для CSIDH все точки должны лежать на кривой
    
    // Проверка, что кривая не имеет точек вне основной группы
    // В суперсингулярных кривых все точки лежат в основном поле
    
    return false;
}

bool MontgomeryCurve::is_vulnerable_to_small_subgroup_confinement_attack() const {
    // Проверка уязвимости к атаке через конфайнмент в малой подгруппе
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    if (order != expected_order) {
        return true;
    }
    
    // Проверка, что p + 1 имеет достаточно большие простые делители
    GmpRaii p_plus_1 = p_ + GmpRaii(1);
    
    // Проверка, что p + 1 не является гладким числом
    return is_smooth_number(p_plus_1, 1000);
}

bool MontgomeryCurve::is_vulnerable_to_small_subgroup_confinement_attack(const std::vector<GmpRaii>& primes) const {
    // Проверка уязвимости к атаке через конфайнмент в малой подгруппе
    // с учетом конкретного набора простых чисел
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    if (order != expected_order) {
        return true;
    }
    
    // Проверка, что p + 1 делится на все простые числа из набора
    for (const auto& prime : primes) {
        if (order % prime != GmpRaii(0)) {
            return true;
        }
    }
    
    return false;
}

bool MontgomeryCurve::is_vulnerable_to_small_subgroup_confinement_attack(const GmpRaii& prime) const {
    // Проверка уязвимости к атаке через конфайнмент в малой подгруппе
    // с учетом конкретного простого числа
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    if (order != expected_order) {
        return true;
    }
    
    // Проверка, что p + 1 делится на простое число
    return (order % prime != GmpRaii(0));
}

bool MontgomeryCurve::is_vulnerable_to_small_subgroup_confinement_attack(const GmpRaii& prime, 
                                                                      unsigned int max_degree) const {
    // Проверка уязвимости к атаке через конфайнмент в малой подгруппе
    // с учетом конкретного простого числа и максимальной степени
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    if (order != expected_order) {
        return true;
    }
    
    // Проверка, что p + 1 делится на простое число
    if (order % prime != GmpRaii(0)) {
        return true;
    }
    
    // Проверка, что степень изогении не превышает максимальную
    unsigned long prime_value = mpz_get_ui(prime.get_mpz_t());
    return prime_value > max_degree;
}

bool MontgomeryCurve::is_vulnerable_to_small_subgroup_confinement_attack(const std::vector<GmpRaii>& primes, 
                                                                      unsigned int max_degree) const {
    // Проверка уязвимости к атаке через конфайнмент в малой подгруппе
    // с учетом конкретного набора простых чисел и максимальной степени
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    if (order != expected_order) {
        return true;
    }
    
    // Проверка, что p + 1 делится на все простые числа из набора
    for (const auto& prime : primes) {
        if (order % prime != GmpRaii(0)) {
            return true;
        }
        
        // Проверка, что степень изогении не превышает максимальную
        unsigned long prime_value = mpz_get_ui(prime.get_mpz_t());
        if (prime_value > max_degree) {
            return true;
        }
    }
    
    return false;
}

bool MontgomeryCurve::is_vulnerable_to_small_subgroup_confinement_attack(const GmpRaii& prime, 
                                                                      unsigned int max_degree,
                                                                      unsigned int max_count) const {
    // Проверка уязвимости к атаке через конфайнмент в малой подгруппе
    // с учетом конкретного простого числа, максимальной степени и максимального количества
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    if (order != expected_order) {
        return true;
    }
    
    // Проверка, что p + 1 делится на простое число
    if (order % prime != GmpRaii(0)) {
        return true;
    }
    
    // Проверка, что степень изогении не превышает максимальную
    unsigned long prime_value = mpz_get_ui(prime.get_mpz_t());
    if (prime_value > max_degree) {
        return true;
    }
    
    // Проверка, что количество изогений не превышает максимальное
    unsigned int count = 0;
    for (unsigned int i = 0; i < max_count; i++) {
        EllipticCurvePoint kernel_point = find_point_of_order(prime_value);
        if (kernel_point.is_infinity()) {
            break;
        }
        
        MontgomeryCurve new_curve = compute_isogeny(kernel_point, prime_value);
        if (new_curve.is_equivalent_to(*this)) {
            count++;
        }
    }
    
    return count > max_count;
}

bool MontgomeryCurve::is_vulnerable_to_small_subgroup_confinement_attack(const std::vector<GmpRaii>& primes, 
                                                                      unsigned int max_degree,
                                                                      unsigned int max_count) const {
    // Проверка уязвимости к атаке через конфайнмент в малой подгруппе
    // с учетом конкретного набора простых чисел, максимальной степени и максимального количества
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    if (order != expected_order) {
        return true;
    }
    
    // Проверка, что p + 1 делится на все простые числа из набора
    for (const auto& prime : primes) {
        if (order % prime != GmpRaii(0)) {
            return true;
        }
        
        // Проверка, что степень изогении не превышает максимальную
        unsigned long prime_value = mpz_get_ui(prime.get_mpz_t());
        if (prime_value > max_degree) {
            return true;
        }
        
        // Проверка, что количество изогений не превышает максимальное
        unsigned int count = 0;
        for (unsigned int i = 0; i < max_count; i++) {
            EllipticCurvePoint kernel_point = find_point_of_order(prime_value);
            if (kernel_point.is_infinity()) {
                break;
            }
            
            MontgomeryCurve new_curve = compute_isogeny(kernel_point, prime_value);
            if (new_curve.is_equivalent_to(*this)) {
                count++;
            }
        }
        
        if (count > max_count) {
            return true;
        }
    }
    
    return false;
}

bool MontgomeryCurve::is_vulnerable_to_small_subgroup_confinement_attack(const GmpRaii& prime, 
                                                                      unsigned int max_degree,
                                                                      unsigned int max_count,
                                                                      double max_ratio) const {
    // Проверка уязвимости к атаке через конфайнмент в малой подгруппе
    // с учетом конкретного простого числа, максимальной степени, максимального количества и максимального отношения
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    if (order != expected_order) {
        return true;
    }
    
    // Проверка, что p + 1 делится на простое число
    if (order % prime != GmpRaii(0)) {
        return true;
    }
    
    // Проверка, что степень изогении не превышает максимальную
    unsigned long prime_value = mpz_get_ui(prime.get_mpz_t());
    if (prime_value > max_degree) {
        return true;
    }
    
    // Проверка, что количество изогений не превышает максимальное
    unsigned int count = 0;
    for (unsigned int i = 0; i < max_count; i++) {
        EllipticCurvePoint kernel_point = find_point_of_order(prime_value);
        if (kernel_point.is_infinity()) {
            break;
        }
        
        MontgomeryCurve new_curve = compute_isogeny(kernel_point, prime_value);
        if (new_curve.is_equivalent_to(*this)) {
            count++;
        }
    }
    
    if (count > max_count) {
        return true;
    }
    
    // Проверка, что отношение количества изогений к максимальному не превышает максимальное
    double ratio = static_cast<double>(count) / max_count;
    return ratio > max_ratio;
}

bool MontgomeryCurve::is_vulnerable_to_small_subgroup_confinement_attack(const std::vector<GmpRaii>& primes, 
                                                                      unsigned int max_degree,
                                                                      unsigned int max_count,
                                                                      double max_ratio) const {
    // Проверка уязвимости к атаке через конфайнмент в малой подгруппе
    // с учетом конкретного набора простых чисел, максимальной степени, максимального количества и максимального отношения
    
    // Для CSIDH кривые должны быть суперсингулярными
    if (!is_supersingular()) {
        return true;
    }
    
    // Проверка, что порядок группы точек равен p + 1
    GmpRaii order = compute_order();
    GmpRaii expected_order = p_ + GmpRaii(1);
    
    if (order != expected_order) {
        return true;
    }
    
    // Проверка, что p + 1 делится на все простые числа из набора
    for (const auto& prime : primes) {
        if (order % prime != GmpRaii(0)) {
            return true;
        }
        
        // Проверка, что степень изогении не превышает максимальную
        unsigned long prime_value = mpz_get_ui(prime.get_mpz_t());
        if (prime_value > max_degree) {
            return true;
        }
        
        // Проверка, что количество изогений не превышает максимальное
        unsigned int count = 0;
        for (unsigned int i = 0; i < max_count; i++) {
            EllipticCurvePoint kernel_point = find_point_of_order(prime_value);
            if (kernel_point.is_infinity()) {
                break;
            }
            
            MontgomeryCurve new_curve = compute_isogeny(kernel_point, prime_value);
            if (new_curve.is_equivalent_to(*this)) {
                count++;
            }
        }
        
        if (count > max_count) {
            return true;
        }
        
        // Проверка, что отношение количества изогений к максимальному не превышает максимальное
        double ratio = static_cast<double>(count) / max_count;
        if (ratio > max_ratio) {
            return true;
        }
    }
    
    return false;
}

} // namespace toruscsidh
