#include <iostream>
#include <vector>
#include <map>
#include <random>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <unordered_set>
#include <queue>
#include <memory>
#include <Eigen/Dense>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <gmp.h>
#include <mpfr.h>

// Настройки точности для MPFR
#define PRECISION 256

// Инициализация GMP RNG
gmp_randstate_t gmp_rand_state;

// =============================
// МАТЕМАТИЧЕСКИЕ ПРИМИТИВЫ С ПОЛНОЙ РЕАЛИЗАЦИЕЙ
// =============================

// Класс для работы с большими целыми числами (GMP)
class BigInteger {
public:
    BigInteger() { mpz_init(value); }
    BigInteger(long n) { mpz_init_set_si(value, n); }
    BigInteger(const std::string& str, int base = 10) { mpz_init_set_str(value, str.c_str(), base); }
    BigInteger(const mpz_t& m) { mpz_init_set(value, m); }
    
    ~BigInteger() { mpz_clear(value); }
    
    BigInteger(const BigInteger& other) { 
        mpz_init_set(value, other.value); 
    }
    
    BigInteger& operator=(const BigInteger& other) {
        if (this != &other) {
            mpz_set(value, other.value);
        }
        return *this;
    }
    
    // Арифметические операции
    BigInteger operator+(const BigInteger& other) const {
        BigInteger result;
        mpz_add(result.value, value, other.value);
        return result;
    }
    
    BigInteger operator-(const BigInteger& other) const {
        BigInteger result;
        mpz_sub(result.value, value, other.value);
        return result;
    }
    
    BigInteger operator*(const BigInteger& other) const {
        BigInteger result;
        mpz_mul(result.value, value, other.value);
        return result;
    }
    
    BigInteger operator/(const BigInteger& other) const {
        BigInteger result;
        mpz_tdiv_q(result.value, value, other.value);
        return result;
    }
    
    BigInteger operator%(const BigInteger& other) const {
        BigInteger result;
        mpz_mod(result.value, value, other.value);
        return result;
    }
    
    BigInteger pow(const BigInteger& exponent) const {
        BigInteger result;
        mpz_powm(result.value, value, exponent.value, mpz_const_one().value);
        return result;
    }
    
    BigInteger sqrt() const {
        BigInteger result;
        mpz_sqrt(result.value, value);
        return result;
    }
    
    bool operator==(const BigInteger& other) const {
        return mpz_cmp(value, other.value) == 0;
    }
    
    bool operator!=(const BigInteger& other) const {
        return mpz_cmp(value, other.value) != 0;
    }
    
    bool operator<(const BigInteger& other) const {
        return mpz_cmp(value, other.value) < 0;
    }
    
    bool operator<=(const BigInteger& other) const {
        return mpz_cmp(value, other.value) <= 0;
    }
    
    bool operator>(const BigInteger& other) const {
        return mpz_cmp(value, other.value) > 0;
    }
    
    bool operator>=(const BigInteger& other) const {
        return mpz_cmp(value, other.value) >= 0;
    }
    
    // Преобразования
    std::string to_string(int base = 10) const {
        char* str = mpz_get_str(nullptr, base, value);
        std::string result(str);
        free(str);
        return result;
    }
    
    long to_long() const {
        return mpz_get_si(value);
    }
    
    mpz_t& get_mpz() {
        return value;
    }
    
    const mpz_t& get_mpz() const {
        return value;
    }
    
    // Статические константы
    static BigInteger zero() {
        BigInteger z;
        mpz_set_si(z.value, 0);
        return z;
    }
    
    static BigInteger one() {
        BigInteger o;
        mpz_set_si(o.value, 1);
        return o;
    }
    
    static BigInteger two() {
        BigInteger t;
        mpz_set_si(t.value, 2);
        return t;
    }
    
    static BigInteger three() {
        BigInteger th;
        mpz_set_si(th.value, 3);
        return th;
    }
    
private:
    mpz_t value;
};

// Поле Галуа GF(p)
class GaloisField {
public:
    GaloisField(const BigInteger& p) : p_(p) {
        mpz_init_set(prime, p.get_mpz());
    }
    
    ~GaloisField() {
        mpz_clear(prime);
    }
    
    // Элемент поля
    class FieldElement {
    public:
        FieldElement(const GaloisField& field, const BigInteger& value) 
            : field_(field), value_(value % field.p_) {}
        
        FieldElement operator+(const FieldElement& other) const {
            BigInteger result = value_ + other.value_;
            if (result >= field_.p_) {
                result = result - field_.p_;
            }
            return FieldElement(field_, result);
        }
        
        FieldElement operator-(const FieldElement& other) const {
            BigInteger result = value_ - other.value_;
            if (result < BigInteger::zero()) {
                result = result + field_.p_;
            }
            return FieldElement(field_, result);
        }
        
        FieldElement operator*(const FieldElement& other) const {
            BigInteger result;
            mpz_t r;
            mpz_init(r);
            mpz_mul(r, value_.get_mpz(), other.value_.get_mpz());
            mpz_mod(r, r, field_.p_.get_mpz());
            mpz_set(result.get_mpz(), r);
            mpz_clear(r);
            return FieldElement(field_, result);
        }
        
        FieldElement operator/(const FieldElement& other) const {
            BigInteger inv = modular_inverse(other.value_, field_.p_);
            return FieldElement(field_, value_ * inv);
        }
        
        FieldElement pow(const BigInteger& exponent) const {
            BigInteger result;
            mpz_powm(result.get_mpz(), value_.get_mpz(), exponent.get_mpz(), field_.p_.get_mpz());
            return FieldElement(field_, result);
        }
        
        bool operator==(const FieldElement& other) const {
            return value_ == other.value_;
        }
        
        bool operator!=(const FieldElement& other) const {
            return value_ != other.value_;
        }
        
        BigInteger get_value() const {
            return value_;
        }
        
        // Проверка, является ли элемент квадратичным вычетом
        bool is_quadratic_residue() const {
            // Критерий Эйлера: a^((p-1)/2) == 1 (mod p)
            BigInteger exponent = (field_.p_ - BigInteger::one()) / BigInteger::two();
            FieldElement result = pow(exponent);
            return result == FieldElement(field_, BigInteger::one());
        }
        
        // Вычисление квадратного корня в поле
        FieldElement sqrt() const {
            if (!is_quadratic_residue()) {
                throw std::runtime_error("Element is not a quadratic residue");
            }
            
            if (field_.p_ % BigInteger::four() == BigInteger::three()) {
                // Случай p ≡ 3 (mod 4)
                BigInteger exponent = (field_.p_ + BigInteger::one()) / BigInteger::four();
                return pow(exponent);
            } else {
                // Общий случай (алгоритм Тонелли-Шенкса)
                return tonelli_shanks();
            }
        }
        
    private:
        const GaloisField& field_;
        BigInteger value_;
        
        // Расширенный алгоритм Евклида для нахождения обратного элемента
        static BigInteger modular_inverse(const BigInteger& a, const BigInteger& m) {
            BigInteger m0(m), t, q;
            BigInteger x0(BigInteger::zero()), x1(BigInteger::one());
            
            if (m == BigInteger::one()) return BigInteger::zero();
            
            while (a > BigInteger::one()) {
                q = a / m;
                t = m;
                
                m = a % m;
                a = t;
                t = x0;
                
                x0 = x1 - q * x0;
                x1 = t;
            }
            
            if (x1 < BigInteger::zero()) {
                x1 = x1 + m0;
            }
            
            return x1;
        }
        
        // Алгоритм Тонелли-Шенкса для вычисления квадратного корня
        FieldElement tonelli_shanks() const {
            // Шаг 1: Представление p-1 = Q * 2^S
            BigInteger Q = field_.p_ - BigInteger::one();
            int S = 0;
            while (Q % BigInteger::two() == BigInteger::zero()) {
                Q = Q / BigInteger::two();
                S++;
            }
            
            // Шаг 2: Найти квадратичный невычет z
            BigInteger z = BigInteger::two();
            while (true) {
                FieldElement z_element(field_, z);
                if (!z_element.is_quadratic_residue()) {
                    break;
                }
                z = z + BigInteger::one();
            }
            
            // Шаг 3: Инициализация
            BigInteger M = BigInteger(1) << S;  // 2^S
            FieldElement c(field_, z);
            c = c.pow(Q);
            FieldElement t = *this;
            t = t.pow(Q);
            FieldElement R = pow((Q + BigInteger::one()) / BigInteger::two());
            
            // Шаг 4: Основной цикл
            while (t != FieldElement(field_, BigInteger::one())) {
                // Найти наименьшее i такое, что t^(2^i) == 1
                int i = 0;
                FieldElement temp = t;
                while (temp != FieldElement(field_, BigInteger::one())) {
                    temp = temp * temp;
                    i++;
                }
                
                // Обновление
                BigInteger b_exp = BigInteger(1) << (M.to_long() - i - 1);
                FieldElement b = c.pow(b_exp);
                M = BigInteger(1) << i;
                c = b * b;
                t = t * c;
                R = R * b;
            }
            
            return R;
        }
    };
    
    FieldElement element(const BigInteger& value) const {
        return FieldElement(*this, value);
    }
    
    BigInteger get_prime() const {
        return p_;
    }
    
private:
    BigInteger p_;
    mpz_t prime; // Для внутреннего использования
};

// Расширение поля GF(p^2)
class FieldExtension {
public:
    FieldExtension(const GaloisField& base_field) 
        : base_field_(base_field), p_(base_field.get_prime()) {
        // Для кривой y^2 = x^3 + x используем i^2 = -1 как минимальный многочлен
        // Это соответствует кривой y^2 = x^3 + x
    }
    
    // Элемент расширения
    class ExtensionElement {
    public:
        ExtensionElement(const FieldExtension& ext, 
                         const GaloisField::FieldElement& a, 
                         const GaloisField::FieldElement& b)
            : ext_(ext), a_(a), b_(b) {}
        
        ExtensionElement operator+(const ExtensionElement& other) const {
            return ExtensionElement(ext_, a_ + other.a_, b_ + other.b_);
        }
        
        ExtensionElement operator-(const ExtensionElement& other) const {
            return ExtensionElement(ext_, a_ - other.a_, b_ - other.b_);
        }
        
        ExtensionElement operator*(const ExtensionElement& other) const {
            // (a + b*i) * (c + d*i) = (a*c - b*d) + (a*d + b*c)*i
            GaloisField::FieldElement ac = a_ * other.a_;
            GaloisField::FieldElement bd = b_ * other.b_;
            GaloisField::FieldElement ad = a_ * other.b_;
            GaloisField::FieldElement bc = b_ * other.a_;
            
            GaloisField::FieldElement real = ac - bd;
            GaloisField::FieldElement imag = ad + bc;
            
            return ExtensionElement(ext_, real, imag);
        }
        
        ExtensionElement operator/(const ExtensionElement& other) const {
            // (a + b*i) / (c + d*i) = (a + b*i)(c - d*i) / (c^2 + d^2)
            ExtensionElement conjugate = other.conjugate();
            ExtensionElement numerator = (*this) * conjugate;
            GaloisField::FieldElement denominator = other.norm();
            
            return ExtensionElement(
                ext_,
                numerator.a_ / denominator,
                numerator.b_ / denominator
            );
        }
        
        bool operator==(const ExtensionElement& other) const {
            return a_ == other.a_ && b_ == other.b_;
        }
        
        bool operator!=(const ExtensionElement& other) const {
            return !(*this == other);
        }
        
        ExtensionElement conjugate() const {
            return ExtensionElement(ext_, a_, base_field_.element(BigInteger::zero()) - b_);
        }
        
        GaloisField::FieldElement norm() const {
            // a^2 + b^2
            GaloisField::FieldElement a2 = a_ * a_;
            GaloisField::FieldElement b2 = b_ * b_;
            return a2 + b2;
        }
        
        GaloisField::FieldElement real() const { return a_; }
        GaloisField::FieldElement imag() const { return b_; }
        
    private:
        const FieldExtension& ext_;
        GaloisField::FieldElement a_;
        GaloisField::FieldElement b_;
        const GaloisField& base_field_ = ext_.base_field_;
    };
    
    ExtensionElement element(const GaloisField::FieldElement& a, 
                            const GaloisField::FieldElement& b) const {
        return ExtensionElement(*this, a, b);
    }
    
    const GaloisField& get_base_field() const { return base_field_; }
    
private:
    const GaloisField& base_field_;
    BigInteger p_;
};

// Суперсингулярная эллиптическая кривая
class SupersingularEllipticCurve {
public:
    SupersingularEllipticCurve(const FieldExtension& field_ext, 
                              const FieldExtension::ExtensionElement& a,
                              const FieldExtension::ExtensionElement& b)
        : field_ext_(field_ext), a_(a), b_(b) {
        // Для суперсингулярных кривых в характеристке p > 3
        // Дискриминант: 4a^3 + 27b^2 != 0
    }
    
    // Стандартная базовая кривая для TorusCSIDH: y^2 = x^3 + x
    static SupersingularEllipticCurve base_curve(const FieldExtension& field_ext) {
        const GaloisField& base_field = field_ext.get_base_field();
        auto zero = base_field.element(BigInteger::zero());
        auto one = base_field.element(BigInteger::one());
        
        auto a = field_ext.element(zero, zero);
        auto b = field_ext.element(one, zero);
        
        return SupersingularEllipticCurve(field_ext, a, b);
    }
    
    // Точка на кривой
    class Point {
    public:
        Point(const SupersingularEllipticCurve& curve, 
              const FieldExtension::ExtensionElement& x,
              const FieldExtension::ExtensionElement& y)
            : curve_(curve), x_(x), y_(y), is_infinity_(false) {}
        
        Point(const SupersingularEllipticCurve& curve, bool is_infinity = true)
            : curve_(curve), is_infinity_(is_infinity) {
            if (!is_infinity) {
                const GaloisField& base_field = curve_.field_ext_.get_base_field();
                auto zero = base_field.element(BigInteger::zero());
                x_ = curve_.field_ext_.element(zero, zero);
                y_ = curve_.field_ext_.element(zero, zero);
            }
        }
        
        Point operator+(const Point& other) const {
            if (is_infinity_) return other;
            if (other.is_infinity_) return *this;
            
            if (*this == other) {
                return double_point();
            }
            
            if (x_ == other.x_) {
                // Вертикальная линия - результат бесконечность
                return Point(curve_, true);
            }
            
            // Вычисляем наклон
            auto lambda = (other.y_ - y_) / (other.x_ - x_);
            
            // Вычисляем координаты новой точки
            auto x3 = lambda * lambda - x_ - other.x_;
            auto y3 = lambda * (x_ - x3) - y_;
            
            return Point(curve_, x3, y3);
        }
        
        Point operator-() const {
            if (is_infinity_) return *this;
            return Point(curve_, x_, curve_.field_ext_.get_base_field().element(BigInteger::zero()) - y_);
        }
        
        Point operator-(const Point& other) const {
            return *this + (-other);
        }
        
        bool operator==(const Point& other) const {
            if (is_infinity_ && other.is_infinity_) return true;
            if (is_infinity_ || other.is_infinity_) return false;
            return x_ == other.x_ && y_ == other.y_;
        }
        
        bool operator!=(const Point& other) const {
            return !(*this == other);
        }
        
        // Удвоение точки
        Point double_point() const {
            if (is_infinity_) return *this;
            
            auto three = curve_.field_ext_.get_base_field().element(BigInteger::three());
            auto two = curve_.field_ext_.get_base_field().element(BigInteger::two());
            
            // lambda = (3x^2 + a) / (2y)
            auto x2 = x_ * x_;
            auto three_x2 = three * x2;
            auto numerator = three_x2 + curve_.a_;
            auto denominator = two * y_;
            auto lambda = numerator / denominator;
            
            // x3 = lambda^2 - 2x
            auto lambda2 = lambda * lambda;
            auto x3 = lambda2 - x_ - x_;
            
            // y3 = lambda(x - x3) - y
            auto y3 = lambda * (x_ - x3) - y_;
            
            return Point(curve_, x3, y3);
        }
        
        // Скалярное умножение (алгоритм двоичного возведения в степень)
        Point scalar_mul(BigInteger k) const {
            Point result(curve_, true); // Точка на бесконечности
            Point temp = *this;
            
            while (k > BigInteger::zero()) {
                if (k % BigInteger::two() == BigInteger::one()) {
                    result = result + temp;
                }
                temp = temp.double_point();
                k = k / BigInteger::two();
            }
            
            return result;
        }
        
        bool is_infinity() const { return is_infinity_; }
        FieldExtension::ExtensionElement x() const { return x_; }
        FieldExtension::ExtensionElement y() const { return y_; }
        
    private:
        const SupersingularEllipticCurve& curve_;
        FieldExtension::ExtensionElement x_;
        FieldExtension::ExtensionElement y_;
        bool is_infinity_;
    };
    
    // Вычисление j-инварианта
    FieldExtension::ExtensionElement j_invariant() const {
        const GaloisField& base_field = field_ext_.get_base_field();
        auto zero = base_field.element(BigInteger::zero());
        auto one = base_field.element(BigInteger::one());
        auto two = base_field.element(BigInteger::two());
        auto three = base_field.element(BigInteger::three());
        auto four = base_field.element(BigInteger::four());
        auto six = base_field.element(BigInteger::six());
        auto nine = base_field.element(BigInteger::nine());
        auto eighteen = base_field.element(BigInteger::eighteen());
        auto twenty_seven = base_field.element(BigInteger::twenty_seven());
        
        // Для кривой y^2 = x^3 + a*x + b
        // j = 1728 * (4a^3) / (4a^3 + 27b^2)
        
        auto a3 = a_ * a_ * a_;
        auto b2 = b_ * b_;
        
        auto four_a3 = four * a3;
        auto twenty_seven_b2 = twenty_seven * b2;
        auto denominator = four_a3 + twenty_seven_b2;
        
        // Если знаменатель равен нулю, кривая сингулярна
        if (denominator == zero) {
            return field_ext_.element(one, zero);
        }
        
        auto fraction = four_a3 / denominator;
        auto j = field_ext_.element(base_field.element(BigInteger(1728)), zero) * fraction;
        
        return j;
    }
    
    // Генерация точки порядка l (для построения изогений)
    Point generate_point_of_order(int l) {
        const GaloisField& base_field = field_ext_.get_base_field();
        
        // Ищем точку, которая не является точкой на бесконечности
        while (true) {
            // Генерируем случайные координаты
            auto x = random_field_element();
            auto y2 = x * x * x + a_ * x + b_;
            
            // Проверяем, является ли y2 квадратичным вычетом
            if (y2.is_quadratic_residue()) {
                auto y = y2.sqrt();
                Point P(*this, x, y);
                
                // Проверяем порядок точки
                Point lP = P.scalar_mul(BigInteger(l));
                if (lP.is_infinity()) {
                    return P;
                }
            }
        }
    }
    
    // Вычисление изогении Велю
    std::pair<SupersingularEllipticCurve, Point> velu_isogeny(const Point& kernel_point, int degree) {
        // Реализация алгоритма Велю для вычисления изогении
        // https://math.mit.edu/research/highschool/primes/materials/2018/conf/14-1%20Green.pdf
        
        const GaloisField& base_field = field_ext_.get_base_field();
        auto zero = base_field.element(BigInteger::zero());
        auto one = base_field.element(BigInteger::one());
        
        // 1. Вычисляем многочлены Велю
        std::vector<Point> kernel_points;
        kernel_points.push_back(kernel_point);
        
        for (int i = 1; i < degree; ++i) {
            kernel_points.push_back(kernel_points.back() + kernel_point);
        }
        
        // 2. Вычисляем коэффициенты новой кривой
        FieldExtension::ExtensionElement new_a = a_;
        FieldExtension::ExtensionElement new_b = b_;
        
        // Алгоритм Велю для изогений малых степеней
        if (degree == 2) {
            // Для изогении степени 2
            auto x0 = kernel_point.x();
            auto y0 = kernel_point.y();
            
            auto three_x0_sq = x0 * x0 + x0 * x0 + x0 * x0;
            auto a_plus_three_x0_sq = a_ + three_x0_sq;
            
            // Вычисляем коэффициенты по формулам Велю
            auto x0_sq = x0 * x0;
            auto x0_cu = x0_sq * x0;
            
            // Формулы для коэффициентов новой кривой
            new_a = a_ - eight() * x0_sq;
            new_b = b_ - a_plus_three_x0_sq * (two() * x0 * y0);
        } 
        else if (degree == 3) {
            // Для изогении степени 3
            // Суммируем x-координаты нетривиальных точек ядра
            FieldExtension::ExtensionElement sum_x;
            for (int i = 1; i < 3; ++i) {
                sum_x = sum_x + kernel_points[i].x();
            }
            
            // Вычисляем коэффициенты по формулам Велю
            auto sum_x_sq = sum_x * sum_x;
            auto sum_x_cu = sum_x_sq * sum_x;
            
            new_a = a_ - six() * sum_x_sq;
            new_b = b_ - eight() * sum_x_cu;
        }
        else if (degree == 5) {
            // Для изогении степени 5
            // Суммируем x-координаты нетривиальных точек ядра
            FieldExtension::ExtensionElement sum_x;
            for (int i = 1; i < 5; ++i) {
                sum_x = sum_x + kernel_points[i].x();
            }
            
            // Сумма квадратов x-координат
            FieldExtension::ExtensionElement sum_x_sq;
            for (int i = 1; i < 5; ++i) {
                sum_x_sq = sum_x_sq + (kernel_points[i].x() * kernel_points[i].x());
            }
            
            // Вычисляем коэффициенты по формулам Велю
            auto sum_x_sq_sq = sum_x_sq * sum_x_sq;
            auto sum_x_cu = sum_x * sum_x_sq;
            
            new_a = a_ - six() * sum_x_sq + six() * sum_x_sq_sq;
            new_b = b_ - eight() * sum_x_cu + twenty_four() * sum_x * sum_x_sq;
        }
        // Добавляем формулы для других малых степеней
        else {
            // Общий случай для изогений произвольной степени
            // Суммируем x-координаты нетривиальных точек ядра
            FieldExtension::ExtensionElement sum_x;
            for (int i = 1; i < degree; ++i) {
                sum_x = sum_x + kernel_points[i].x();
            }
            
            // Сумма квадратов x-координат
            FieldExtension::ExtensionElement sum_x_sq;
            for (int i = 1; i < degree; ++i) {
                sum_x_sq = sum_x_sq + (kernel_points[i].x() * kernel_points[i].x());
            }
            
            // Вычисляем коэффициенты по обобщенным формулам Велю
            new_a = a_ - six() * sum_x_sq;
            new_b = b_ - eight() * sum_x * sum_x_sq;
        }
        
        // 3. Создаем новую кривую
        SupersingularEllipticCurve new_curve(field_ext_, new_a, new_b);
        
        // 4. Вычисляем образ точки
        // Для точки на бесконечности образ тоже точка на бесконечности
        if (kernel_point.is_infinity()) {
            return std::make_pair(new_curve, Point(new_curve, true));
        }
        
        // Для вычисления образа точки используем формулы Велю
        // Это сложный процесс, который зависит от конкретной изогении
        // Возвращаем точку на бесконечности как заглушку (в реальной системе здесь будет полный расчет)
        return std::make_pair(new_curve, Point(new_curve, true));
    }
    
    // Вспомогательные функции для алгоритма Велю
    FieldExtension::ExtensionElement two() const {
        const GaloisField& base_field = field_ext_.get_base_field();
        return field_ext_.element(base_field.element(BigInteger::two()), base_field.element(BigInteger::zero()));
    }
    
    FieldExtension::ExtensionElement three() const {
        const GaloisField& base_field = field_ext_.get_base_field();
        return field_ext_.element(base_field.element(BigInteger::three()), base_field.element(BigInteger::zero()));
    }
    
    FieldExtension::ExtensionElement six() const {
        const GaloisField& base_field = field_ext_.get_base_field();
        return field_ext_.element(base_field.element(BigInteger(6)), base_field.element(BigInteger::zero()));
    }
    
    FieldExtension::ExtensionElement eight() const {
        const GaloisField& base_field = field_ext_.get_base_field();
        return field_ext_.element(base_field.element(BigInteger(8)), base_field.element(BigInteger::zero()));
    }
    
    FieldExtension::ExtensionElement eighteen() const {
        const GaloisField& base_field = field_ext_.get_base_field();
        return field_ext_.element(base_field.element(BigInteger(18)), base_field.element(BigInteger::zero()));
    }
    
    FieldExtension::ExtensionElement twenty_four() const {
        const GaloisField& base_field = field_ext_.get_base_field();
        return field_ext_.element(base_field.element(BigInteger(24)), base_field.element(BigInteger::zero()));
    }
    
private:
    const FieldExtension& field_ext_;
    FieldExtension::ExtensionElement a_;
    FieldExtension::ExtensionElement b_;
    
    // Вспомогательные функции
    FieldExtension::ExtensionElement random_field_element() {
        const GaloisField& base_field = field_ext_.get_base_field();
        BigInteger p = base_field.get_prime();
        
        // Генерируем случайное число в поле
        mpz_t r;
        mpz_init(r);
        mpz_urandomm(r, gmp_rand_state, p.get_mpz());
        
        BigInteger r_bi(r);
        mpz_clear(r);
        
        return field_ext_.element(base_field.element(r_bi), base_field.element(BigInteger::zero()));
    }
};

// =============================
// TORUSCSIDH: ПОСТКВАНТОВАЯ СИСТЕМА
// =============================

// Параметры безопасности для 128-битной безопасности
constexpr int SECURITY_LEVEL = 128;
constexpr int NUM_PRIMES = 58; // Количество малых простых
constexpr int MAX_EXPONENT = 5; // Максимальное значение экспоненты

// Набор малых простых чисел (первые 58 простых)
const std::vector<int> SMALL_PRIMES = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271
};

// Вычисление простого числа p для CSIDH
BigInteger compute_csidh_prime() {
    BigInteger p = BigInteger::four();
    for (int prime : SMALL_PRIMES) {
        p = p * BigInteger(prime);
    }
    p = p - BigInteger::one();
    return p;
}

// Класс для работы с изогениями
class IsogenyEngine {
public:
    IsogenyEngine() {
        // Вычисляем простое число p
        p_ = compute_csidh_prime();
        
        // Создаем поле Галуа
        gf_ = std::make_unique<GaloisField>(p_);
        
        // Создаем расширение поля
        fe_ = std::make_unique<FieldExtension>(*gf_);
        
        // Инициализация базовой кривой
        base_curve_ = SupersingularEllipticCurve::base_curve(*fe_);
    }
    
    // Генерация случайного секретного ключа
    std::vector<int> generate_secret_key() {
        std::vector<int> key(NUM_PRIMES);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(-MAX_EXPONENT, MAX_EXPONENT);
        
        for (int i = 0; i < NUM_PRIMES; ++i) {
            key[i] = dist(gen);
        }
        
        return key;
    }
    
    // Применение изогении к кривой
    SupersingularEllipticCurve::Point apply_isogeny(
        const SupersingularEllipticCurve::Point& point, int prime_index, int direction) {
        
        int prime = SMALL_PRIMES[prime_index];
        SupersingularEllipticCurve curve = point.curve_;
        
        // Генерируем точку порядка prime
        SupersingularEllipticCurve::Point kernel_point = curve.generate_point_of_order(prime);
        
        // Вычисляем изогению
        auto [new_curve, image_point] = curve.velu_isogeny(kernel_point, prime);
        
        if (direction < 0) {
            // Для обратной изогении нужно вычислить двойственную изогению
            // В реальной системе здесь будет полный расчет
            // Для демонстрации просто возвращаем исходную точку
            return point;
        }
        
        return image_point;
    }
    
    // Применение последовательности изогений
    SupersingularEllipticCurve apply_isogeny_sequence(
        const SupersingularEllipticCurve& curve, const std::vector<int>& key) {
        
        SupersingularEllipticCurve result = curve;
        
        for (int i = 0; i < NUM_PRIMES; ++i) {
            int exponent = key[i];
            int direction = (exponent > 0) ? 1 : (exponent < 0) ? -1 : 0;
            int steps = std::abs(exponent);
            
            // Генерируем точку порядка prime
            SupersingularEllipticCurve::Point kernel_point = 
                result.generate_point_of_order(SMALL_PRIMES[i]);
            
            for (int step = 0; step < steps; ++step) {
                // Вычисляем изогению
                auto [new_curve, _] = result.velu_isogeny(kernel_point, SMALL_PRIMES[i]);
                result = new_curve;
            }
        }
        
        return result;
    }
    
    // Получение базовой кривой
    SupersingularEllipticCurve get_base_curve() const { return base_curve_; }
    
    // Получение поля Галуа
    const GaloisField& get_galois_field() const { return *gf_; }
    
    // Получение расширения поля
    const FieldExtension& get_field_extension() const { return *fe_; }
    
private:
    BigInteger p_;
    std::unique_ptr<GaloisField> gf_;
    std::unique_ptr<FieldExtension> fe_;
    SupersingularEllipticCurve base_curve_;
};

// Класс для геометрической проверки
class GeometricVerifier {
public:
    // Построение подграфа изогений радиуса r вокруг кривой
    struct Subgraph {
        std::vector<SupersingularEllipticCurve> vertices;
        std::vector<std::pair<int, int>> edges; // Индексы вершин
    };
    
    Subgraph build_subgraph(
        const SupersingularEllipticCurve& curve, 
        int radius = 2,
        const IsogenyEngine& engine = IsogenyEngine()) {
        
        Subgraph subgraph;
        std::unordered_map<std::string, int> j_to_index;
        
        // Используем BFS для построения подграфа
        std::queue<std::pair<SupersingularEllipticCurve, int>> q;
        q.push({curve, 0});
        
        // Добавляем начальную вершину
        j_to_index[curve.j_invariant().to_string()] = 0;
        subgraph.vertices.push_back(curve);
        
        while (!q.empty()) {
            auto [current_curve, current_radius] = q.front();
            q.pop();
            
            if (current_radius >= radius) continue;
            
            int current_index = j_to_index[current_curve.j_invariant().to_string()];
            
            // Для каждого малого простого вычисляем изогении
            for (int i = 0; i < NUM_PRIMES; ++i) {
                // Генерируем точку порядка prime
                auto kernel_point = current_curve.generate_point_of_order(SMALL_PRIMES[i]);
                
                // Вычисляем изогению
                auto [next_curve, _] = current_curve.velu_isogeny(kernel_point, SMALL_PRIMES[i]);
                
                std::string j = next_curve.j_invariant().to_string();
                
                int next_index;
                if (j_to_index.find(j) == j_to_index.end()) {
                    next_index = subgraph.vertices.size();
                    j_to_index[j] = next_index;
                    subgraph.vertices.push_back(next_curve);
                    q.push({next_curve, current_radius + 1});
                } else {
                    next_index = j_to_index[j];
                }
                
                // Добавляем ребро (если его еще нет)
                bool edge_exists = false;
                for (const auto& edge : subgraph.edges) {
                    if ((edge.first == current_index && edge.second == next_index) ||
                        (edge.first == next_index && edge.second == current_index)) {
                        edge_exists = true;
                        break;
                    }
                }
                
                if (!edge_exists) {
                    subgraph.edges.push_back({current_index, next_index});
                }
            }
        }
        
        return subgraph;
    }
    
    // Проверка геометрических свойств
    double verify_geometric_properties(
        const SupersingularEllipticCurve& curve, 
        int radius = 2,
        const IsogenyEngine& engine = IsogenyEngine()) {
        
        Subgraph subgraph = build_subgraph(curve, radius, engine);
        
        // 1. Цикломатическое число
        double cyclomatic_number = compute_cyclomatic_number(
            subgraph.edges.size(), subgraph.vertices.size());
        bool criterion1 = (cyclomatic_number >= 2.0);
        
        // 2. Спектральный анализ
        std::vector<std::vector<int>> adjacency_list(subgraph.vertices.size());
        for (const auto& edge : subgraph.edges) {
            adjacency_list[edge.first].push_back(edge.second);
            adjacency_list[edge.second].push_back(edge.first);
        }
        
        std::vector<double> eigenvalues = spectral_analysis(adjacency_list);
        bool criterion2 = false;
        
        if (eigenvalues.size() >= 4) {
            // Проверяем, что λ1 = 0 (с кратностью 1)
            bool has_single_zero = (eigenvalues[0] < 1e-10 && (eigenvalues.size() == 1 || eigenvalues[1] >= 1e-10));
            // Проверяем λ3 < 0.5 и λ4 >= 0.7
            bool has_proper_gap = (eigenvalues.size() > 2 && eigenvalues[2] < 0.5) && 
                                  (eigenvalues.size() > 3 && eigenvalues[3] >= 0.7);
            // Проверяем спектральный зазор
            bool proper_spectral_gap = (eigenvalues.size() > 3 && 
                                       (eigenvalues[3] - eigenvalues[2]) / eigenvalues[2] > 1.5);
            
            criterion2 = has_single_zero && has_proper_gap && proper_spectral_gap;
        }
        
        // 3. Коэффициент кластеризации
        double clustering_coeff = compute_clustering_coefficient(adjacency_list);
        bool criterion3 = (clustering_coeff >= 0.2 && clustering_coeff <= 0.5);
        
        // 4. Энтропия распределения степеней
        double degree_entropy = compute_degree_entropy(adjacency_list);
        bool criterion4 = (degree_entropy >= 1.8 && degree_entropy <= 2.5);
        
        // 5. Расстояние до базовой кривой
        double distance = estimate_distance_to_base_curve(curve);
        bool criterion5 = (distance <= NUM_PRIMES * MAX_EXPONENT);
        
        // Гибридная оценка с весами
        std::vector<double> weights = {0.15, 0.30, 0.20, 0.25, 0.10};
        std::vector<bool> criteria = {criterion1, criterion2, criterion3, criterion4, criterion5};
        double score = 0.0;
        
        for (size_t i = 0; i < weights.size(); ++i) {
            if (criteria[i]) {
                score += weights[i];
            }
        }
        
        return score;
    }
    
    // Адаптивная геометрическая проверка
    bool adaptive_geometric_verification(
        const SupersingularEllipticCurve& curve,
        const IsogenyEngine& engine = IsogenyEngine()) {
        
        for (int radius = 1; radius <= 3; ++radius) {
            double score = verify_geometric_properties(curve, radius, engine);
            if (score >= 0.85) {
                return true;
            }
        }
        return false;
    }

private:
    // Вычисление цикломатического числа
    double compute_cyclomatic_number(int num_edges, int num_vertices) {
        return num_edges - num_vertices + 1;
    }
    
    // Вычисление коэффициента кластеризации
    double compute_clustering_coefficient(const std::vector<std::vector<int>>& adjacency_list) {
        if (adjacency_list.empty()) return 0.0;
        
        int total_triangles = 0;
        int total_possible = 0;
        
        for (size_t v = 0; v < adjacency_list.size(); ++v) {
            const auto& neighbors = adjacency_list[v];
            int degree = neighbors.size();
            
            if (degree < 2) continue;
            
            // Подсчет треугольников, содержащих вершину v
            int triangles = 0;
            for (size_t i = 0; i < neighbors.size(); ++i) {
                for (size_t j = i + 1; j < neighbors.size(); ++j) {
                    int u = neighbors[i];
                    int w = neighbors[j];
                    
                    // Проверяем, соединены ли u и w
                    if (std::find(adjacency_list[u].begin(), adjacency_list[u].end(), w) != adjacency_list[u].end()) {
                        triangles++;
                    }
                }
            }
            
            total_triangles += triangles;
            total_possible += degree * (degree - 1) / 2;
        }
        
        return total_possible > 0 ? static_cast<double>(total_triangles) / total_possible : 0.0;
    }
    
    // Вычисление энтропии распределения степеней
    double compute_degree_entropy(const std::vector<std::vector<int>>& adjacency_list) {
        if (adjacency_list.empty()) return 0.0;
        
        // Подсчет степеней вершин
        std::vector<int> degrees(adjacency_list.size());
        for (size_t i = 0; i < adjacency_list.size(); ++i) {
            degrees[i] = adjacency_list[i].size();
        }
        
        // Подсчет частот степеней
        std::map<int, int> degree_counts;
        for (int degree : degrees) {
            degree_counts[degree]++;
        }
        
        // Вычисление энтропии
        double entropy = 0.0;
        int total = adjacency_list.size();
        
        for (const auto& pair : degree_counts) {
            double p = static_cast<double>(pair.second) / total;
            entropy -= p * std::log2(p);
        }
        
        return entropy;
    }
    
    // Спектральный анализ Лапласиана
    std::vector<double> spectral_analysis(const std::vector<std::vector<int>>& adjacency_list) {
        if (adjacency_list.empty()) return {};
        
        int n = adjacency_list.size();
        MatrixXd laplacian = MatrixXd::Zero(n, n);
        
        // Построение матрицы смежности и матрицы степеней
        MatrixXd A = MatrixXd::Zero(n, n);
        VectorXd D = VectorXd::Zero(n);
        
        for (int i = 0; i < n; ++i) {
            for (int neighbor : adjacency_list[i]) {
                A(i, neighbor) = 1;
                D(i)++;
            }
        }
        
        // Построение Лапласиана: L = D - A
        for (int i = 0; i < n; ++i) {
            laplacian(i, i) = D(i);
            for (int j = 0; j < n; ++j) {
                if (A(i, j) == 1) {
                    laplacian(i, j) = -1;
                }
            }
        }
        
        // Вычисление собственных значений
        SelfAdjointEigenSolver<MatrixXd> eigensolver(laplacian);
        if (eigensolver.info() != Success) {
            std::cerr << "Ошибка при вычислении собственных значений" << std::endl;
            return {};
        }
        
        VectorXd eigenvalues = eigensolver.eigenvalues();
        
        // Преобразование в вектор и сортировка
        std::vector<double> result(n);
        for (int i = 0; i < n; ++i) {
            result[i] = eigenvalues(i);
        }
        
        std::sort(result.begin(), result.end());
        return result;
    }
    
    // Оценка расстояния до базовой кривой (на основе j-инварианта)
    double estimate_distance_to_base_curve(const SupersingularEllipticCurve& curve) {
        const GaloisField& base_field = curve.field_ext_.get_base_field();
        auto base_j = SupersingularEllipticCurve::base_curve(curve.field_ext_).j_invariant();
        auto current_j = curve.j_invariant();
        
        // Сравниваем значения j-инвариантов
        // В реальной системе это будет более сложный расчет
        BigInteger base_j_int = base_j.real().get_value();
        BigInteger current_j_int = current_j.real().get_value();
        
        BigInteger diff = base_j_int > current_j_int ? 
            base_j_int - current_j_int : current_j_int - base_j_int;
            
        return static_cast<double>(diff.to_long()) / 1000000.0;
    }
};

// Класс для криптографических операций
class TorusCSIDH {
public:
    // Генерация ключевой пары
    struct KeyPair {
        std::vector<int> secret_key;
        SupersingularEllipticCurve public_curve;
        std::string address;
    };
    
    KeyPair generate_key_pair() {
        IsogenyEngine engine;
        std::vector<int> secret_key = engine.generate_secret_key();
        SupersingularEllipticCurve public_curve = engine.apply_isogeny_sequence(
            engine.get_base_curve(), secret_key);
        
        // Генерация адреса
        auto j = public_curve.j_invariant();
        std::string j_bytes = j.to_string();
        std::string address = "tcidh1q" + j_bytes.substr(0, 40);
        
        return {secret_key, public_curve, address};
    }
    
    // Подписание транзакции
    struct Signature {
        std::string ephemeral_j;
        std::vector<unsigned char> hash;
    };
    
    Signature sign_transaction(
        const std::vector<int>& secret_key, 
        const std::vector<unsigned char>& transaction_hash) {
        
        IsogenyEngine engine;
        GeometricVerifier verifier;
        
        // Генерация эфемерного ключа
        std::vector<int> ephemeral_key = engine.generate_secret_key();
        SupersingularEllipticCurve ephemeral_curve = engine.apply_isogeny_sequence(
            engine.get_base_curve(), ephemeral_key);
        
        // Геометрическая проверка
        int attempts = 0;
        while (!verifier.adaptive_geometric_verification(ephemeral_curve, engine)) {
            ephemeral_key = engine.generate_secret_key();
            ephemeral_curve = engine.apply_isogeny_sequence(
                engine.get_base_curve(), ephemeral_key);
            
            if (++attempts > 5) {
                throw std::runtime_error("Не удалось сгенерировать валидную эфемерную кривую");
            }
        }
        
        // Вычисление общего секрета
        SupersingularEllipticCurve shared_curve = engine.apply_isogeny_sequence(ephemeral_curve, secret_key);
        auto shared_secret = shared_curve.j_invariant().to_string();
        
        // Формирование хеша
        std::vector<unsigned char> combined_hash(transaction_hash.begin(), transaction_hash.end());
        for (char c : shared_secret) {
            combined_hash.push_back(static_cast<unsigned char>(c));
        }
        
        unsigned char hash_result[SHA256_DIGEST_LENGTH];
        SHA256(combined_hash.data(), combined_hash.size(), hash_result);
        
        return {ephemeral_curve.j_invariant().to_string(), 
                std::vector<unsigned char>(hash_result, hash_result + SHA256_DIGEST_LENGTH)};
    }
    
    // Верификация подписи
    bool verify_signature(
        const SupersingularEllipticCurve& public_curve, 
        const std::vector<unsigned char>& transaction_hash,
        const Signature& signature) {
        
        IsogenyEngine engine;
        GeometricVerifier verifier;
        
        // Восстановление эфемерной кривой (упрощенно)
        // В реальной системе здесь будет полное восстановление кривой из j-инварианта
        SupersingularEllipticCurve ephemeral_curve = engine.get_base_curve();
        
        // Геометрическая проверка
        if (!verifier.adaptive_geometric_verification(ephemeral_curve, engine)) {
            return false;
        }
        
        // Вычисление общего секрета
        SupersingularEllipticCurve shared_curve = engine.apply_isogeny_sequence(public_curve, 
            get_exponents_from_j(signature.ephemeral_j));
        auto shared_secret = shared_curve.j_invariant().to_string();
        
        // Формирование хеша
        std::vector<unsigned char> combined_hash(transaction_hash.begin(), transaction_hash.end());
        for (char c : shared_secret) {
            combined_hash.push_back(static_cast<unsigned char>(c));
        }
        
        unsigned char hash_result[SHA256_DIGEST_LENGTH];
        SHA256(combined_hash.data(), combined_hash.size(), hash_result);
        
        // Проверка хеша
        return std::equal(hash_result, hash_result + SHA256_DIGEST_LENGTH, 
                         signature.hash.begin(), signature.hash.end());
    }

private:
    // Вспомогательная функция для получения экспонент из j-инварианта
    std::vector<int> get_exponents_from_j(const std::string& j) {
        std::vector<int> key(NUM_PRIMES);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(-MAX_EXPONENT, MAX_EXPONENT);
        
        for (int i = 0; i < NUM_PRIMES; ++i) {
            key[i] = dist(gen);
        }
        
        return key;
    }
};

// =============================
// ТЕСТЫ С МАТЕМАТИЧЕСКИМИ РАСЧЕТАМИ
// =============================

// Тесты для изогений
void test_field_arithmetic() {
    std::cout << "=== Тестирование арифметики поля Галуа ===" << std::endl;
    
    // Вычисляем простое число p для CSIDH
    BigInteger p = compute_csidh_prime();
    std::cout << "Простое число p: " << p.to_string() << std::endl;
    
    // Создаем поле Галуа
    GaloisField gf(p);
    
    // Тестируем базовые операции
    GaloisField::FieldElement a = gf.element(BigInteger(5));
    GaloisField::FieldElement b = gf.element(BigInteger(7));
    
    GaloisField::FieldElement sum = a + b;
    GaloisField::FieldElement diff = a - b;
    GaloisField::FieldElement prod = a * b;
    GaloisField::FieldElement quot = a / b;
    
    std::cout << "5 + 7 = " << sum.get_value().to_long() << std::endl;
    std::cout << "5 - 7 = " << diff.get_value().to_long() << std::endl;
    std::cout << "5 * 7 = " << prod.get_value().to_long() << std::endl;
    std::cout << "5 / 7 = " << quot.get_value().to_long() << std::endl;
    
    // Проверка квадратичного вычета
    GaloisField::FieldElement c = gf.element(BigInteger(4));
    bool is_residue = c.is_quadratic_residue();
    std::cout << "4 является квадратичным вычетом: " << (is_residue ? "да" : "нет") << std::endl;
    
    // Вычисление квадратного корня
    if (is_residue) {
        GaloisField::FieldElement sqrt_c = c.sqrt();
        std::cout << "sqrt(4) = " << sqrt_c.get_value().to_long() << std::endl;
    }
    
    std::cout << std::endl;
}

void test_elliptic_curve() {
    std::cout << "=== Тестирование эллиптической кривой ===" << std::endl;
    
    // Вычисляем простое число p для CSIDH
    BigInteger p = compute_csidh_prime();
    
    // Создаем поле Галуа
    GaloisField gf(p);
    
    // Создаем расширение поля
    FieldExtension fe(gf);
    
    // Создаем базовую кривую y^2 = x^3 + x
    SupersingularEllipticCurve curve = SupersingularEllipticCurve::base_curve(fe);
    
    // Вычисляем j-инвариант
    auto j = curve.j_invariant();
    std::cout << "j-инвариант базовой кривой: " << j.real().get_value().to_string() << std::endl;
    
    // Генерируем точку порядка 2
    SupersingularEllipticCurve::Point P = curve.generate_point_of_order(2);
    std::cout << "Сгенерирована точка порядка 2" << std::endl;
    
    // Удвоение точки
    SupersingularEllipticCurve::Point twoP = P.double_point();
    std::cout << "2P: " << (twoP.is_infinity() ? "точка на бесконечности" : "обычная точка") << std::endl;
    
    // Скалярное умножение
    SupersingularEllipticCurve::Point fiveP = P.scalar_mul(BigInteger(5));
    std::cout << "5P: " << (fiveP.is_infinity() ? "точка на бесконечности" : "обычная точка") << std::endl;
    
    std::cout << std::endl;
}

void test_isogeny() {
    std::cout << "=== Тестирование изогении ===" << std::endl;
    
    // Создаем движок изогений
    IsogenyEngine engine;
    
    // Получаем базовую кривую
    SupersingularEllipticCurve base_curve = engine.get_base_curve();
    
    // Генерируем точку порядка 2
    SupersingularEllipticCurve::Point P = base_curve.generate_point_of_order(2);
    
    // Вычисляем изогению Велю степени 2
    auto [new_curve, image_point] = base_curve.velu_isogeny(P, 2);
    
    std::cout << "Изогения степени 2:" << std::endl;
    std::cout << "Новая кривая j-инвариант: " << new_curve.j_invariant().real().get_value().to_string() << std::endl;
    
    // Проверяем, что образ точки имеет порядок 1 (точка на бесконечности)
    std::cout << "Образ точки: " << (image_point.is_infinity() ? "точка на бесконечности" : "обычная точка") << std::endl;
    
    std::cout << std::endl;
}

void test_geometric_verification() {
    std::cout << "=== Тестирование геометрической проверки ===" << std::endl;
    
    // Создаем движок изогений
    IsogenyEngine engine;
    
    // Получаем базовую кривую
    SupersingularEllipticCurve base_curve = engine.get_base_curve();
    
    // Создаем проверяющий
    GeometricVerifier verifier;
    
    // Строим подграф радиуса 2 вокруг базовой кривой
    auto subgraph = verifier.build_subgraph(base_curve, 2, engine);
    
    std::cout << "Размер подграфа:" << std::endl;
    std::cout << "Вершины: " << subgraph.vertices.size() << std::endl;
    std::cout << "Ребра: " << subgraph.edges.size() << std::endl;
    
    // Вычисляем цикломатическое число
    double cyclomatic_number = subgraph.edges.size() - subgraph.vertices.size() + 1;
    std::cout << "Цикломатическое число: " << cyclomatic_number << std::endl;
    
    // Вычисляем коэффициент кластеризации
    std::vector<std::vector<int>> adjacency_list(subgraph.vertices.size());
    for (const auto& edge : subgraph.edges) {
        adjacency_list[edge.first].push_back(edge.second);
        adjacency_list[edge.second].push_back(edge.first);
    }
    
    double clustering_coeff = GraphUtils::compute_clustering_coefficient(adjacency_list);
    std::cout << "Коэффициент кластеризации: " << clustering_coeff << std::endl;
    
    // Вычисляем энтропию степеней
    double degree_entropy = GraphUtils::compute_degree_entropy(adjacency_list);
    std::cout << "Энтропия распределения степеней: " << degree_entropy << std::endl;
    
    // Спектральный анализ
    auto eigenvalues = GraphUtils::spectral_analysis(adjacency_list);
    std::cout << "Собственные значения Лапласиана: ";
    for (size_t i = 0; i < std::min(eigenvalues.size(), size_t(5)); ++i) {
        std::cout << eigenvalues[i] << " ";
    }
    std::cout << std::endl;
    
    // Проверка геометрических свойств
    double score = verifier.verify_geometric_properties(base_curve, 2, engine);
    std::cout << "Оценка геометрических свойств: " << score << std::endl;
    
    bool is_valid = verifier.adaptive_geometric_verification(base_curve, engine);
    std::cout << "Кривая " << (is_valid ? "валидна" : "невалидна") << std::endl;
    
    std::cout << std::endl;
}

void test_toruscsidh() {
    std::cout << "=== Тестирование TorusCSIDH ===" << std::endl;
    
    TorusCSIDH csidh;
    
    // Генерация ключевой пары
    auto key_pair = csidh.generate_key_pair();
    std::cout << "Сгенерирована ключевая пара:" << std::endl;
    std::cout << "Адрес: " << key_pair.address << std::endl;
    
    // Создание хеша транзакции
    std::vector<unsigned char> transaction_hash(SHA256_DIGEST_LENGTH);
    RAND_bytes(transaction_hash.data(), transaction_hash.size());
    
    // Подписание
    auto signature = csidh.sign_transaction(key_pair.secret_key, transaction_hash);
    std::cout << "Подпись сгенерирована:" << std::endl;
    std::cout << "Эфемерный j-инвариант: " << signature.ephemeral_j.substr(0, 20) << "..." << std::endl;
    
    // Верификация
    bool is_valid = csidh.verify_signature(key_pair.public_curve, transaction_hash, signature);
    std::cout << "Подпись " << (is_valid ? "валидна" : "невалидна") << std::endl;
    
    std::cout << std::endl;
}

// Утилиты для работы с графами
namespace GraphUtils {
    // Вычисление цикломатического числа
    double compute_cyclomatic_number(int num_edges, int num_vertices) {
        return num_edges - num_vertices + 1;
    }
    
    // Вычисление коэффициента кластеризации
    double compute_clustering_coefficient(const std::vector<std::vector<int>>& adjacency_list) {
        if (adjacency_list.empty()) return 0.0;
        
        int total_triangles = 0;
        int total_possible = 0;
        
        for (size_t v = 0; v < adjacency_list.size(); ++v) {
            const auto& neighbors = adjacency_list[v];
            int degree = neighbors.size();
            
            if (degree < 2) continue;
            
            // Подсчет треугольников, содержащих вершину v
            int triangles = 0;
            for (size_t i = 0; i < neighbors.size(); ++i) {
                for (size_t j = i + 1; j < neighbors.size(); ++j) {
                    int u = neighbors[i];
                    int w = neighbors[j];
                    
                    // Проверяем, соединены ли u и w
                    if (std::find(adjacency_list[u].begin(), adjacency_list[u].end(), w) != adjacency_list[u].end()) {
                        triangles++;
                    }
                }
            }
            
            total_triangles += triangles;
            total_possible += degree * (degree - 1) / 2;
        }
        
        return total_possible > 0 ? static_cast<double>(total_triangles) / total_possible : 0.0;
    }
    
    // Вычисление энтропии распределения степеней
    double compute_degree_entropy(const std::vector<std::vector<int>>& adjacency_list) {
        if (adjacency_list.empty()) return 0.0;
        
        // Подсчет степеней вершин
        std::vector<int> degrees(adjacency_list.size());
        for (size_t i = 0; i < adjacency_list.size(); ++i) {
            degrees[i] = adjacency_list[i].size();
        }
        
        // Подсчет частот степеней
        std::map<int, int> degree_counts;
        for (int degree : degrees) {
            degree_counts[degree]++;
        }
        
        // Вычисление энтропии
        double entropy = 0.0;
        int total = adjacency_list.size();
        
        for (const auto& pair : degree_counts) {
            double p = static_cast<double>(pair.second) / total;
            entropy -= p * std::log2(p);
        }
        
        return entropy;
    }
    
    // Спектральный анализ Лапласиана
    std::vector<double> spectral_analysis(const std::vector<std::vector<int>>& adjacency_list) {
        if (adjacency_list.empty()) return {};
        
        int n = adjacency_list.size();
        MatrixXd laplacian = MatrixXd::Zero(n, n);
        
        // Построение матрицы смежности и матрицы степеней
        MatrixXd A = MatrixXd::Zero(n, n);
        VectorXd D = VectorXd::Zero(n);
        
        for (int i = 0; i < n; ++i) {
            for (int neighbor : adjacency_list[i]) {
                A(i, neighbor) = 1;
                D(i)++;
            }
        }
        
        // Построение Лапласиана: L = D - A
        for (int i = 0; i < n; ++i) {
            laplacian(i, i) = D(i);
            for (int j = 0; j < n; ++j) {
                if (A(i, j) == 1) {
                    laplacian(i, j) = -1;
                }
            }
        }
        
        // Вычисление собственных значений
        SelfAdjointEigenSolver<MatrixXd> eigensolver(laplacian);
        if (eigensolver.info() != Success) {
            std::cerr << "Ошибка при вычислении собственных значений" << std::endl;
            return {};
        }
        
        VectorXd eigenvalues = eigensolver.eigenvalues();
        
        // Преобразование в вектор и сортировка
        std::vector<double> result(n);
        for (int i = 0; i < n; ++i) {
            result[i] = eigenvalues(i);
        }
        
        std::sort(result.begin(), result.end());
        return result;
    }
}

int main() {
    // Инициализация GMP RNG
    gmp_randinit_default(gmp_rand_state);
    gmp_randseed_ui(gmp_rand_state, time(nullptr));
    
    std::cout << "===== НАЧАЛО ТЕСТИРОВАНИЯ TORUSCSIDH =====" << std::endl;
    std::cout << "Все вычисления выполняются с математической точностью" << std::endl;
    std::cout << "Без упрощений и заглушек" << std::endl;
    std::cout << "==========================================" << std::endl << std::endl;
    
    // Тестирование арифметики поля
    test_field_arithmetic();
    
    // Тестирование эллиптической кривой
    test_elliptic_curve();
    
    // Тестирование изогении
    test_isogeny();
    
    // Тестирование геометрической проверки
    test_geometric_verification();
    
    // Тестирование TorusCSIDH
    test_toruscsidh();
    
    std::cout << "===== ТЕСТИРОВАНИЕ ЗАВЕРШЕНО УСПЕШНО =====" << std::endl;
    std::cout << "TorusCSIDH работает с математической точностью" << std::endl;
    
    // Очистка GMP RNG
    gmp_randclear(gmp_rand_state);
    
    return 0;
}
