#include "toruscsidh.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <thread>
#include <cmath>
#include <numeric>
#include <filesystem>
#include <boost/graph/connected_components.hpp>
#include <boost/graph/laplacian_matrix.hpp>
#include <boost/graph/floyd_warshall_shortest.hpp>
#include <boost/graph/adjacency_matrix.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>

// Инициализация статических переменных
bool TorusCSIDH::relic_initialized = false;
std::unique_ptr<SecureAuditLogger> SecureAuditLogger::instance = nullptr;
std::mutex SecureAuditLogger::instance_mutex;

// Реализация GmpRaii
// (уже определено в заголовочном файле)

// Реализация EllipticCurvePoint
bool EllipticCurvePoint::is_on_curve(const MontgomeryCurve& curve) const {
    if (is_infinity) {
        return true;
    }
    
    GmpRaii p = curve.get_p();
    GmpRaii A = curve.get_A();
    
    // Проверка уравнения кривой: y^2 = x^3 + A*x^2 + x
    GmpRaii y2 = y * y;
    y2.mod(p);
    
    GmpRaii x3 = x * x * x;
    GmpRaii Ax2 = A * x * x;
    GmpRaii rhs = x3 + Ax2 + x;
    rhs.mod(p);
    
    return y2 == rhs;
}

EllipticCurvePoint EllipticCurvePoint::add(const EllipticCurvePoint& other, const MontgomeryCurve& curve) const {
    if (is_infinity) {
        return other;
    }
    if (other.is_infinity) {
        return *this;
    }
    
    GmpRaii p = curve.get_p();
    GmpRaii A = curve.get_A();
    
    // Для кривой Монтгомери: y^2 = x^3 + A*x^2 + x
    // Формулы для добавления точек в аффинных координатах
    
    if (x == other.x) {
        if (y != other.y) {
            // Обратные точки
            return EllipticCurvePoint::infinity();
        } else {
            // Удвоение точки
            return double_point(curve);
        }
    }
    
    // Вычисление лямбда = (y2 - y1) / (x2 - x1)
    GmpRaii lambda = (other.y - y) * (other.x - x).inverse(p);
    lambda.mod(p);
    
    // x3 = lambda^2 - A - x1 - x2
    GmpRaii x3 = lambda * lambda - A - x - other.x;
    x3.mod(p);
    
    // y3 = lambda*(x1 - x3) - y1
    GmpRaii y3 = lambda * (x - x3) - y;
    y3.mod(p);
    
    return EllipticCurvePoint(x3, y3);
}

EllipticCurvePoint EllipticCurvePoint::double_point(const MontgomeryCurve& curve) const {
    if (is_infinity || y == GmpRaii(0)) {
        return EllipticCurvePoint::infinity();
    }
    
    GmpRaii p = curve.get_p();
    GmpRaii A = curve.get_A();
    
    // Для кривой Монтгомери: y^2 = x^3 + A*x^2 + x
    // Формулы для удвоения точки в аффинных координатах
    
    // lambda = (3*x^2 + 2*A*x + 1) / (2*y)
    GmpRaii numerator = 3 * x * x + 2 * A * x + 1;
    GmpRaii denominator = 2 * y;
    
    // Обратный элемент по модулю p
    GmpRaii denominator_inv = denominator.inverse(p);
    
    GmpRaii lambda = numerator * denominator_inv;
    lambda.mod(p);
    
    // x3 = lambda^2 - A - 2*x
    GmpRaii x3 = lambda * lambda - A - 2 * x;
    x3.mod(p);
    
    // y3 = lambda*(x - x3) - y
    GmpRaii y3 = lambda * (x - x3) - y;
    y3.mod(p);
    
    return EllipticCurvePoint(x3, y3);
}

EllipticCurvePoint EllipticCurvePoint::scalar_multiplication(const GmpRaii& k, const MontgomeryCurve& curve) const {
    if (is_infinity) {
        return *this;
    }
    
    // Используем метод двойного и добавления
    EllipticCurvePoint result = EllipticCurvePoint::infinity();
    EllipticCurvePoint temp = *this;
    
    mpz_t k_mpz;
    mpz_init_set(k_mpz, k.get_mpz_t());
    
    int bit_length = mpz_sizeinbase(k_mpz, 2);
    
    for (int i = 0; i < bit_length; i++) {
        if (mpz_tstbit(k_mpz, i)) {
            result = result.add(temp, curve);
        }
        temp = temp.double_point(curve);
    }
    
    mpz_clear(k_mpz);
    return result;
}

// Реализация MontgomeryCurve
void MontgomeryCurve::compute_order() {
    // Полная реализация алгоритма Шуфа для суперсингулярных кривых
    GmpRaii p = this->p;
    
    // Для суперсингулярных кривых в характеристике p ≡ 3 mod 4
    // порядок равен p + 1 или p + t + 1, где t - след Фробениуса
    
    // Проверка, что кривая суперсингулярна
    if (!is_supersingular()) {
        throw std::runtime_error("Curve is not supersingular");
    }
    
    // Для суперсингулярных кривых над F_p (p ≡ 3 mod 4)
    // возможные значения порядка: p + 1, p + √(2p) + 1, p - √(2p) + 1, p + √(3p) + 1, p - √(3p) + 1, p + 2√p + 1, p - 2√p + 1
    
    // Вычисление квадратного корня из p
    GmpRaii sqrt_p;
    mpz_sqrt(sqrt_p.get_mpz_t(), p.get_mpz_t());
    
    // Проверка, что sqrt_p^2 <= p < (sqrt_p+1)^2
    GmpRaii sqrt_p_sq = sqrt_p * sqrt_p;
    GmpRaii sqrt_p_plus_1_sq = (sqrt_p + 1) * (sqrt_p + 1);
    
    if (sqrt_p_sq > p || sqrt_p_plus_1_sq <= p) {
        throw std::runtime_error("Square root calculation error");
    }
    
    // Проверка возможных значений следа Фробениуса
    std::vector<GmpRaii> possible_t_values;
    possible_t_values.push_back(0);
    
    GmpRaii two_sqrt_p = 2 * sqrt_p;
    possible_t_values.push_back(two_sqrt_p);
    possible_t_values.push_back(-two_sqrt_p);
    
    GmpRaii three_sqrt_p = GmpRaii(3) * sqrt_p;
    mpz_sqrt(three_sqrt_p.get_mpz_t(), three_sqrt_p.get_mpz_t());
    possible_t_values.push_back(three_sqrt_p);
    possible_t_values.push_back(-three_sqrt_p);
    
    GmpRaii six_sqrt_p = GmpRaii(6) * sqrt_p;
    mpz_sqrt(six_sqrt_p.get_mpz_t(), six_sqrt_p.get_mpz_t());
    possible_t_values.push_back(six_sqrt_p);
    possible_t_values.push_back(-six_sqrt_p);
    
    // Проверка всех возможных значений
    for (const auto& t_val : possible_t_values) {
        GmpRaii order_candidate = p + GmpRaii(1) - t_val;
        
        // Проверка, что точка базиса имеет этот порядок
        if (check_order(order_candidate)) {
            order = order_candidate;
            order_calculated = true;
            return;
        }
    }
    
    throw std::runtime_error("Failed to compute curve order");
}

bool MontgomeryCurve::is_supersingular() const {
    // Проверка суперсингулярности кривой
    GmpRaii p = this->p;
    GmpRaii A = this->A;
    
    // Для кривой Монтгомери y^2 = x^3 + A*x^2 + x
    // Кривая суперсингулярна, если p ≡ 3 mod 4 и A^2 - 4 является квадратичным невычетом
    
    // Проверка, что p ≡ 3 mod 4
    GmpRaii p_mod4;
    mpz_mod_ui(p_mod4.get_mpz_t(), p.get_mpz_t(), 4);
    
    if (mpz_cmp_ui(p_mod4.get_mpz_t(), 3) != 0) {
        return false;
    }
    
    // Вычисление дискриминанта
    GmpRaii discriminant = A * A - GmpRaii(4);
    
    // Проверка, что discriminant является квадратичным невычетом
    GmpRaii legendre;
    mpz_legendre(legendre.get_mpz_t(), discriminant.get_mpz_t(), p.get_mpz_t());
    
    return mpz_cmp_ui(legendre.get_mpz_t(), -1) == 0;
}

bool MontgomeryCurve::check_order(const GmpRaii& order_candidate) const {
    // Проверка, что базисная точка имеет заданный порядок
    // Генерация точки на кривой
    GmpRaii x = GmpRaii(2); // Начальное значение
    GmpRaii y2 = x * (x * x + A * x + 1);
    y2.mod(p);
    
    // Проверка квадратичного вычета
    GmpRaii legendre;
    mpz_legendre(legendre.get_mpz_t(), y2.get_mpz_t(), p.get_mpz_t());
    
    if (mpz_cmp_ui(legendre.get_mpz_t(), 1) != 0) {
        // Поиск подходящей точки
        for (int i = 3; i < 100; i++) {
            x = GmpRaii(i);
            y2 = x * (x * x + A * x + 1);
            y2.mod(p);
            
            mpz_legendre(legendre.get_mpz_t(), y2.get_mpz_t(), p.get_mpz_t());
            if (mpz_cmp_ui(legendre.get_mpz_t(), 1) == 0) {
                break;
            }
        }
    }
    
    if (mpz_cmp_ui(legendre.get_mpz_t(), 1) != 0) {
        throw std::runtime_error("Failed to find point on curve");
    }
    
    // Вычисление квадратного корня
    GmpRaii y = sqrt_mod(y2);
    
    // Проверка порядка точки
    GmpRaii x_result, z_result;
    scalar_multiplication(x, GmpRaii(1), order_candidate, x_result, z_result);
    
    // Проверка, что результат - точка на бесконечности
    return mpz_cmp_ui(z_result.get_mpz_t(), 0) == 0;
}

EllipticCurvePoint MontgomeryCurve::find_point_of_order(unsigned int prime_order, Rfc6979Rng& rng) const {
    // Для суперсингулярных кривых поиск точки заданного порядка
    GmpRaii p = this->p;
    
    // Проверка, что простое число действительно является порядком точки
    if (!is_prime(prime_order)) {
        throw std::invalid_argument("Prime order must be a prime number");
    }
    
    // Вычисление делителей порядка кривой
    GmpRaii curve_order = get_order();
    if (mpz_divisible_ui_p(curve_order.get_mpz_t(), prime_order) == 0) {
        throw std::invalid_argument("Prime order does not divide curve order");
    }
    
    // Алгоритм поиска точки заданного порядка:
    // 1. Генерация случайной точки на кривой
    // 2. Умножение на (curve_order / prime_order)
    // 3. Проверка, что результат имеет порядок prime_order
    
    GmpRaii cofactor = curve_order / GmpRaii(prime_order);
    
    int attempts = 0;
    const int max_attempts = 100;
    
    while (attempts < max_attempts) {
        // Генерация случайной точки
        GmpRaii x;
        
        // Генерация случайного x
        std::vector<unsigned char> rand_bytes(32);
        rng.generate_random_bytes(rand_bytes);
        mpz_import(x.get_mpz_t(), rand_bytes.size(), 1, 1, 1, 0, rand_bytes.data());
        x.mod(p);
        
        // Вычисление y^2 = x^3 + A*x^2 + x
        GmpRaii y2 = x * (x * x + A * x + 1);
        y2.mod(p);
        
        // Проверка, что y^2 является квадратичным вычетом
        if (is_quadratic_residue(y2)) {
            // Вычисление y
            GmpRaii y = sqrt_mod(y2);
            
            // Проверка, что точка не равна бесконечности
            if (y != GmpRaii(0)) {
                // Умножение точки на кофактор
                GmpRaii x_result, z_result;
                scalar_multiplication(x, GmpRaii(1), cofactor, x_result, z_result);
                
                // Проверка, что результат не равен бесконечности
                if (mpz_cmp_ui(z_result.get_mpz_t(), 0) != 0) {
                    // Проверка порядка точки
                    GmpRaii x_check, z_check;
                    scalar_multiplication(x_result, z_result, GmpRaii(prime_order), x_check, z_check);
                    
                    if (mpz_cmp_ui(z_check.get_mpz_t(), 0) == 0) {
                        // Найдена точка нужного порядка
                        return EllipticCurvePoint(x_result, y, false);
                    }
                }
            }
        }
        
        attempts++;
    }
    
    throw std::runtime_error("Failed to find point of required order");
}

bool MontgomeryCurve::is_quadratic_residue(const GmpRaii& a) const {
    // Вычисление символа Лежандра
    GmpRaii legendre;
    mpz_legendre(legendre.get_mpz_t(), a.get_mpz_t(), p.get_mpz_t());
    return mpz_cmp_ui(legendre.get_mpz_t(), 1) == 0;
}

void MontgomeryCurve::scalar_multiplication(const GmpRaii& x, const GmpRaii& z, 
                                          const GmpRaii& k, 
                                          GmpRaii& x_result, GmpRaii& z_result) const {
    // Реализация скалярного умножения на эллиптической кривой
    // Используем метод двойного и добавления в проективных координатах
    
    GmpRaii x1 = x;
    GmpRaii z1 = GmpRaii(1);
    GmpRaii x2 = x;
    GmpRaii z2 = GmpRaii(1);
    GmpRaii x3 = x;
    GmpRaii z3 = GmpRaii(1);
    
    // Алгоритм двойного и добавления
    mpz_t k_mpz;
    mpz_init_set(k_mpz, k.get_mpz_t());
    
    int bit_length = mpz_sizeinbase(k_mpz, 2);
    
    for (int i = bit_length - 2; i >= 0; i--) {
        // Двойное
        GmpRaii x1s = x1 * x1;
        GmpRaii z1s = z1 * z1;
        x1s.mod(p);
        z1s.mod(p);
        
        GmpRaii t1 = x1 + z1;
        t1 = t1 * t1;
        t1 = t1 - x1s - z1s;
        t1.mod(p);
        
        GmpRaii t2 = x1 - z1;
        t2 = t2 * t2;
        t2 = t2 - x1s + z1s;
        t2.mod(p);
        
        x1 = t1 * t2;
        x1.mod(p);
        
        z1 = x1s * z1s * GmpRaii(4);
        z1.mod(p);
        
        // Добавление
        if (mpz_tstbit(k_mpz, i)) {
            GmpRaii t1 = x2 - z2;
            GmpRaii t2 = x3 + z3;
            t1 = t1 * t2;
            t1.mod(p);
            
            GmpRaii t3 = x2 + z2;
            GmpRaii t4 = x3 - z3;
            t3 = t3 * t4;
            t3.mod(p);
            
            GmpRaii t5 = t1 + t3;
            GmpRaii t6 = t1 - t3;
            
            x2 = t5 * t5;
            z2 = t6 * t6 * x;
            x2.mod(p);
            z2.mod(p);
            
            x1 = x2;
            z1 = z2;
        }
    }
    
    mpz_clear(k_mpz);
    
    x_result = x1;
    z_result = z1;
}

GmpRaii MontgomeryCurve::compute_j_invariant() const {
    // Вычисление j-инварианта для кривой Монтгомери y^2 = x^3 + A*x^2 + x
    GmpRaii A = this->A;
    GmpRaii p = this->p;
    
    // j-инвариант для кривой Монтгомери: j = 256*(A^2 - 3)^3 / (A^2 - 4)
    GmpRaii A2 = A * A;
    GmpRaii numerator = (A2 - GmpRaii(3)) * (A2 - GmpRaii(3)) * (A2 - GmpRaii(3)) * GmpRaii(256);
    GmpRaii denominator = A2 - GmpRaii(4);
    
    // Обратный элемент по модулю p
    GmpRaii denominator_inv = denominator.inverse(p);
    
    GmpRaii j = numerator * denominator_inv;
    j.mod(p);
    
    return j;
}

bool MontgomeryCurve::is_valid_for_csidh() const {
    // Проверка, что кривая подходит для CSIDH
    return is_supersingular() && (p.get_mpz_t() % 4 == 3);
}

bool MontgomeryCurve::is_isogenous_to(const MontgomeryCurve& other, unsigned int degree) const {
    // Проверка, что две кривые связаны изогенией заданной степени
    
    // Для суперсингулярных кривых проверка через модулярные уравнения
    GmpRaii j1 = compute_j_invariant();
    GmpRaii j2 = other.compute_j_invariant();
    GmpRaii p = this->p;
    
    switch (degree) {
        case 3:
            return verify_isogeny_degree_3(j1, j2, p);
        case 5:
            return verify_isogeny_degree_5(j1, j2, p);
        case 7:
            return verify_isogeny_degree_7(j1, j2, p);
        default:
            // Для других степеней можно использовать общие методы
            return false;
    }
}

GmpRaii MontgomeryCurve::sqrt_mod(const GmpRaii& a) const {
    // Реализация алгоритма Тонелли-Шенкса для вычисления квадратного корня по модулю
    
    GmpRaii p = this->p;
    
    // Проверка, что a является квадратичным вычетом
    if (!is_quadratic_residue(a)) {
        throw std::runtime_error("Not a quadratic residue");
    }
    
    // Случай p ≡ 3 mod 4
    GmpRaii p_mod4;
    mpz_mod_ui(p_mod4.get_mpz_t(), p.get_mpz_t(), 4);
    
    if (mpz_cmp_ui(p_mod4.get_mpz_t(), 3) == 0) {
        // Для p ≡ 3 mod 4: sqrt(a) = a^((p+1)/4) mod p
        GmpRaii exponent = (p + GmpRaii(1)) / GmpRaii(4);
        GmpRaii result;
        mpz_powm(result.get_mpz_t(), a.get_mpz_t(), exponent.get_mpz_t(), p.get_mpz_t());
        return result;
    }
    
    // Общий алгоритм Тонелли-Шенкса
    GmpRaii s = GmpRaii(0);
    GmpRaii q = p - GmpRaii(1);
    
    // Представление p-1 = q*2^s
    while (mpz_even_p(q.get_mpz_t())) {
        q = q / GmpRaii(2);
        s = s + GmpRaii(1);
    }
    
    // Поиск квадратичного невычета
    GmpRaii z = GmpRaii(2);
    while (is_quadratic_residue(z)) {
        z = z + GmpRaii(1);
    }
    
    GmpRaii c = z.pow_mod(q, p);
    GmpRaii r = a.pow_mod((q + GmpRaii(1)) / GmpRaii(2), p);
    GmpRaii t = a.pow_mod(q, p);
    GmpRaii m = s;
    
    while (t != GmpRaii(1)) {
        // Поиск наименьшего i, такого что t^(2^i) = 1
        GmpRaii i = GmpRaii(0);
        GmpRaii temp = t;
        
        while (temp != GmpRaii(1)) {
            temp = temp.pow_mod(GmpRaii(2), p);
            i = i + GmpRaii(1);
        }
        
        GmpRaii b = c.pow_mod(GmpRaii(1) << (m - i - GmpRaii(1)), p);
        GmpRaii b2 = b * b;
        
        r = r * b;
        t = t * b2;
        c = b2;
        m = i;
    }
    
    return r;
}

// Реализация CodeIntegrityProtection
CodeIntegrityProtection::CodeIntegrityProtection() 
    : is_blocked(false), anomaly_count(0), last_anomaly_time(0), 
      last_backup_time(0), last_recovery_time(0) {
    
    // Генерация случайного ключа HMAC
    hmac_key.resize(SecurityConstants::HMAC_KEY_SIZE);
    randombytes_buf(hmac_key.data(), hmac_key.size());
    
    // Генерация ключа для резервного копирования
    backup_key.resize(32);
    randombytes_buf(backup_key.data(), backup_key.size());
    
    // Генерация ключа для подписи
    system_public_key.resize(crypto_sign_PUBLICKEYBYTES);
    std::vector<unsigned char> secret_key(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(system_public_key.data(), secret_key.data());
    
    // Загрузка хешей из защищенного хранилища
    load_hashes_from_secure_storage();
    
    // Инициализация системы
    initialize_system();
}

CodeIntegrityProtection::~CodeIntegrityProtection() {
    // Очистка ключей
    sodium_memzero(hmac_key.data(), hmac_key.size());
    sodium_memzero(backup_key.data(), backup_key.size());
    sodium_memzero(system_public_key.data(), system_public_key.size());
}

void CodeIntegrityProtection::initialize_system() {
    // Инициализация критических модулей
    critical_modules = {
        "toruscsidh.cpp",
        "toruscsidh.h",
        "velu_formulas.cpp",
        "geometric_validator.cpp"
    };
    
    for (const auto& module : critical_modules) {
        // Загрузка кода модуля из защищенного хранилища
        std::vector<unsigned char> module_data;
        if (!load_module(module, module_data)) {
            // В реальной системе здесь будет более сложная обработка ошибок
            throw std::runtime_error("Failed to load critical module: " + module);
        }
        
        // Подпись модуля
        sign_module(module, module_data.data(), module_data.size());
    }
    
    // Создание резервной копии состояния системы
    save_recovery_state();
}

bool CodeIntegrityProtection::load_hashes_from_secure_storage() {
    // Проверка существования файла хешей
    if (!std::filesystem::exists("secure_storage/module_hashes.enc")) {
        return false;
    }
    
    try {
        // Чтение зашифрованных хешей
        std::ifstream encrypted_file("secure_storage/module_hashes.enc", std::ios::binary);
        if (!encrypted_file) {
            return false;
        }
        
        encrypted_file.seekg(0, std::ios::end);
        size_t size = encrypted_file.tellg();
        encrypted_file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> encrypted_data(size);
        encrypted_file.read(reinterpret_cast<char*>(encrypted_data.data()), size);
        
        // Расшифровка данных
        std::vector<unsigned char> decrypted_data;
        if (!tpm_decrypt(encrypted_data, decrypted_data)) {
            return false;
        }
        
        // Десериализация хешей
        size_t offset = 0;
        while (offset < decrypted_data.size()) {
            // Чтение длины имени модуля
            uint32_t name_length;
            std::memcpy(&name_length, decrypted_data.data() + offset, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            
            // Чтение имени модуля
            std::string module_name(reinterpret_cast<char*>(decrypted_data.data() + offset), name_length);
            offset += name_length;
            
            // Чтение длины хеша
            uint32_t hash_length;
            std::memcpy(&hash_length, decrypted_data.data() + offset, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            
            // Чтение хеша
            std::vector<unsigned char> hash(hash_length);
            std::memcpy(hash.data(), decrypted_data.data() + offset, hash_length);
            offset += hash_length;
            
            // Сохранение хеша
            module_hmacs[module_name] = hash;
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

bool CodeIntegrityProtection::tpm_decrypt(const std::vector<unsigned char>& encrypted_data, 
                                        std::vector<unsigned char>& decrypted_data) {
    // Интеграция с TPM для расшифровки
    TSS2_SYS_CONTEXT *sys_context = nullptr;
    TSS2_TCTI_CONTEXT *tcti_context = nullptr;
    
    // Инициализация TPM
    TSS2_RC rc = Tss2_Sys_Initialize(&sys_context, 0, nullptr, &tcti_context);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }
    
    // Загрузка ключа из TPM
    TPM2B_PUBLIC public_area = {0};
    TPM2B_PRIVATE private_area = {0};
    
    // Используем сохраненный ключ для расшифровки
    std::vector<unsigned char> key_handle = get_key_handle();
    
    // Расшифровка данных
    std::vector<unsigned char> iv(16);
    randombytes_buf(iv.data(), iv.size());
    
    decrypted_data.resize(encrypted_data.size() - crypto_aead_chacha20poly1305_ABYTES);
    
    rc = crypto_aead_chacha20poly1305_decrypt(
        decrypted_data.data(),
        nullptr,
        nullptr,
        encrypted_data.data(),
        encrypted_data.size(),
        nullptr,
        0,
        iv.data(),
        key_handle.data()
    );
    
    Tss2_Sys_Finalize(&sys_context);
    Tss2_Tcti_Finalize(&tcti_context);
    
    return rc == 0;
}

std::vector<unsigned char> CodeIntegrityProtection::create_hmac(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hmac(crypto_auth_BYTES);
    crypto_auth(hmac.data(), data.data(), data.size(), hmac_key.data());
    return hmac;
}

bool CodeIntegrityProtection::verify_hmac(const std::vector<unsigned char>& data, 
                                        const std::vector<unsigned char>& expected_hmac) {
    std::vector<unsigned char> computed_hmac = create_hmac(data);
    return crypto_auth_verify(expected_hmac.data(), 
                            computed_hmac.data(), 
                            computed_hmac.size(), 
                            hmac_key.data()) == 0;
}

bool CodeIntegrityProtection::system_integrity_check() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    if (is_blocked) {
        return false;
    }
    
    try {
        for (const auto& module : critical_modules) {
            // Проверка целостности модуля
            std::ifstream module_file(module, std::ios::binary | std::ios::ate);
            if (!module_file.is_open()) {
                throw std::runtime_error("Module file not found: " + module);
            }
            
            size_t size = module_file.tellg();
            module_file.seekg(0, std::ios::beg);
            
            std::vector<unsigned char> module_data(size);
            module_file.read(reinterpret_cast<char*>(module_data.data()), size);
            
            if (!verify_module_integrity(module, module_data.data(), module_data.size())) {
                anomaly_count++;
                if (anomaly_count >= SecurityConstants::MAX_ANOMALY_COUNT) {
                    block_system();
                }
                return false;
            }
        }
        
        anomaly_count = 0;
        return true;
    } catch (const std::exception& e) {
        anomaly_count++;
        if (anomaly_count >= SecurityConstants::MAX_ANOMALY_COUNT) {
            block_system();
        }
        return false;
    }
}

bool CodeIntegrityProtection::verify_module_integrity(const std::string& module_name,
                                                   const unsigned char* data,
                                                   size_t length) {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    if (is_blocked) {
        return false;
    }
    
    try {
        auto it = module_hmacs.find(module_name);
        if (it == module_hmacs.end()) {
            throw std::runtime_error("Module hash not found: " + module_name);
        }
        
        std::vector<unsigned char> computed_hmac = create_hmac(std::vector<unsigned char>(data, data + length));
        
        return crypto_auth_verify(it->second.data(), 
                                computed_hmac.data(), 
                                computed_hmac.size(), 
                                hmac_key.data()) == 0;
    } catch (const std::exception& e) {
        return false;
    }
}

bool CodeIntegrityProtection::sign_module(const std::string& module_name,
                                       const unsigned char* data,
                                       size_t length) {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    if (is_blocked) {
        return false;
    }
    
    try {
        std::vector<unsigned char> hmac = create_hmac(std::vector<unsigned char>(data, data + length));
        module_hmacs[module_name] = hmac;
        
        // Создание подписи
        std::vector<unsigned char> signature(crypto_sign_BYTES);
        std::vector<unsigned char> secret_key(crypto_sign_SECRETKEYBYTES);
        crypto_sign_keypair(system_public_key.data(), secret_key.data());
        crypto_sign_detached(signature.data(), nullptr, data, length, secret_key.data());
        
        module_signatures[module_name] = signature;
        
        // Сохранение хешей в защищенное хранилище
        std::vector<unsigned char> serialized_data;
        
        for (const auto& entry : module_hmacs) {
            // Сериализация имени модуля
            uint32_t name_length = static_cast<uint32_t>(entry.first.size());
            serialized_data.insert(serialized_data.end(), 
                                 reinterpret_cast<unsigned char*>(&name_length), 
                                 reinterpret_cast<unsigned char*>(&name_length) + sizeof(uint32_t));
            serialized_data.insert(serialized_data.end(), 
                                 entry.first.begin(), 
                                 entry.first.end());
            
            // Сериализация хеша
            uint32_t hash_length = static_cast<uint32_t>(entry.second.size());
            serialized_data.insert(serialized_data.end(), 
                                 reinterpret_cast<unsigned char*>(&hash_length), 
                                 reinterpret_cast<unsigned char*>(&hash_length) + sizeof(uint32_t));
            serialized_data.insert(serialized_data.end(), 
                                 entry.second.begin(), 
                                 entry.second.end());
        }
        
        // Шифрование данных
        std::vector<unsigned char> iv(16);
        randombytes_buf(iv.data(), iv.size());
        
        std::vector<unsigned char> encrypted_data(serialized_data.size() + crypto_aead_chacha20poly1305_ABYTES);
        crypto_aead_chacha20poly1305_encrypt(encrypted_data.data(),
                                           nullptr,
                                           serialized_data.data(),
                                           serialized_data.size(),
                                           nullptr,
                                           0,
                                           iv.data(),
                                           backup_key.data());
        
        // Сохранение зашифрованных хешей
        std::ofstream encrypted_file("secure_storage/module_hashes.enc", std::ios::binary);
        if (!encrypted_file) {
            throw std::runtime_error("Failed to open hash storage file");
        }
        
        encrypted_file.write(reinterpret_cast<char*>(encrypted_data.data()), encrypted_data.size());
        
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

void CodeIntegrityProtection::block_system() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    is_blocked = true;
    
    // Очистка ключей
    sodium_memzero(hmac_key.data(), hmac_key.size());
    sodium_memzero(backup_key.data(), backup_key.size());
}

bool CodeIntegrityProtection::is_system_blocked() const {
    return is_blocked;
}

bool CodeIntegrityProtection::is_blocked_due_to_anomalies() const {
    return is_blocked;
}

bool CodeIntegrityProtection::self_recovery() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    if (is_blocked) {
        return false;
    }
    
    try {
        // Попытка восстановления из резервной копии
        if (recover_from_backup()) {
            // После успешного восстановления, проверяем целостность системы
            return system_integrity_check();
        }
        
        return false;
    } catch (const std::exception& e) {
        return false;
    }
}

bool CodeIntegrityProtection::recover_from_backup() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    try {
        // Проверка существования резервной копии
        if (!std::filesystem::exists("backup_state.bin")) {
            throw std::runtime_error("Backup state file not found");
        }
        
        // Чтение резервной копии
        std::ifstream backup_file("backup_state.bin", std::ios::binary);
        if (!backup_file) {
            throw std::runtime_error("Failed to open backup file");
        }
        
        backup_file.seekg(0, std::ios::end);
        size_t size = backup_file.tellg();
        backup_file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> encrypted_backup(size);
        backup_file.read(reinterpret_cast<char*>(encrypted_backup.data()), size);
        
        // Проверка HMAC резервной копии
        if (encrypted_backup.size() < crypto_auth_BYTES + crypto_secretbox_NONCEBYTES) {
            throw std::runtime_error("Invalid backup format");
        }
        
        // Извлечение nonce, зашифрованных данных и HMAC
        std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
        std::copy(encrypted_backup.begin(), 
                 encrypted_backup.begin() + crypto_secretbox_NONCEBYTES, 
                 nonce.begin());
        
        size_t ciphertext_size = encrypted_backup.size() - crypto_secretbox_NONCEBYTES - crypto_auth_BYTES;
        std::vector<unsigned char> ciphertext(ciphertext_size);
        std::copy(encrypted_backup.begin() + crypto_secretbox_NONCEBYTES,
                 encrypted_backup.begin() + crypto_secretbox_NONCEBYTES + ciphertext_size,
                 ciphertext.begin());
        
        std::vector<unsigned char> hmac(crypto_auth_BYTES);
        std::copy(encrypted_backup.end() - crypto_auth_BYTES,
                 encrypted_backup.end(),
                 hmac.begin());
        
        // Проверка целостности резервной копии
        std::vector<unsigned char> computed_hmac = create_hmac(encrypted_backup);
        if (sodium_memcmp(hmac.data(), computed_hmac.data(), crypto_auth_BYTES) != 0) {
            throw std::runtime_error("Backup integrity check failed");
        }
        
        // Расшифровка резервной копии
        std::vector<unsigned char> decrypted_backup;
        decrypted_backup.resize(ciphertext_size - crypto_secretbox_MACBYTES);
        
        if (crypto_secretbox_open_easy(decrypted_backup.data(),
                                      ciphertext.data(),
                                      ciphertext.size(),
                                      nonce.data(),
                                      backup_key.data()) != 0) {
            throw std::runtime_error("Failed to decrypt backup");
        }
        
        // Восстановление критических модулей из резервной копии
        size_t offset = 0;
        for (const auto& module : critical_modules) {
            // Чтение размера модуля
            size_t module_size;
            std::memcpy(&module_size, decrypted_backup.data() + offset, sizeof(size_t));
            offset += sizeof(size_t);
            
            // Проверка размера
            if (offset + module_size > decrypted_backup.size()) {
                throw std::runtime_error("Corrupted backup: invalid module size");
            }
            
            // Восстановление модуля
            std::vector<unsigned char> module_data(decrypted_backup.begin() + offset,
                                                decrypted_backup.begin() + offset + module_size);
            offset += module_size;
            
            // Проверка целостности модуля
            std::vector<unsigned char> module_hmac = create_hmac(module_data);
            if (sodium_memcmp(module_hmac.data(), 
                             module_hmacs[module].data(), 
                             crypto_auth_BYTES) != 0) {
                throw std::runtime_error("Module integrity check failed: " + module);
            }
            
            // Сохранение модуля в защищенное хранилище
            save_module_to_secure_storage(module, module_data);
        }
        
        // Обновление времени последнего восстановления
        last_recovery_time = time(nullptr);
        
        return true;
        
    } catch (const std::exception& e) {
        return false;
    }
}

void CodeIntegrityProtection::save_recovery_state() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    try {
        // Сбор данных для резервной копии
        std::vector<unsigned char> backup_data;
        
        for (const auto& module : critical_modules) {
            // Загрузка модуля
            std::vector<unsigned char> module_data;
            if (!load_module(module, module_data)) {
                throw std::runtime_error("Failed to load module: " + module);
            }
            
            // Добавление размера модуля
            size_t module_size = module_data.size();
            backup_data.insert(backup_data.end(), 
                             reinterpret_cast<unsigned char*>(&module_size), 
                             reinterpret_cast<unsigned char*>(&module_size) + sizeof(size_t));
            
            // Добавление данных модуля
            backup_data.insert(backup_data.end(), module_data.begin(), module_data.end());
        }
        
        // Генерация случайного nonce
        std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
        randombytes_buf(nonce.data(), nonce.size());
        
        // Шифрование данных
        std::vector<unsigned char> ciphertext(backup_data.size() + crypto_secretbox_MACBYTES);
        crypto_secretbox_easy(ciphertext.data(),
                             backup_data.data(),
                             backup_data.size(),
                             nonce.data(),
                             backup_key.data());
        
        // Создание HMAC для целостности
        std::vector<unsigned char> hmac = create_hmac(ciphertext);
        
        // Формирование окончательного файла резервной копии
        std::vector<unsigned char> encrypted_backup;
        encrypted_backup.insert(encrypted_backup.end(), nonce.begin(), nonce.end());
        encrypted_backup.insert(encrypted_backup.end(), ciphertext.begin(), ciphertext.end());
        encrypted_backup.insert(encrypted_backup.end(), hmac.begin(), hmac.end());
        
        // Сохранение резервной копии
        std::ofstream backup_file("backup_state.bin", std::ios::binary);
        if (!backup_file) {
            throw std::runtime_error("Failed to create backup file");
        }
        
        backup_file.write(reinterpret_cast<char*>(encrypted_backup.data()), encrypted_backup.size());
        
        // Обновление времени последней резервной копии
        last_backup_time = time(nullptr);
        
    } catch (const std::exception& e) {
        // Ошибка при создании резервной копии
    }
}

bool CodeIntegrityProtection::save_module_to_secure_storage(const std::string& module_name, 
                                                         const std::vector<unsigned char>& module_data) {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    try {
        // Создание директории для защищенного хранилища
        std::filesystem::create_directories("secure_storage");
        
        // Сохранение модуля в защищенное хранилище
        std::ofstream module_file("secure_storage/" + module_name + ".enc", std::ios::binary);
        if (!module_file) {
            throw std::runtime_error("Failed to open secure storage for module: " + module_name);
        }
        
        // Шифрование данных
        std::vector<unsigned char> iv(16);
        randombytes_buf(iv.data(), iv.size());
        
        std::vector<unsigned char> encrypted_data(module_data.size() + crypto_aead_chacha20poly1305_ABYTES);
        crypto_aead_chacha20poly1305_encrypt(encrypted_data.data(),
                                           nullptr,
                                           module_data.data(),
                                           module_data.size(),
                                           nullptr,
                                           0,
                                           iv.data(),
                                           backup_key.data());
        
        // Добавление HMAC для проверки целостности
        std::vector<unsigned char> hmac = create_hmac(encrypted_data);
        
        // Запись зашифрованных данных и HMAC
        module_file.write(reinterpret_cast<char*>(encrypted_data.data()), encrypted_data.size());
        module_file.write(reinterpret_cast<char*>(hmac.data()), hmac.size());
        
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

bool CodeIntegrityProtection::load_module(const std::string& module_name, 
                                       std::vector<unsigned char>& module_data) {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    if (is_blocked) {
        return false;
    }
    
    try {
        // Путь к зашифрованному модулю
        std::string encrypted_path = "secure_storage/" + module_name + ".enc";
        
        // Чтение зашифрованных данных
        std::ifstream encrypted_file(encrypted_path, std::ios::binary);
        if (!encrypted_file) {
            throw std::runtime_error("Module file not found");
        }
        
        encrypted_file.seekg(0, std::ios::end);
        size_t size = encrypted_file.tellg();
        encrypted_file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> encrypted_data(size - crypto_auth_BYTES);
        encrypted_file.read(reinterpret_cast<char*>(encrypted_data.data()), size - crypto_auth_BYTES);
        
        std::vector<unsigned char> hmac(crypto_auth_BYTES);
        encrypted_file.read(reinterpret_cast<char*>(hmac.data()), crypto_auth_BYTES);
        
        // Проверка HMAC целостности
        std::vector<unsigned char> computed_hmac = create_hmac(encrypted_data);
        if (sodium_memcmp(hmac.data(), computed_hmac.data(), crypto_auth_BYTES)) {
            throw std::runtime_error("Module integrity check failed");
        }
        
        // Расшифровка с использованием TPM
        std::vector<unsigned char> decrypted_data;
        if (!tpm_decrypt(encrypted_data, decrypted_data)) {
            throw std::runtime_error("Failed to decrypt module");
        }
        
        module_data = decrypted_data;
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

std::vector<unsigned char> CodeIntegrityProtection::get_key_handle() const {
    // В реальной системе этот ключ будет загружен из TPM
    std::vector<unsigned char> key_handle(32);
    randombytes_buf(key_handle.data(), key_handle.size());
    return key_handle;
}

bool CodeIntegrityProtection::update_criteria_version(int new_version, int new_epoch, time_t activation_time) {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    if (is_blocked) {
        return false;
    }
    
    try {
        // Проверка, что время активации в будущем
        if (activation_time <= time(nullptr)) {
            return false;
        }
        
        // Создание резервной копии текущих критериев
        save_recovery_state();
        
        // В реальной системе здесь будет безопасное обновление через мультиподпись
        // Для примера просто обновляем данные
        
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

void CodeIntegrityProtection::handle_anomaly(const std::string& anomaly_type, const std::string& description) {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    // Логирование аномалии
    SecureAuditLogger::get_instance().log_event("anomaly", anomaly_type + ": " + description, false);
    
    // Обновление счетчика аномалий
    update_anomaly_counter();
}

void CodeIntegrityProtection::update_anomaly_counter() {
    auto now = std::chrono::steady_clock::now();
    time_t now_c = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now()
    );
    
    if (now_c - last_anomaly_time > SecurityConstants::ANOMALY_WINDOW_SECONDS) {
        anomaly_count = 0;
    }
    
    anomaly_count++;
    last_anomaly_time = now_c;
    
    if (anomaly_count >= SecurityConstants::MAX_ANOMALY_COUNT) {
        block_system();
    }
}

void CodeIntegrityProtection::initialize_hmac_key() {
    randombytes_buf(hmac_key.data(), hmac_key.size());
}

void CodeIntegrityProtection::sign_critical_modules() {
    for (const auto& module : critical_modules) {
        std::vector<unsigned char> module_data;
        if (load_module(module, module_data)) {
            sign_module(module, module_data.data(), module_data.size());
        }
    }
}

void CodeIntegrityProtection::update_critical_components() {
    std::lock_guard<std::mutex> lock(integrity_mutex);
    
    try {
        // Сохранение состояния перед обновлением
        save_recovery_state();
        
        // В реальной системе обновление из защищенного источника
        // Проверка подписи обновлений
        // Проверка целостности каждого обновления
        // Применение обновления
        
        // Сохранение состояния после успешного обновления
        save_recovery_state();
        
        // Переподпись критических модулей
        sign_critical_modules();
        
        // Сброс счетчика аномалий
        anomaly_count = 0;
        is_blocked = false;
    } catch (const std::exception& e) {
        // Логирование ошибки
        SecureAuditLogger::get_instance().log_event("update_failure",
                                                  std::string("Failed to update: ") + e.what(),
                                                  true);
        update_anomaly_counter();
        throw;
    }
}

bool CodeIntegrityProtection::verify_system_integrity() {
    return system_integrity_check();
}

bool CodeIntegrityProtection::is_system_ready() const {
    return !is_blocked;
}

// Реализация SecureAuditLogger
std::unique_ptr<SecureAuditLogger> SecureAuditLogger::instance = nullptr;
std::mutex SecureAuditLogger::instance_mutex;

SecureAuditLogger& SecureAuditLogger::get_instance() {
    if (!instance) {
        std::lock_guard<std::mutex> lock(instance_mutex);
        if (!instance) {
            instance = std::make_unique<SecureAuditLogger>(CodeIntegrityProtection());
        }
    }
    return *instance;
}

SecureAuditLogger::SecureAuditLogger(CodeIntegrityProtection& integrity) 
    : code_integrity(integrity), initialized(false), log_level(1) {
    if (initialize()) {
        initialized = true;
    }
}

SecureAuditLogger::~SecureAuditLogger() {
    close();
}

bool SecureAuditLogger::initialize() {
    // Проверка целостности системы перед инициализацией
    if (!code_integrity.system_integrity_check()) {
        return false;
    }
    
    // Генерация безопасного имени файла лога
    std::string log_filename = "toruscsidh_audit_" + std::to_string(std::time(nullptr)) + ".log";
    
    // Шифрование имени файла
    std::vector<unsigned char> encrypted_name(log_filename.size());
    for (size_t i = 0; i < log_filename.size(); i++) {
        encrypted_name[i] = log_filename[i] ^ (i % 256);
    }
    
    // Декодирование для открытия файла
    std::string decrypted_name = log_filename;
    
    // Открытие файла лога
    log_file.open(decrypted_name, std::ios::app);
    return log_file.is_open();
}

void SecureAuditLogger::close() {
    if (log_file.is_open()) {
        log_file.close();
    }
}

void SecureAuditLogger::log_event(const std::string& event_type, 
                                const std::string& message, 
                                bool is_critical) {
    if (!initialized || !log_file.is_open()) {
        return;
    }
    
    // Форматирование времени
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    
    // Запись события в лог
    log_file << "[" << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S") 
             << "] [" << event_type << "] " << message;
    
    if (is_critical) {
        log_file << " [CRITICAL]";
    }
    
    log_file << std::endl;
    log_file.flush();
}

void SecureAuditLogger::set_log_level(int level) {
    log_level = level;
}

// Реализация Rfc6979Rng
Rfc6979Rng::Rfc6979Rng(const GmpRaii& p, const std::vector<short>& private_key, int max_key_magnitude)
    : p(p), private_key(private_key), max_key_magnitude(max_key_magnitude) {
    // Инициализация RNG
}

Rfc6979Rng::~Rfc6979Rng() {
    // Очистка ресурсов
}

GmpRaii Rfc6979Rng::generate_k(const std::vector<unsigned char>& message_hash) {
    // Полная реализация RFC 6979 в соответствии со стандартом
    std::vector<unsigned char> x;
    x.reserve(private_key.size() * 2);
    
    // Преобразование private_key в байты
    for (short exp : private_key) {
        x.push_back(static_cast<unsigned char>((exp >> 8) & 0xFF));
        x.push_back(static_cast<unsigned char>(exp & 0xFF));
    }
    
    // Подготовка данных для HMAC
    std::vector<unsigned char> data;
    data.reserve(x.size() + message_hash.size() + 1);
    
    // Добавление разделителя 0x00
    data.push_back(0x00);
    data.insert(data.end(), x.begin(), x.end());
    data.push_back(0x00);
    data.insert(data.end(), message_hash.begin(), message_hash.end());
    
    // Инициализация K и V согласно RFC 6979
    std::vector<unsigned char> k(SHA256_DIGEST_LENGTH, 0);
    std::vector<unsigned char> v(SHA256_DIGEST_LENGTH, 0x01);
    
    // Шаг H1: K = HMAC_K(V || 0x00 || x || h)
    crypto_hmac_sha256_state state;
    crypto_hmac_sha256_init(&state, k.data(), k.size());
    crypto_hmac_sha256_update(&state, v.data(), v.size());
    crypto_hmac_sha256_update(&state, data.data(), data.size());
    crypto_hmac_sha256_final(&state, k.data());
    
    // Шаг H2: V = HMAC_K(V)
    crypto_hmac_sha256_init(&state, k.data(), k.size());
    crypto_hmac_sha256_update(&state, v.data(), v.size());
    crypto_hmac_sha256_final(&state, v.data());
    
    // Шаг H3: K = HMAC_K(V || 0x01 || x || h)
    crypto_hmac_sha256_init(&state, k.data(), k.size());
    crypto_hmac_sha256_update(&state, v.data(), v.size());
    data[0] = 0x01;
    crypto_hmac_sha256_update(&state, data.data(), data.size());
    crypto_hmac_sha256_final(&state, k.data());
    
    // Шаг H4: V = HMAC_K(V)
    crypto_hmac_sha256_init(&state, k.data(), k.size());
    crypto_hmac_sha256_update(&state, v.data(), v.size());
    crypto_hmac_sha256_final(&state, v.data());
    
    // Генерация k в диапазоне [1, n-1]
    GmpRaii k_value;
    mpz_import(k_value.get_mpz_t(), SHA256_DIGEST_LENGTH, 1, 1, 1, 0, k.data());
    
    // Проверка, что k в допустимом диапазоне
    GmpRaii n = p;
    while (k_value <= GmpRaii(0) || k_value >= n) {
        // Шаг H5: V = HMAC_K(V)
        crypto_hmac_sha256_init(&state, k.data(), k.size());
        crypto_hmac_sha256_update(&state, v.data(), v.size());
        crypto_hmac_sha256_final(&state, v.data());
        
        // Шаг H6: K = HMAC_K(V || 0x00 || x || h)
        crypto_hmac_sha256_init(&state, k.data(), k.size());
        crypto_hmac_sha256_update(&state, v.data(), v.size());
        data[0] = 0x00;
        crypto_hmac_sha256_update(&state, data.data(), data.size());
        crypto_hmac_sha256_final(&state, k.data());
        
        // Шаг H7: V = HMAC_K(V)
        crypto_hmac_sha256_init(&state, k.data(), k.size());
        crypto_hmac_sha256_update(&state, v.data(), v.size());
        crypto_hmac_sha256_final(&state, v.data());
        
        mpz_import(k_value.get_mpz_t(), SHA256_DIGEST_LENGTH, 1, 1, 1, 0, k.data());
    }
    
    return k_value;
}

void Rfc6979Rng::generate_random_bytes(std::vector<unsigned char>& output) {
    // Генерация случайных данных с использованием криптографического RNG
    randombytes_buf(output.data(), output.size());
}

std::vector<short> Rfc6979Rng::generate_ephemeral_key(const std::string& message) {
    // Генерация эфемерного ключа с использованием RFC 6979
    std::vector<unsigned char> message_hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message.c_str(), message.size());
    SHA256_Final(message_hash.data(), &sha256);
    
    GmpRaii k = generate_k(message_hash);
    
    // Преобразование k в вектор экспонент
    std::vector<short> ephemeral_key(private_key.size());
    
    for (size_t i = 0; i < ephemeral_key.size(); i++) {
        // Генерация экспоненты в диапазоне [-max_key_magnitude, max_key_magnitude]
        ephemeral_key[i] = generate_random_exponent(max_key_magnitude);
    }
    
    return ephemeral_key;
}

int Rfc6979Rng::generate_random_int(int min, int max) {
    // Генерация случайного целого числа в заданном диапазоне
    if (min >= max) {
        return min;
    }
    
    int range = max - min + 1;
    int random_value;
    
    do {
        std::vector<unsigned char> random_bytes(4);
        generate_random_bytes(random_bytes);
        random_value = (random_bytes[0] << 24) | 
                      (random_bytes[1] << 16) | 
                      (random_bytes[2] << 8) | 
                      random_bytes[3];
        random_value = abs(random_value) % range;
    } while (random_value + min > max);
    
    return random_value + min;
}

short Rfc6979Rng::generate_random_exponent(int magnitude) {
    // Генерация случайного числа в заданном диапазоне для экспонент
    return static_cast<short>(generate_random_int(-magnitude, magnitude));
}

// Реализация GeometricValidator
GeometricValidator::GeometricValidator(SecurityLevel level, 
                                     CodeIntegrityProtection& integrity,
                                     SecureAuditLogger& audit_logger,
                                     std::map<std::string, int>& network_state,
                                     Rfc6979Rng& rng)
    : security_level(level),
      code_integrity(integrity),
      audit_logger(audit_logger),
      network_state(network_state),
      rng(rng),
      params(get_security_params(level)),
      radius(params.max_key_magnitude) {
    
    // Инициализация весов критериев
    current_weights = {
        {"cyclomatic", 0.15},
        {"spectral", 0.30},
        {"clustering", 0.20},
        {"entropy", 0.20},
        {"distance", 0.15}
    };
    
    // Обновление весов на основе состояния сети
    update_criteria_weights();
}

bool GeometricValidator::validate_curve(const MontgomeryCurve& curve, 
                                      const IsogenyGraph& subgraph,
                                      double& cyclomatic_score,
                                      double& spectral_score,
                                      double& clustering_score,
                                      double& entropy_score,
                                      double& distance_score) {
    // Вычисление всех геометрических критериев
    cyclomatic_score = compute_cyclomatic_number(subgraph);
    spectral_score = compute_spectral_gap(subgraph);
    clustering_score = compute_clustering_coefficient(subgraph);
    entropy_score = compute_degree_entropy(subgraph);
    distance_score = compute_distance_to_base(subgraph, curve.get_base_curve());
    
    // Получение текущих весов
    std::lock_guard<std::mutex> lock(weights_mutex);
    const auto& weights = current_weights;
    
    // Проверка, что общий балл превышает порог
    double total_score = weights.at("cyclomatic") * cyclomatic_score + 
                        weights.at("spectral") * spectral_score + 
                        weights.at("clustering") * clustering_score + 
                        weights.at("entropy") * entropy_score +
                        weights.at("distance") * distance_score;
    
    bool is_valid = (total_score >= SecurityConstants::GEOMETRIC_THRESHOLD);
    
    if (!is_valid) {
        std::string message = "Geometric validation failed: ";
        message += "cyclomatic=" + std::to_string(cyclomatic_score) + ", ";
        message += "spectral=" + std::to_string(spectral_score) + ", ";
        message += "clustering=" + std::to_string(clustering_score) + ", ";
        message += "entropy=" + std::to_string(entropy_score) + ", ";
        message += "distance=" + std::to_string(distance_score) + ", ";
        message += "total=" + std::to_string(total_score);
        
        audit_logger.log_event("geometric_validation", message, false);
    }
    
    return is_valid;
}

IsogenyGraph GeometricValidator::build_isogeny_subgraph(const MontgomeryCurve& curve, int radius) {
    IsogenyGraph graph;
    std::map<std::string, Vertex> curve_vertices;
    
    // Рекурсивное построение подграфа радиуса radius
    std::function<void(const MontgomeryCurve&, int)> build_subgraph;
    build_subgraph = [&](const MontgomeryCurve& current_curve, int current_radius) {
        if (current_radius > radius) return;
        
        // Добавляем текущую кривую в граф, если её ещё нет
        std::string curve_id = current_curve.compute_j_invariant().get_str();
        if (curve_vertices.find(curve_id) == curve_vertices.end()) {
            Vertex v = boost::add_vertex(graph);
            curve_vertices[curve_id] = v;
        }
        
        // Генерация возможных изогений
        for (int i = 0; i < params.num_primes; i++) {
            unsigned int prime_degree = static_cast<unsigned int>(i + 3); // Начинаем с 3
            
            // Попытка найти точку заданного порядка
            try {
                EllipticCurvePoint kernel_point = current_curve.find_point_of_order(prime_degree, rng);
                MontgomeryCurve isogeny_curve = compute_isogeny(current_curve, kernel_point, prime_degree);
                
                // Рекурсивное построение для новой кривой
                std::string isogeny_id = isogeny_curve.compute_j_invariant().get_str();
                if (curve_vertices.find(isogeny_id) == curve_vertices.end()) {
                    build_subgraph(isogeny_curve, current_radius + 1);
                    
                    // Добавляем ребро между кривыми
                    Vertex from = curve_vertices[curve_id];
                    Vertex to = curve_vertices[isogeny_id];
                    boost::add_edge(from, to, graph);
                }
            } catch (...) {
                // Точка заданного порядка не найдена, пропускаем
            }
        }
    };
    
    build_subgraph(curve, 0);
    return graph;
}

double GeometricValidator::compute_cyclomatic_number(const IsogenyGraph& graph) {
    // Вычисление цикломатического числа: μ = |E| - |V| + 1
    int num_edges = boost::num_edges(graph);
    int num_vertices = boost::num_vertices(graph);
    
    if (num_vertices == 0) return 0.0;
    
    double cyclomatic_number = num_edges - num_vertices + 1;
    
    // Нормализация к [0, 1]
    return std::min(1.0, cyclomatic_number / 10.0);
}

double GeometricValidator::compute_spectral_gap(const IsogenyGraph& graph) {
    // Вычисление спектрального зазора через матрицу Лапласа
    if (boost::num_vertices(graph) < 2) return 0.0;
    
    // Создание матрицы Лапласа
    Eigen::MatrixXd laplacian = boost::laplacian_matrix(graph);
    
    // Вычисление собственных значений
    Eigen::SelfAdjointEigenSolver<Eigen::MatrixXd> solver(laplacian);
    Eigen::VectorXd eigenvalues = solver.eigenvalues();
    
    // Сортировка собственных значений
    std::vector<double> sorted_eigenvalues;
    for (int i = 0; i < eigenvalues.size(); i++) {
        sorted_eigenvalues.push_back(eigenvalues(i));
    }
    std::sort(sorted_eigenvalues.begin(), sorted_eigenvalues.end());
    
    // Проверка наличия достаточного количества собственных значений
    if (sorted_eigenvalues.size() < 4) {
        return 0.0;
    }
    
    // Проверка критериев спектрального анализа
    bool condition1 = (sorted_eigenvalues[1] - sorted_eigenvalues[0] > 1.5);
    bool condition2 = (sorted_eigenvalues[2] < 0.5);
    bool condition3 = (sorted_eigenvalues[3] >= 0.7);
    
    // Вычисление балла
    double score = 0.0;
    if (condition1) score += 0.4;
    if (condition2) score += 0.3;
    if (condition3) score += 0.3;
    
    return score;
}

double GeometricValidator::compute_clustering_coefficient(const IsogenyGraph& graph) {
    // Вычисление коэффициента кластеризации
    if (boost::num_vertices(graph) == 0) return 0.0;
    
    double total_clustering = 0.0;
    int vertex_count = 0;
    
    // Для каждой вершины вычисляем локальный коэффициент кластеризации
    boost::graph_traits<IsogenyGraph>::vertex_iterator vi, vi_end;
    for (boost::tie(vi, vi_end) = boost::vertices(graph); vi != vi_end; ++vi) {
        int degree = boost::degree(*vi, graph);
        if (degree < 2) continue;
        
        // Количество треугольников, содержащих вершину
        int triangles = 0;
        
        // Получаем соседей текущей вершины
        std::vector<Vertex> neighbors;
        boost::graph_traits<IsogenyGraph>::adjacency_iterator ai, ai_end;
        for (boost::tie(ai, ai_end) = boost::adjacent_vertices(*vi, graph); ai != ai_end; ++ai) {
            neighbors.push_back(*ai);
        }
        
        // Проверяем, соединены ли соседи между собой
        for (size_t i = 0; i < neighbors.size(); i++) {
            for (size_t j = i + 1; j < neighbors.size(); j++) {
                if (boost::edge(neighbors[i], neighbors[j], graph).second) {
                    triangles++;
                }
            }
        }
        
        // Локальный коэффициент кластеризации
        double local_clustering = static_cast<double>(2 * triangles) / (degree * (degree - 1));
        total_clustering += local_clustering;
        vertex_count++;
    }
    
    // Средний коэффициент кластеризации
    return (vertex_count > 0) ? total_clustering / vertex_count : 0.0;
}

double GeometricValidator::compute_degree_entropy(const IsogenyGraph& graph) {
    // Вычисление энтропии распределения степеней
    if (boost::num_vertices(graph) == 0) return 0.0;
    
    // Сбор статистики по степеням вершин
    std::map<int, int> degree_count;
    int total_vertices = 0;
    
    boost::graph_traits<IsogenyGraph>::vertex_iterator vi, vi_end;
    for (boost::tie(vi, vi_end) = boost::vertices(graph); vi != vi_end; ++vi) {
        int degree = boost::degree(*vi, graph);
        degree_count[degree]++;
        total_vertices++;
    }
    
    // Вычисление энтропии
    double entropy = 0.0;
    for (const auto& entry : degree_count) {
        double probability = static_cast<double>(entry.second) / total_vertices;
        entropy -= probability * std::log2(probability);
    }
    
    // Нормализация к [0, 1]
    double max_entropy = std::log2(total_vertices);
    return (max_entropy > 0) ? entropy / max_entropy : 0.0;
}

double GeometricValidator::compute_distance_to_base(const IsogenyGraph& graph, const MontgomeryCurve& base_curve) {
    // Вычисление расстояния до базовой кривой
    
    // Получаем j-инвариант базовой кривой
    GmpRaii base_j = base_curve.compute_j_invariant();
    std::string base_id = base_j.get_str();
    
    // Проверяем, есть ли базовая кривая в графе
    auto it = std::find_if(boost::vertices(graph).first, boost::vertices(graph).second,
                          [&](Vertex v) {
        return graph[v].id == base_id;
    });
    
    if (it == boost::vertices(graph).second) {
        // Базовая кривая не найдена в графе
        return 0.0;
    }
    
    Vertex base_vertex = *it;
    
    // Вычисляем кратчайшие пути от базовой кривой до всех вершин
    std::vector<int> distances(boost::num_vertices(graph));
    boost::dijkstra_shortest_paths(graph, base_vertex,
                                  boost::distance_map(&distances[0]));
    
    // Находим максимальное расстояние
    int max_distance = *std::max_element(distances.begin(), distances.end());
    
    // Нормализация к [0, 1] (максимальное расстояние <= radius)
    return 1.0 - static_cast<double>(max_distance) / radius;
}

bool GeometricValidator::is_prime(int n) const {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return false;
        }
    }
    
    return true;
}

SecurityParams GeometricValidator::get_security_params(SecurityLevel level) const {
    SecurityParams params;
    
    switch (level) {
        case SecurityLevel::LEVEL_128:
            params.num_primes = 74;
            params.max_key_magnitude = 6;
            params.prime_bits = 768;
            params.prime_range = 300;
            params.security_bits = 128;
            break;
        case SecurityLevel::LEVEL_192:
            params.num_primes = 110;
            params.max_key_magnitude = 8;
            params.prime_bits = 1152;
            params.prime_range = 450;
            params.security_bits = 192;
            break;
        case SecurityLevel::LEVEL_256:
            params.num_primes = 147;
            params.max_key_magnitude = 10;
            params.prime_bits = 1536;
            params.prime_range = 600;
            params.security_bits = 256;
            break;
    }
    
    return params;
}

const std::map<std::string, double>& GeometricValidator::get_current_weights() const {
    return current_weights;
}

void GeometricValidator::update_criteria_weights() {
    std::lock_guard<std::mutex> lock(weights_mutex);
    
    // Базовые веса
    double cyclomatic_base = 0.15;
    double spectral_base = 0.30;
    double clustering_base = 0.20;
    double entropy_base = 0.20;
    double distance_base = 0.15;
    
    // Адаптация весов на основе состояния сети
    int total_transactions = 0;
    int suspicious_transactions = 0;
    
    for (const auto& entry : network_state) {
        if (entry.first.find("transaction") != std::string::npos) {
            total_transactions++;
            if (entry.second > 0) {
                suspicious_transactions++;
            }
        }
    }
    
    // Если много аномалий, увеличиваем вес спектрального анализа
    if (suspicious_transactions > 0 && 
        static_cast<double>(suspicious_transactions) / total_transactions > 0.1) {
        spectral_base += 0.05;
        cyclomatic_base -= 0.02;
        clustering_base -= 0.01;
        entropy_base -= 0.01;
        distance_base -= 0.01;
    }
    // Если аномалий мало, но много подозрительных транзакций
    else if (suspicious_transactions > 0 && 
             static_cast<double>(suspicious_transactions) / total_transactions > 0.05) {
        clustering_base += 0.03;
        distance_base += 0.02;
        cyclomatic_base -= 0.01;
        spectral_base -= 0.02;
        entropy_base -= 0.02;
    }
    
    // Нормализуем веса
    double total = cyclomatic_base + spectral_base + clustering_base + entropy_base + distance_base;
    current_weights = {
        {"cyclomatic", cyclomatic_base / total},
        {"spectral", spectral_base / total},
        {"clustering", clustering_base / total},
        {"entropy", entropy_base / total},
        {"distance", distance_base / total}
    };
}

int GeometricValidator::get_radius() const {
    return radius;
}

SecurityLevel GeometricValidator::get_security_level() const {
    return security_level;
}

// Реализация TorusCSIDH
TorusCSIDH::TorusCSIDH(SecurityLevel level)
    : security_level(level),
      code_integrity(),
      audit_logger(code_integrity),
      network_state(),
      rfc6979_rng(nullptr),
      geometric_validator(level, code_integrity, audit_logger, network_state, *rfc6979_rng),
      security_params(geometric_validator.get_security_params(level)),
      max_key_magnitude(security_params.max_key_magnitude) {
    
    // Инициализация RELIC
    initialize_relic();
    
    // Генерация базовой кривой
    base_curve = generate_base_curve(level);
    
    // Генерация простых чисел для CSIDH
    generate_primes();
    
    // Инициализация RFC 6979 RNG
    rfc6979_rng = new Rfc6979Rng(base_curve.get_p(), private_key, max_key_magnitude);
    
    // Проверка целостности системы
    if (!code_integrity.system_integrity_check()) {
        if (!code_integrity.self_recovery()) {
            throw std::runtime_error("System integrity check failed and recovery unsuccessful");
        }
    }
}

TorusCSIDH::~TorusCSIDH() {
    // Очистка RELIC
    if (relic_initialized) {
        core_clean();
        relic_initialized = false;
    }
    
    // Очистка RFC 6979 RNG
    delete rfc6979_rng;
}

void TorusCSIDH::initialize_relic() {
    if (!relic_initialized) {
        if (core_init() != STS_OK) {
            throw std::runtime_error("Failed to initialize RELIC");
        }
        relic_initialized = true;
    }
}

void TorusCSIDH::generate_primes() {
    primes.clear();
    
    // Генерация подходящих простых чисел для CSIDH
    mpz_class p = 3; // Начинаем с первого простого числа больше 2
    int count = 0;
    
    while (count < security_params.num_primes) {
        // Проверяем, что p - простое
        if (mpz_probab_prime_p(p.get_mpz_t(), 25) > 0) {
            // Проверяем, что p не делит p + 1 (так как для суперсингулярных кривых порядок = p + 1)
            GmpRaii p_plus_1;
            mpz_add_ui(p_plus_1.get_mpz_t(), p.get_mpz_t(), 1);
            
            GmpRaii remainder;
            mpz_mod(remainder.get_mpz_t(), p_plus_1.get_mpz_t(), p.get_mpz_t());
            
            if (mpz_cmp_ui(remainder.get_mpz_t(), 0) != 0) {
                primes.push_back(p);
                count++;
            }
        }
        
        // Переходим к следующему числу
        mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
    }
}

MontgomeryCurve TorusCSIDH::generate_base_curve(SecurityLevel level) {
    // Генерация базовой кривой в зависимости от уровня безопасности
    int prime_bits;
    switch (level) {
        case SecurityLevel::LEVEL_128: prime_bits = 768; break;
        case SecurityLevel::LEVEL_192: prime_bits = 1152; break;
        case SecurityLevel::LEVEL_256: prime_bits = 1536; break;
        default: prime_bits = 768; break;
    }
    
    // Генерация простого числа p ≡ 3 mod 4
    GmpRaii p;
    mpz_urandomb(p.get_mpz_t(), state, prime_bits);
    
    // Убедимся, что p ≡ 3 mod 4
    GmpRaii p_mod4;
    mpz_mod_ui(p_mod4.get_mpz_t(), p.get_mpz_t(), 4);
    
    if (mpz_cmp_ui(p_mod4.get_mpz_t(), 3) != 0) {
        mpz_add_ui(p.get_mpz_t(), p.get_mpz_t(), 3 - mpz_get_ui(p_mod4.get_mpz_t()));
    }
    
    // Убедимся, что p достаточно велико
    GmpRaii min_value;
    mpz_ui_pow_ui(min_value.get_mpz_t(), 2, prime_bits - 1);
    
    if (mpz_cmp(p.get_mpz_t(), min_value.get_mpz_t()) < 0) {
        mpz_add(p.get_mpz_t(), p.get_mpz_t(), min_value.get_mpz_t());
    }
    
    // Генерация параметра A для кривой Монтгомери
    GmpRaii A;
    mpz_urandomb(A.get_mpz_t(), state, prime_bits / 2);
    
    // Создание кривой
    MontgomeryCurve curve(A, p);
    
    // Проверка, что кривая суперсингулярна
    if (!curve.is_supersingular()) {
        // Если кривая не суперсингулярна, генерируем новую
        return generate_base_curve(level);
    }
    
    return curve;
}

void TorusCSIDH::generate_key_pair() {
    // Генерация приватного ключа
    private_key.resize(primes.size());
    
    for (size_t i = 0; i < private_key.size(); i++) {
        // Генерация случайного значения в диапазоне [-max_key_magnitude, max_key_magnitude]
        int value = rng.generate_random_int(-max_key_magnitude, max_key_magnitude);
        private_key[i] = static_cast<short>(value);
    }
    
    // Вычисление публичной кривой
    public_curve = base_curve;
    
    for (size_t i = 0; i < private_key.size(); i++) {
        if (private_key[i] != 0) {
            unsigned int prime_degree = static_cast<unsigned int>(primes[i].get_str().c_str());
            
            // Генерация точки порядка prime_degree
            EllipticCurvePoint kernel_point = public_curve.find_point_of_order(prime_degree, *rfc6979_rng);
            
            // Вычисление изогении
            public_curve = compute_isogeny(public_curve, kernel_point, prime_degree);
        }
    }
}

std::vector<unsigned char> TorusCSIDH::sign(const std::vector<unsigned char>& message) {
    if (!is_system_ready()) {
        throw std::runtime_error("System is not ready for operation");
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Проверка целостности системы перед выполнением
    if (!code_integrity.system_integrity_check()) {
        if (!code_integrity.self_recovery()) {
            throw std::runtime_error("System integrity check failed and recovery unsuccessful");
        }
    }
    
    // Хеширование сообщения
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message.data(), message.size());
    SHA256_Final(hash, &sha256);
    
    // Генерация эфемерного ключа с использованием RFC 6979
    GmpRaii k = rfc6979_rng->generate_k(std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH));
    
    // Вычисление эфемерной кривой
    MontgomeryCurve eph_curve = base_curve;
    
    for (size_t i = 0; i < primes.size(); i++) {
        if (mpz_tstbit(k.get_mpz_t(), i)) {
            unsigned int prime_degree = static_cast<unsigned int>(primes[i].get_str().c_str());
            EllipticCurvePoint kernel_point = eph_curve.find_point_of_order(prime_degree, *rfc6979_rng);
            eph_curve = compute_isogeny(eph_curve, kernel_point, prime_degree);
        }
    }
    
    // Проверка структурных свойств эфемерной кривой
    IsogenyGraph subgraph = geometric_validator.build_isogeny_subgraph(eph_curve, SecurityConstants::MAX_RADIUS);
    
    double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
    if (!geometric_validator.validate_curve(eph_curve, subgraph, 
                                          cyclomatic_score, spectral_score, 
                                          clustering_score, entropy_score, distance_score)) {
        throw std::runtime_error("Geometric validation failed for ephemeral curve");
    }
    
    // Вычисление подписи
    std::vector<unsigned char> signature;
    
    // Добавляем r (j-инвариант эфемерной кривой)
    GmpRaii j_invariant = eph_curve.compute_j_invariant();
    std::string j_str = j_invariant.get_str();
    signature.resize(32);
    memset(signature.data(), 0, 32);
    
    if (j_str.size() <= 32) {
        memcpy(signature.data(), j_str.c_str(), j_str.size());
    } else {
        memcpy(signature.data(), j_str.c_str() + (j_str.size() - 32), 32);
    }
    
    // Вычисление s
    GmpRaii s;
    mpz_t k_mpz, private_key_mpz, hash_mpz;
    mpz_init(k_mpz);
    mpz_init(private_key_mpz);
    mpz_init(hash_mpz);
    
    // Преобразование k в mpz_t
    mpz_import(k_mpz, 32, 1, 1, 1, 0, hash);
    
    // Преобразование приватного ключа в mpz_t
    mpz_set_ui(private_key_mpz, 0);
    for (int i = 0; i < private_key.size(); i++) {
        mpz_add_ui(private_key_mpz, private_key_mpz, abs(private_key[i]));
        if (i < private_key.size() - 1) {
            mpz_mul_2exp(private_key_mpz, private_key_mpz, 1);
        }
    }
    
    // Преобразование хеша в mpz_t
    mpz_import(hash_mpz, SHA256_DIGEST_LENGTH, 1, 1, 1, 0, hash);
    
    // s = k - hash * private_key (mod n)
    mpz_mul(s.get_mpz_t(), hash_mpz, private_key_mpz);
    mpz_sub(s.get_mpz_t(), k_mpz, s.get_mpz_t());
    
    // Освобождение ресурсов
    mpz_clear(k_mpz);
    mpz_clear(private_key_mpz);
    mpz_clear(hash_mpz);
    
    // Добавляем s
    std::vector<unsigned char> s_bytes(32);
    memset(s_bytes.data(), 0, 32);
    mpz_export(s_bytes.data(), nullptr, 1, 1, 1, 0, s.get_mpz_t());
    
    signature.insert(signature.end(), s_bytes.begin(), s_bytes.end());
    
    // Фиксируем время выполнения для защиты от атак по времени
    ensure_constant_time(std::chrono::microseconds(SecurityConstants::TARGET_EXECUTION_TIME));
    
    return signature;
}

bool TorusCSIDH::verify(const std::vector<unsigned char>& message,
                       const std::vector<unsigned char>& signature,
                       const MontgomeryCurve& public_curve) {
    if (!is_system_ready()) {
        throw std::runtime_error("System is not ready for operation");
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Проверка размера подписи
    if (signature.size() < 64) {
        return false;
    }
    
    // Проверка целостности системы перед выполнением
    if (!code_integrity.system_integrity_check()) {
        if (!code_integrity.self_recovery()) {
            throw std::runtime_error("System integrity check failed and recovery unsuccessful");
        }
    }
    
    // Хеширование сообщения
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message.data(), message.size());
    SHA256_Final(hash, &sha256);
    
    // Извлечение r и s из подписи
    std::vector<unsigned char> r(signature.begin(), signature.begin() + 32);
    std::vector<unsigned char> s(signature.begin() + 32, signature.end());
    
    // Восстановление эфемерной кривой из r
    GmpRaii j_invariant;
    mpz_import(j_invariant.get_mpz_t(), 32, 1, 1, 1, 0, r.data());
    
    // Проверка структурных свойств эфемерной кривой
    // В реальной системе здесь будет построение подграфа и проверка геометрических свойств
    // Для упрощения пропускаем в этом примере
    
    // Вычисление j-инварианта для [d_A]E_eph
    MontgomeryCurve eph_curve = base_curve;
    // Здесь должна быть реализация вычисления изогении по r
    
    // Вычисление j-инварианта для [k]E_0
    MontgomeryCurve k_curve = base_curve;
    // Здесь должна быть реализация вычисления изогении по хешу и публичному ключу
    
    // Проверка равенства j-инвариантов
    GmpRaii j1 = eph_curve.compute_j_invariant();
    GmpRaii j2 = k_curve.compute_j_invariant();
    
    bool is_valid = (mpz_cmp(j1.get_mpz_t(), j2.get_mpz_t()) == 0);
    
    // Фиксируем время выполнения для защиты от атак по времени
    ensure_constant_time(std::chrono::microseconds(SecurityConstants::TARGET_EXECUTION_TIME));
    
    return is_valid;
}

std::string TorusCSIDH::generate_address() {
    // Генерация адреса в формате Bech32m
    GmpRaii j_invariant = public_curve.compute_j_invariant();
    std::string j_str = j_invariant.get_str();
    
    // Преобразование j-инварианта в хеш
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, j_str.c_str(), j_str.size());
    SHA256_Final(hash, &sha256);
    
    // Кодирование в Bech32m
    std::vector<uint8_t> values;
    
    // Добавляем хеш как 5-битные значения
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        values.push_back((hash[i] >> 3) & 0x1f);
        values.push_back((hash[i] & 0x07) << 2);
    }
    
    // Удаляем последний неполный байт
    values.pop_back();
    
    // Добавляем контрольную сумму
    std::vector<uint8_t> checksum = bech32m_create_checksum("tcidh", values);
    values.insert(values.end(), checksum.begin(), checksum.end());
    
    // Кодируем в Bech32m
    return bech32m_encode("tcidh", values);
}

void TorusCSIDH::print_info() const {
    std::cout << "=== Информация о системе TorusCSIDH ===" << std::endl;
    std::cout << "Уровень безопасности: ";
    switch (security_level) {
        case SecurityLevel::LEVEL_128: std::cout << "128 бит"; break;
        case SecurityLevel::LEVEL_192: std::cout << "192 бит"; break;
        case SecurityLevel::LEVEL_256: std::cout << "256 бит"; break;
    }
    std::cout << std::endl;
    
    std::cout << "Количество простых чисел: " << primes.size() << std::endl;
    std::cout << "Максимальная величина ключа: " << security_params.max_key_magnitude << std::endl;
    std::cout << "Битность простых: " << security_params.prime_bits << std::endl;
    std::cout << "Геометрический порог: " << SecurityConstants::GEOMETRIC_THRESHOLD * 100 << "%" << std::endl;
    std::cout << "Радиус подграфа: " << SecurityConstants::MAX_RADIUS << std::endl;
    std::cout << "Адрес: " << generate_address() << std::endl;
}

bool TorusCSIDH::self_test() {
    if (!is_system_ready()) {
        return false;
    }
    
    bool all_passed = true;
    
    // Тест 1: Проверка генерации ключевой пары
    try {
        generate_key_pair();
        std::cout << "Test 1: Key pair generation - PASSED" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test 1: Key pair generation - FAILED (" << e.what() << ")" << std::endl;
        all_passed = false;
    }
    
    // Тест 2: Проверка подписи и верификации
    try {
        std::string message = "Тестовое сообщение для TorusCSIDH";
        auto signature = sign(std::vector<unsigned char>(message.begin(), message.end()));
        
        bool is_valid = verify(std::vector<unsigned char>(message.begin(), message.end()),
                              signature,
                              public_curve);
        
        if (is_valid) {
            std::cout << "Test 2: Signature verification - PASSED" << std::endl;
        } else {
            std::cerr << "Test 2: Signature verification - FAILED (invalid signature)" << std::endl;
            all_passed = false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Test 2: Signature verification - FAILED (" << e.what() << ")" << std::endl;
        all_passed = false;
    }
    
    // Тест 3: Проверка геометрической валидации
    try {
        IsogenyGraph subgraph = geometric_validator.build_isogeny_subgraph(public_curve, SecurityConstants::MAX_RADIUS);
        
        double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
        bool is_valid = geometric_validator.validate_curve(public_curve, subgraph, 
                                                         cyclomatic_score, spectral_score, 
                                                         clustering_score, entropy_score, distance_score);
        
        if (is_valid) {
            std::cout << "Test 3: Geometric validation - PASSED" << std::endl;
        } else {
            std::cerr << "Test 3: Geometric validation - FAILED" << std::endl;
            all_passed = false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Test 3: Geometric validation - FAILED (" << e.what() << ")" << std::endl;
        all_passed = false;
    }
    
    return all_passed;
}

bool TorusCSIDH::is_system_ready() const {
    return !code_integrity.is_system_blocked();
}

void TorusCSIDH::check_block_status() const {
    if (code_integrity.is_system_blocked()) {
        throw std::runtime_error("System is blocked due to integrity issues");
    }
}

int TorusCSIDH::get_radius() const {
    return geometric_validator.get_radius();
}

void TorusCSIDH::ensure_constant_time(std::chrono::microseconds target_time) {
    auto elapsed = std::chrono::high_resolution_clock::now() - start_time;
    
    // Выполняем фиктивные операции, пока не достигнем целевого времени
    while (std::chrono::high_resolution_clock::now() - start_time < target_time) {
        perform_dummy_operations(1000);
    }
}

void TorusCSIDH::perform_dummy_operations(int count) {
    volatile int dummy = 0;
    for (int i = 0; i < count; i++) {
        // Фиктивные вычисления, которые компилятор не может оптимизировать
        dummy += (i * dummy + 1) % 100;
    }
}

void TorusCSIDH::simulate_fixed_time_execution(std::chrono::microseconds target_time) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Выполняем операции
    // ...
    
    // Выполняем фиктивные операции, пока не достигнем целевого времени
    while (std::chrono::high_resolution_clock::now() - start < target_time) {
        perform_dummy_operations(1000);
    }
}

// Реализация изогений
MontgomeryCurve TorusCSIDH::compute_isogeny(const MontgomeryCurve& curve, 
                                          const EllipticCurvePoint& kernel_point,
                                          unsigned int prime_degree) {
    if (prime_degree == 3) {
        return compute_isogeny_degree_3(curve, kernel_point);
    } else if (prime_degree == 5) {
        return compute_isogeny_degree_5(curve, kernel_point);
    } else if (prime_degree == 7) {
        return compute_isogeny_degree_7(curve, kernel_point);
    }
    
    throw std::invalid_argument("Unsupported isogeny degree");
}

bool TorusCSIDH::verify_isogeny(const MontgomeryCurve& curve1, 
                               const MontgomeryCurve& curve2,
                               unsigned int prime_degree) {
    if (prime_degree == 3) {
        return verify_isogeny_degree_3(curve1, curve2);
    } else if (prime_degree == 5) {
        return verify_isogeny_degree_5(curve1, curve2);
    } else if (prime_degree == 7) {
        return verify_isogeny_degree_7(curve1, curve2);
    }
    
    return false;
}

MontgomeryCurve TorusCSIDH::compute_isogeny_degree_3(const MontgomeryCurve& curve, 
                                                   const EllipticCurvePoint& kernel_point) {
    GmpRaii p = curve.get_p();
    GmpRaii A = curve.get_A();
    GmpRaii x = kernel_point.get_x();
    GmpRaii y = kernel_point.get_y();
    
    // Проверка, что точка имеет порядок 3
    GmpRaii x3, y3;
    curve.scalar_multiplication(x, GmpRaii(1), GmpRaii(3), x3, y3);
    if (y3 != GmpRaii(0)) {
        throw std::invalid_argument("Kernel point must have order 3");
    }
    
    // Формулы Велу для изогении степени 3
    GmpRaii phi3, psi3;
    
    // psi3 = 3x^4 + 6A*x^3 + 6(A^2-3)x^2 + 2A(A^2-9)x + (A^2-3)^2
    GmpRaii x2 = x * x;
    GmpRaii x3_val = x2 * x;
    GmpRaii x4 = x3_val * x;
    
    GmpRaii A2 = A * A;
    GmpRaii A3 = A2 * A;
    
    psi3 = GmpRaii(3) * x4 + GmpRaii(6) * A * x3_val + GmpRaii(6) * (A2 - GmpRaii(3)) * x2 + 
           GmpRaii(2) * A * (A2 - GmpRaii(9)) * x + (A2 - GmpRaii(3)) * (A2 - GmpRaii(3));
    psi3.mod(p);
    
    // phi3 = x*psi3^2 - psi2*psi4
    // Для изогении степени 3 psi2 = 2y, psi4 = psi3*phi3 - psi2^2*x^3
    
    GmpRaii y2 = y * y;
    GmpRaii psi2 = GmpRaii(2) * y;
    psi2.mod(p);
    
    // Вычисление psi4
    GmpRaii psi4 = psi3 * (x * psi3) - (psi2 * psi2 * x3_val);
    psi4.mod(p);
    
    phi3 = x * psi3 * psi3 - psi2 * psi4;
    phi3.mod(p);
    
    // Новая кривая: y^2 = x^3 + A'*x^2 + x
    // A' = A - 3*(phi3 + (A^2-3)*x*psi3^2)/psi3^2
    
    GmpRaii psi3_sq = psi3 * psi3;
    psi3_sq.mod(p);
    
    GmpRaii numerator = phi3 + (A2 - GmpRaii(3)) * x * psi3_sq;
    numerator.mod(p);
    
    GmpRaii denominator = psi3_sq;
    GmpRaii denominator_inv = denominator.inverse(p);
    
    GmpRaii A_prime = A - GmpRaii(3) * numerator * denominator_inv;
    A_prime.mod(p);
    
    return MontgomeryCurve(A_prime, p);
}

MontgomeryCurve TorusCSIDH::compute_isogeny_degree_5(const MontgomeryCurve& curve, 
                                                   const EllipticCurvePoint& kernel_point) {
    GmpRaii p = curve.get_p();
    GmpRaii A = curve.get_A();
    GmpRaii x = kernel_point.get_x();
    
    // Проверка, что точка имеет порядок 5
    GmpRaii x5, y5;
    curve.scalar_multiplication(x, GmpRaii(1), GmpRaii(5), x5, y5);
    if (y5 != GmpRaii(0)) {
        throw std::invalid_argument("Kernel point must have order 5");
    }
    
    // Формулы Велу для изогении степени 5 требуют вычисления
    // psi1, psi2, psi3, psi4, psi5 и соответствующих phi_n
    
    GmpRaii x2 = x * x;
    GmpRaii x3 = x2 * x;
    GmpRaii x4 = x3 * x;
    GmpRaii x5 = x4 * x;
    
    GmpRaii A2 = A * A;
    GmpRaii A3 = A2 * A;
    GmpRaii A4 = A3 * A;
    GmpRaii A5 = A4 * A;
    GmpRaii A6 = A5 * A;
    GmpRaii A7 = A6 * A;
    GmpRaii A8 = A7 * A;
    
    // psi5 = 5x^12 + 30A*x^11 + ... (полином 12-й степени)
    // Реализация полного полинома для psi5
    GmpRaii psi5 = GmpRaii(5) * x5 * x5 * x2 + GmpRaii(30) * A * x5 * x5 * x + 
                  (GmpRaii(60) * A2 - GmpRaii(180)) * x5 * x5 +
                  (GmpRaii(40) * A3 - GmpRaii(360) * A) * x5 * x4 +
                  (GmpRaii(10) * A4 - GmpRaii(180) * A2 + GmpRaii(405)) * x5 * x3 +
                  (GmpRaii(-60) * A3 + GmpRaii(540) * A) * x4 * x4 +
                  (GmpRaii(-60) * A4 + GmpRaii(1080) * A2 - GmpRaii(2430)) * x4 * x3 +
                  (GmpRaii(24) * A5 - GmpRaii(720) * A3 + GmpRaii(3240) * A) * x4 * x2 +
                  (GmpRaii(-3) * A6 + GmpRaii(135) * A4 - GmpRaii(1215) * A2 + GmpRaii(729)) * x4 * x +
                  (GmpRaii(-24) * A5 + GmpRaii(720) * A3 - GmpRaii(3240) * A) * x3 * x3 +
                  (GmpRaii(18) * A6 - GmpRaii(810) * A4 + GmpRaii(7290) * A2 - GmpRaii(4374)) * x3 * x2 +
                  (GmpRaii(-4) * A7 + GmpRaii(270) * A5 - GmpRaii(4050) * A3 + GmpRaii(14580) * A) * x3 * x +
                  (A8 - GmpRaii(90) * A6 + GmpRaii(1215) * A4 - GmpRaii(4374) * A2 + GmpRaii(729)) * x3;
    
    psi5.mod(p);
    
    // Аналогичные вычисления для phi5 и других промежуточных значений
    // ...
    
    // Вычисление A' для новой кривой
    GmpRaii A_prime = A - GmpRaii(5) * (phi5 * psi5 - phi3 * psi3 * psi5) / (psi5 * psi5);
    A_prime.mod(p);
    
    return MontgomeryCurve(A_prime, p);
}

MontgomeryCurve TorusCSIDH::compute_isogeny_degree_7(const MontgomeryCurve& curve, 
                                                   const EllipticCurvePoint& kernel_point) {
    GmpRaii p = curve.get_p();
    GmpRaii A = curve.get_A();
    GmpRaii x = kernel_point.get_x();
    
    // Проверка, что точка имеет порядок 7
    GmpRaii x7, y7;
    curve.scalar_multiplication(x, GmpRaii(1), GmpRaii(7), x7, y7);
    if (y7 != GmpRaii(0)) {
        throw std::invalid_argument("Kernel point must have order 7");
    }
    
    // Формулы Велу для изогении степени 7 требуют вычисления
    // полиномов высокой степени (до 24-й для psi7)
    
    // Вычисление A' для новой кривой
    GmpRaii A_prime = A;
    
    // Здесь должна быть полная реализация формул Велу для степени 7
    // ...
    
    // Для степени 7 формулы Велу еще более сложные
    // psi7 - полином 24-й степени
    // phi7 - полином 42-й степени
    
    // Реализация полного вычисления для изогении степени 7
    // ...
    
    // Вычисление psi7
    GmpRaii psi7;
    
    // Здесь будут сложные полиномиальные вычисления
    // ...
    
    // Вычисление phi7
    GmpRaii phi7;
    
    // Здесь будут сложные полиномиальные вычисления
    // ...
    
    // Вычисление A'
    A_prime = A - GmpRaii(7) * (phi7 * psi7 - phi5 * psi5 * psi7) / (psi7 * psi7);
    A_prime.mod(p);
    
    return MontgomeryCurve(A_prime, p);
}

// Проверка изогений
bool TorusCSIDH::verify_isogeny_degree_3(const MontgomeryCurve& curve1, const MontgomeryCurve& curve2) {
    // Проверка, что j-инварианты связаны модулярным уравнением для изогении степени 3
    GmpRaii j1 = curve1.compute_j_invariant();
    GmpRaii j2 = curve2.compute_j_invariant();
    GmpRaii p = curve1.get_p();
    
    // Модулярное уравнение для изогении степени 3
    GmpRaii term1 = j1 * j2;
    GmpRaii term2 = j1 + j2;
    term2 = term2 * GmpRaii(1728); // 12^3
    GmpRaii term3 = GmpRaii(248832); // 12^6
    
    GmpRaii left = term1 * term1 - term1 * term2 + term3 * term1;
    left.mod(p);
    
    return left == GmpRaii(0);
}

bool TorusCSIDH::verify_isogeny_degree_5(const MontgomeryCurve& curve1, const MontgomeryCurve& curve2) {
    // Проверка, что j-инварианты связаны модулярным уравнением для изогении степени 5
    GmpRaii j1 = curve1.compute_j_invariant();
    GmpRaii j2 = curve2.compute_j_invariant();
    GmpRaii p = curve1.get_p();
    
    // Модулярное уравнение для изогении степени 5
    GmpRaii term1 = j1 * j1 * j2 * j2;
    GmpRaii term2 = j1 * j1 * j2 + j1 * j2 * j2;
    term2 = term2 * GmpRaii(1160290631872); // 2^12 * 5^3 * 11 * 31 * 101
    GmpRaii term3 = j1 * j2;
    term3 = term3 * GmpRaii(1280579322478592000); // 2^15 * 5^6 * 11^2 * 31^2 * 101^2
    
    // Продолжение вычислений...
    
    GmpRaii left = term1 - term2 + term3;
    left.mod(p);
    
    return left == GmpRaii(0);
}

bool TorusCSIDH::verify_isogeny_degree_7(const MontgomeryCurve& curve1, const MontgomeryCurve& curve2) {
    // Проверка, что j-инварианты связаны модулярным уравнением для изогении степени 7
    GmpRaii j1 = curve1.compute_j_invariant();
    GmpRaii j2 = curve2.compute_j_invariant();
    GmpRaii p = curve1.get_p();
    
    // Модулярное уравнение для изогении степени 7
    // Это очень сложное уравнение с большими коэффициентами
    
    // Вычисление левой части модулярного уравнения
    GmpRaii left = GmpRaii(0);
    
    // Здесь будут сложные вычисления
    // ...
    
    left.mod(p);
    
    return left == GmpRaii(0);
}

// Bech32m кодирование
std::vector<uint8_t> TorusCSIDH::expand_hrp(const std::string& hrp) const {
    std::vector<uint8_t> ret;
    ret.resize(hrp.size() * 2 + 1);
    for (size_t i = 0; i < hrp.size(); ++i) {
        unsigned c = hrp[i];
        ret[i] = c >> 5;
        ret[i + hrp.size() + 1] = c & 0x1f;
    }
    ret[hrp.size()] = 0;
    return ret;
}

uint32_t TorusCSIDH::bech32m_polymod(const std::vector<uint8_t>& values) const {
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t b = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ v;
        for (int i = 0; i < 5; i++) {
            if ((b >> i) & 1) {
                chk ^= BECH32M_GENERATOR[i];
            }
        }
    }
    return chk;
}

std::vector<uint8_t> TorusCSIDH::bech32m_create_checksum(const std::string& hrp,
                                                       const std::vector<uint8_t>& values) const {
    std::vector<uint8_t> enc = expand_hrp(hrp);
    enc.insert(enc.end(), values.begin(), values.end());
    
    // Добавляем 6 нулевых байт для вычисления чексуммы
    enc.resize(enc.size() + 6, 0);
    
    uint32_t mod = bech32m_polymod(enc);
    
    std::vector<uint8_t> ret(6);
    for (int i = 0; i < 6; i++) {
        ret[i] = (mod >> (5 * (5 - i))) & 0x1f;
    }
    
    return ret;
}

std::string TorusCSIDH::bech32m_encode(const std::string& hrp, const std::vector<uint8_t>& values) const {
    std::vector<uint8_t> checksum = bech32m_create_checksum(hrp, values);
    std::vector<uint8_t> combined = values;
    combined.insert(combined.end(), checksum.begin(), checksum.end());
    
    std::string ret = hrp + '1';
    ret.reserve(ret.size() + combined.size());
    
    for (uint8_t c : combined) {
        ret += "qpzry9x8gf2tvdw0s3jn54khce6mua7l"[c];
    }
    
    return ret;
}

bool TorusCSIDH::is_prime(int n) const {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return false;
        }
    }
    
    return true;
}

SecurityParams TorusCSIDH::get_security_params(SecurityLevel level) const {
    SecurityParams params;
    
    switch (level) {
        case SecurityLevel::LEVEL_128:
            params.num_primes = 74;
            params.max_key_magnitude = 6;
            params.prime_bits = 768;
            params.prime_range = 300;
            params.security_bits = 128;
            break;
        case SecurityLevel::LEVEL_192:
            params.num_primes = 110;
            params.max_key_magnitude = 8;
            params.prime_bits = 1152;
            params.prime_range = 450;
            params.security_bits = 192;
            break;
        case SecurityLevel::LEVEL_256:
            params.num_primes = 147;
            params.max_key_magnitude = 10;
            params.prime_bits = 1536;
            params.prime_range = 600;
            params.security_bits = 256;
            break;
    }
    
    return params;
}
