#ifndef TORUSCSIDH_H
#define TORUSCSIDH_H

#include <vector>
#include <string>
#include <chrono>
#include <gmpxx.h>
#include <sodium.h>
#include "security_constants.h"
#include "secure_random.h"
#include "postquantum_hash.h"
#include "rfc6979_rng.h"
#include "elliptic_curve.h"
#include "geometric_validator.h"
#include "code_integrity.h"
#include "secure_audit_logger.h"

/**
 * @brief Параметры CSIDH
 */
struct CSIDHParameters {
    std::vector<GmpRaii> primes;  ///< Простые числа для изогений
    int security_bits;            ///< Уровень безопасности в битах
    size_t num_primes;            ///< Количество простых чисел
    int max_key_magnitude;        ///< Максимальная величина ключа
};

/**
 * @brief Основной класс для реализации TorusCSIDH
 */
class TorusCSIDH {
public:
    /**
     * @brief Конструктор
     * @param security_level Уровень безопасности
     */
    TorusCSIDH(SecurityConstants::SecurityLevel security_level = SecurityConstants::SecurityLevel::LEVEL_128);
    
    /**
     * @brief Деструктор
     */
    ~TorusCSIDH();
    
    /**
     * @brief Инициализация системы
     */
    void initialize();
    
    /**
     * @brief Генерация ключевой пары
     */
    void generate_key_pair();
    
    /**
     * @brief Подпись сообщения
     * @param message Сообщение
     * @return Подпись
     */
    std::vector<unsigned char> sign(const std::vector<unsigned char>& message);
    
    /**
     * @brief Проверка подписи
     * @param message Сообщение
     * @param signature Подпись
     * @return true, если подпись верна
     */
    bool verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature);
    
    /**
     * @brief Генерация адреса в формате Bech32m
     * @return Адрес
     */
    std::string generate_address();
    
    /**
     * @brief Печать информации о системе
     */
    void print_info() const;
    
    /**
     * @brief Проверка, готова ли система к работе
     * @return true, если система готова
     */
    bool is_system_ready() const;
    
    /**
     * @brief Получение публичной кривой
     * @return Публичная кривая
     */
    const MontgomeryCurve& get_public_curve() const;
    
    /**
     * @brief Получение приватного ключа
     * @return Приватный ключ
     */
    const std::vector<short>& get_private_key() const;
    
    /**
     * @brief Получение параметров CSIDH
     * @return Параметры CSIDH
     */
    const CSIDHParameters& get_params() const;
    
    /**
     * @brief Получение генератора случайных чисел RFC 6979
     * @return Указатель на генератор
     */
    Rfc6979Rng* get_rfc6979_rng() const;
    
    /**
     * @brief Получение кода целостности
     * @return Ссылка на код целостности
     */
    CodeIntegrityProtection& get_code_integrity();
    
    /**
     * @brief Получение простых чисел
     * @return Вектор простых чисел
     */
    const std::vector<GmpRaii>& get_primes() const;
    
    /**
     * @brief Проверка, является ли ключ "малым"
     * @param key Ключ
     * @return true, если ключ "малый"
     */
    bool is_small_key(const GmpRaii& key) const;
    
    /**
     * @brief Проверка на слабые ключи
     * @return true, если ключ слабый
     */
    bool is_weak_key() const;
    
    /**
     * @brief Проверка, является ли ключ безопасным
     * @return true, если ключ безопасен
     */
    bool is_secure_key() const;
    
    /**
     * @brief Обеспечение постоянного времени выполнения
     * @param target_time Целевое время выполнения
     */
    void ensure_constant_time(const std::chrono::microseconds& target_time);
    
    /**
     * @brief Вычисление изогении заданной степени
     * @param curve Базовая кривая
     * @param kernel_point Точка ядра
     * @param degree Степень изогении
     * @return Новая кривая после изогении
     */
    MontgomeryCurve compute_isogeny(const MontgomeryCurve& curve, 
                                  const EllipticCurvePoint& kernel_point, 
                                  unsigned int degree) const;
    
    /**
     * @brief Вычисление изогении степени 7
     * @param curve Базовая кривая
     * @param kernel_point Точка ядра
     * @return Новая кривая после изогении
     */
    MontgomeryCurve compute_isogeny_degree_7(const MontgomeryCurve& curve,
                                           const EllipticCurvePoint& kernel_point) const;
    
    /**
     * @brief Преобразование приватного ключа в GMP ключ
     * @param private_key Приватный ключ
     * @return GMP ключ
     */
    GmpRaii convert_to_gmp_key(const std::vector<short>& private_key) const;

private:
    SecurityConstants::SecurityLevel security_level;  ///< Уровень безопасности
    MontgomeryCurve base_curve;                       ///< Базовая кривая
    MontgomeryCurve public_curve;                     ///< Публичная кривая
    std::vector<short> private_key;                   ///< Приватный ключ
    CSIDHParameters params;                           ///< Параметры CSIDH
    Rfc6979Rng* rfc6979_rng;                          ///< Генератор RFC 6979
    bool initialized;                                 ///< Флаг инициализации
    std::chrono::high_resolution_clock::time_point start_time; ///< Время начала операции
    CodeIntegrityProtection code_integrity;           ///< Система целостности
    GeometricValidator geometric_validator;           ///< Геометрический валидатор
    
    /**
     * @brief Генерация простых чисел для CSIDH
     */
    void generate_primes();
    
    /**
     * @brief Инициализация RELIC
     */
    void initialize_relic();
    
    /**
     * @brief Очистка RELIC
     */
    void cleanup_relic();
};

#endif // TORUSCSIDH_H
