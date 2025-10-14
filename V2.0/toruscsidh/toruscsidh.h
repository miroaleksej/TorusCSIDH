#ifndef TORUSCSIDH_H
#define TORUSCSIDH_H

#include <vector>
#include <gmpxx.h>
#include <chrono>
#include <mutex>
#include <memory>
#include <map>
#include "elliptic_curve.h"
#include "geometric_validator.h"
#include "rfc6979_rng.h"
#include "code_integrity.h"
#include "security_constants.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

/**
 * @brief Класс для реализации постквантовой криптосистемы TorusCSIDH
 * 
 * Реализует безопасную постквантовую криптосистему на основе суперсингулярных изогений.
 * Включает геометрическую проверку для защиты от атак через поддельные кривые.
 */
class TorusCSIDH {
public:
    /**
     * @brief Конструктор
     * 
     * @param security_level Уровень безопасности
     */
    explicit TorusCSIDH(SecurityConstants::SecurityLevel security_level);
    
    /**
     * @brief Деструктор
     */
    ~TorusCSIDH();
    
    /**
     * @brief Генерация ключевой пары
     * 
     * Генерирует приватный и публичный ключи.
     */
    void generate_key_pair();
    
    /**
     * @brief Подпись сообщения
     * 
     * Подписывает сообщение с использованием приватного ключа.
     * 
     * @param message Сообщение для подписи
     * @return Подпись
     */
    std::vector<unsigned char> sign(const std::vector<unsigned char>& message);
    
    /**
     * @brief Верификация подписи
     * 
     * Проверяет подпись сообщения с использованием публичного ключа.
     * 
     * @param message Сообщение
     * @param signature Подпись
     * @return true, если подпись верна
     */
    bool verify(const std::vector<unsigned char>& message, 
                const std::vector<unsigned char>& signature);
    
    /**
     * @brief Генерация адреса
     * 
     * Генерирует адрес в формате Bech32m.
     * 
     * @return Адрес
     */
    std::string generate_address();
    
    /**
     * @brief Печать информации о системе
     */
    void print_info() const;
    
    /**
     * @brief Проверка, готова ли система к работе
     * 
     * @return true, если система готова к работе
     */
    bool is_system_ready() const;
    
    /**
     * @brief Получение публичной кривой
     * 
     * @return Публичная кривая
     */
    const MontgomeryCurve& get_public_curve() const;
    
    /**
     * @brief Получение приватного ключа
     * 
     * @return Приватный ключ
     */
    const std::vector<short>& get_private_key() const;
    
    /**
     * @brief Получение системы проверки целостности
     * 
     * @return Система проверки целостности
     */
    CodeIntegrityProtection& get_code_integrity();
    
    /**
     * @brief Получение системы проверки целостности (константная версия)
     * 
     * @return Система проверки целостности
     */
    const CodeIntegrityProtection& get_code_integrity() const;
    
    /**
     * @brief Проверка целостности ключа
     * 
     * @return true, если ключ цел
     */
    bool verify_key_integrity() const;
    
    /**
     * @brief Проверка, является ли ключ "малым"
     * 
     * @return true, если ключ "малый"
     */
    bool is_small_key() const;
    
    /**
     * @brief Проверка на слабые ключи
     * 
     * @return true, если ключ слабый
     */
    bool is_weak_key() const;
    
    /**
     * @brief Проверка, является ли ключ безопасным
     * 
     * @return true, если ключ безопасен
     */
    bool is_secure_key() const;
    
    /**
     * @brief Обеспечение постоянного времени выполнения
     * 
     * @param target_time Целевое время выполнения
     */
    void ensure_constant_time(const std::chrono::microseconds& target_time);
    
    /**
     * @brief Проверка на наличие регулярных паттернов в ключе
     * 
     * @return true, если паттерны обнаружены
     */
    bool has_regular_patterns() const;
    
    /**
     * @brief Проверка, уязвим ли ключ к атаке через длинный путь
     * 
     * @return true, если ключ уязвим
     */
    bool is_vulnerable_to_long_path_attack() const;
    
    /**
     * @brief Проверка, уязвим ли ключ к атаке через вырожденную топологию
     * 
     * @return true, если ключ уязвим
     */
    bool is_vulnerable_to_degenerate_topology_attack() const;
    
    /**
     * @brief Вычисление изогении заданной степени
     * 
     * @param curve Базовая кривая
     * @param kernel_point Точка ядра
     * @param degree Степень изогении
     * @return Результирующая кривая
     */
    MontgomeryCurve compute_isogeny(const MontgomeryCurve& curve,
                                  const EllipticCurvePoint& kernel_point,
                                  unsigned int degree) const;
    
    /**
     * @brief Проверка, что кривая принадлежит графу изогений
     * 
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @param primes Простые числа для изогений
     * @return true, если кривая принадлежит графу изогений
     */
    bool is_curve_in_isogeny_graph(const MontgomeryCurve& base_curve,
                                  const MontgomeryCurve& target_curve,
                                  const std::vector<GmpRaii>& primes) const;
    
    /**
     * @brief Проверка модулярного уравнения для изогении степени 3
     * 
     * @param j1 Первый j-инвариант
     * @param j2 Второй j-инвариант
     * @param p Простое число характеристики поля
     * @return true, если модулярное уравнение выполняется
     */
    bool verify_modular_equation_degree_3(const GmpRaii& j1, const GmpRaii& j2, const GmpRaii& p) const;
    
    /**
     * @brief Проверка модулярного уравнения для изогении степени 5
     * 
     * @param j1 Первый j-инвариант
     * @param j2 Второй j-инвариант
     * @param p Простое число характеристики поля
     * @return true, если модулярное уравнение выполняется
     */
    bool verify_modular_equation_degree_5(const GmpRaii& j1, const GmpRaii& j2, const GmpRaii& p) const;
    
    /**
     * @brief Проверка модулярного уравнения для изогении степени 7
     * 
     * @param j1 Первый j-инвариант
     * @param j2 Второй j-инвариант
     * @param p Простое число характеристики поля
     * @return true, если модулярное уравнение выполняется
     */
    bool verify_modular_equation_degree_7(const GmpRaii& j1, const GmpRaii& j2, const GmpRaii& p) const;
    
    /**
     * @brief Проверка модулярного уравнения для изогении общей степени
     * 
     * @param j1 Первый j-инвариант
     * @param j2 Второй j-инвариант
     * @param degree Степень изогении
     * @param p Простое число характеристики поля
     * @return true, если модулярное уравнение выполняется
     */
    bool verify_modular_equation_general(const GmpRaii& j1, const GmpRaii& j2, 
                                       unsigned int degree, const GmpRaii& p) const;
    
    /**
     * @brief Проверка, что кривая имеет правильную структуру
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая имеет правильную структуру
     */
    bool has_valid_structure(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка, что кривая не является поддельной
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая не поддельная
     */
    bool is_not_fake_curve(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Вычисление многочлена деления
     * 
     * @param n Степень многочлена
     * @return Многочлен деления
     */
    GmpRaii compute_division_polynomial(unsigned int n) const;
    
    /**
     * @brief Проверка, что кривая принадлежит графу изогений
     * 
     * @param base_curve Базовая кривая
     * @param target_curve Целевая кривая
     * @param primes Простые числа для изогений
     * @return true, если кривая принадлежит графу изогений
     */
    bool is_curve_in_isogeny_graph(const MontgomeryCurve& base_curve,
                                  const MontgomeryCurve& target_curve,
                                  const std::vector<GmpRaii>& primes) const;
    
    /**
     * @brief Проверка, что кривая является легитимной для TorusCSIDH
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая легитимна
     */
    bool is_legitimate_curve(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Вычисление коэффициентов модулярного уравнения
     * 
     * @param degree Степень изогении
     * @param p Простое число характеристики поля
     * @return Вектор коэффициентов
     */
    std::vector<GmpRaii> compute_modular_equation_coefficients(unsigned int degree, const GmpRaii& p) const;
    
    /**
     * @brief Вычисление модулярного полинома
     * 
     * @param degree Степень изогении
     * @param j1 Первый j-инвариант
     * @param j2 Второй j-инвариант
     * @param p Простое число характеристики поля
     * @return Значение модулярного полинома
     */
    GmpRaii compute_modular_polynomial(unsigned int degree, 
                                      const GmpRaii& j1, 
                                      const GmpRaii& j2, 
                                      const GmpRaii& p) const;
    
private:
    /**
     * @brief Инициализация системы
     */
    void initialize();
    
    /**
     * @brief Инициализация системы RELIC
     */
    void initialize_relic();
    
    /**
     * @brief Проверка целостности ключа
     * 
     * @return true, если ключ цел
     */
    bool verify_key_integrity_internal() const;
    
    SecurityConstants::SecurityLevel security_level_; ///< Уровень безопасности
    bool system_ready_; ///< Готова ли система к работе
    std::chrono::high_resolution_clock::time_point start_time_; ///< Время начала операции
    MontgomeryCurve base_curve_; ///< Базовая кривая
    std::vector<short> private_key_; ///< Приватный ключ
    MontgomeryCurve public_curve_; ///< Публичная кривая
    GeometricValidator geometric_validator_; ///< Геометрический валидатор
    std::unique_ptr<Rfc6979Rng> rfc6979_rng_; ///< Генератор RFC 6979
    CodeIntegrityProtection code_integrity_; ///< Проверка целостности системы
    mutable std::mutex toruscsidh_mutex_; ///< Мьютекс для синхронизации
};

} // namespace toruscsidh

#endif // TORUSCSIDH_H
