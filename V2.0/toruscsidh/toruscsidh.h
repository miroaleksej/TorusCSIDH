#ifndef TORUSCSIDH_TORUSCSIDH_H
#define TORUSCSIDH_TORUSCSIDH_H

#include <vector>
#include <chrono>
#include <gmpxx.h>
#include "elliptic_curve.h"
#include "geometric_validator.h"
#include "code_integrity.h"
#include "rfc6979_rng.h"
#include "security_constants.h"
#include "postquantum_hash.h"

namespace toruscsidh {

/**
 * @brief Класс для реализации постквантовой криптосистемы TorusCSIDH
 * 
 * Реализует полную систему цифровой подписи TorusCSIDH с многоуровневой
 * защитой от атак через поддельные кривые.
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
     * @brief Инициализация системы
     */
    void initialize();
    
    /**
     * @brief Генерация ключевой пары
     */
    void generate_key_pair();
    
    /**
     * @brief Подпись сообщения
     * 
     * @param message Сообщение для подписи
     * @return Подпись
     */
    std::vector<unsigned char> sign(const std::vector<unsigned char>& message);
    
    /**
     * @brief Верификация подписи
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
     * @return Адрес в формате Bech32m
     */
    std::string generate_address();
    
    /**
     * @brief Печать информации о системе
     */
    void print_info() const;
    
    /**
     * @brief Проверка, готова ли система к работе
     * 
     * @return true, если система готова
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
     * @return Ссылка на систему проверки целостности
     */
    CodeIntegrityProtection& get_code_integrity();
    
    /**
     * @brief Проверка целостности ключа
     * 
     * @return true, если ключ цел
     */
    bool verify_key_integrity() const;
    
    /**
     * @brief Проверка, что ключ "малый"
     * 
     * @return true, если ключ "малый"
     */
    bool is_small_key() const;
    
    /**
     * @brief Проверка, что ключ слабый
     * 
     * @return true, если ключ слабый
     */
    bool is_weak_key() const;
    
    /**
     * @brief Проверка, что ключ безопасен
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
    
private:
    SecurityConstants::SecurityLevel security_level_; ///< Уровень безопасности
    bool system_ready_; ///< Готова ли система к работе
    MontgomeryCurve base_curve_; ///< Базовая кривая
    MontgomeryCurve public_curve_; ///< Публичная кривая
    std::vector<short> private_key_; ///< Приватный ключ
    GeometricValidator geometric_validator_; ///< Геометрический валидатор
    CodeIntegrityProtection code_integrity_; ///< Система проверки целостности
    std::unique_ptr<Rfc6979Rng> rfc6979_rng_; ///< Генератор RFC 6979
    std::chrono::high_resolution_clock::time_point start_time_; ///< Время начала операции
    
    /**
     * @brief Проверка, что кривая имеет регулярные паттерны
     * 
     * @return true, если кривая имеет регулярные паттерны
     */
    bool has_regular_patterns() const;
    
    /**
     * @brief Проверка, что кривая уязвима к атаке через длинный путь
     * 
     * @return true, если кривая уязвима к атаке через длинный путь
     */
    bool is_vulnerable_to_long_path_attack() const;
    
    /**
     * @brief Проверка, что кривая уязвима к атаке через вырожденную топологию
     * 
     * @return true, если кривая уязвима к атаке через вырожденную топологию
     */
    bool is_vulnerable_to_degenerate_topology_attack() const;
};

} // namespace toruscsidh

#endif // TORUSCSIDH_TORUSCSIDH_H
