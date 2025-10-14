#ifndef TORUSCSIDH_H
#define TORUSCSIDH_H

#include <vector>
#include <string>
#include <gmpxx.h>
#include <chrono>
#include "security_constants.h"
#include "elliptic_curve.h"
#include "geometric_validator.h"
#include "code_integrity_protection.h"
#include "secure_random.h"
#include "postquantum_hash.h"
#include "bech32m.h"

namespace toruscsidh {

/**
 * @brief Основной класс системы TorusCSIDH
 * 
 * Реализует постквантовую систему цифровой подписи на основе суперсингулярных изогений
 * с трехуровневой проверкой безопасности: алгебраической, геометрической и системной.
 */
class TorusCSIDH {
public:
    /**
     * @brief Конструктор
     * 
     * @param security_level Уровень безопасности (128, 192 или 256 бит)
     */
    explicit TorusCSIDH(SecurityConstants::SecurityLevel security_level = SecurityConstants::SecurityLevel::LEVEL_128);
    
    /**
     * @brief Деструктор
     */
    ~TorusCSIDH();
    
    /**
     * @brief Инициализация системы
     * 
     * Выполняет необходимые проверки и настройки перед использованием.
     */
    void initialize();
    
    /**
     * @brief Генерация ключевой пары
     * 
     * Генерирует приватный и публичный ключи.
     */
    void generate_key_pair();
    
    /**
     * @brief Подпись сообщения
     * 
     * Создает цифровую подпись для заданного сообщения.
     * 
     * @param message Сообщение для подписи
     * @return Подпись
     */
    std::vector<unsigned char> sign(const std::vector<unsigned char>& message);
    
    /**
     * @brief Верификация подписи
     * 
     * Проверяет подпись для заданного сообщения.
     * 
     * @param message Сообщение
     * @param signature Подпись
     * @return true, если подпись верна
     */
    bool verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature);
    
    /**
     * @brief Генерация адреса в формате Bech32m
     * 
     * @return Адрес
     */
    std::string generate_address();
    
    /**
     * @brief Печать информации о системе
     */
    void print_info() const;
    
    /**
     * @brief Проверка, готова ли система к использованию
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
    const CodeIntegrityProtection& get_code_integrity() const;
    
    /**
     * @brief Получение геометрического валидатора
     * 
     * @return Ссылка на геометрический валидатор
     */
    const GeometricValidator& get_geometric_validator() const;
    
    /**
     * @brief Проверка "малости" ключа
     * 
     * Проверяет, что ключ удовлетворяет условиям малости для CSIDH.
     * 
     * @return true, если ключ "малый"
     */
    bool is_small_key() const;
    
    /**
     * @brief Проверка на слабые ключи
     * 
     * Обнаруживает ключи с регулярными паттернами или другими уязвимостями.
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
     * @brief Обеспечение постоянного времени выполнения
     * 
     * Добавляет задержку, чтобы операция выполнялась за строго определенное время.
     * 
     * @param target_time Целевое время выполнения
     */
    void ensure_constant_time(const std::chrono::microseconds& target_time);
    
    /**
     * @brief Проверка, что кривая принадлежит графу изогений
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая принадлежит графу изогений
     */
    bool is_curve_in_isogeny_graph(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Проверка геометрических свойств кривой
     * 
     * Выполняет комплексную геометрическую проверку кривой.
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая проходит геометрическую проверку
     */
    bool validate_geometric_properties(const MontgomeryCurve& curve) const;
    
    /**
     * @brief Получение параметров безопасности
     * 
     * @return Параметры безопасности
     */
    const SecurityConstants::CSIDHParams& get_security_params() const;
    
    /**
     * @brief Получение списка простых чисел
     * 
     * @return Список простых чисел
     */
    const std::vector<GmpRaii>& get_primes() const;

private:
    // Уровень безопасности
    SecurityConstants::SecurityLevel security_level_;
    
    // Параметры безопасности для CSIDH
    SecurityConstants::CSIDHParams params;
    
    // Приватный ключ
    std::vector<short> private_key;
    
    // Публичная кривая
    MontgomeryCurve public_curve;
    
    // Время начала операции для обеспечения постоянного времени
    std::chrono::high_resolution_clock::time_point start_time;
    
    // Геометрический валидатор
    GeometricValidator geometric_validator;
    
    // Система проверки целостности
    CodeIntegrityProtection code_integrity;
    
    // Базовая кривая
    MontgomeryCurve base_curve;
    
    /**
     * @brief Инициализация параметров безопасности
     */
    void initialize_security_params();
    
    /**
     * @brief Проверка базовых параметров
     * 
     * @return true, если параметры корректны
     */
    bool validate_base_parameters() const;
    
    /**
     * @brief Построение графа изогений
     * 
     * @param center_curve Центральная кривая
     * @param radius Радиус графа
     * @return Построенный граф
     */
    GeometricValidator::Graph build_isogeny_graph(const MontgomeryCurve& center_curve, int radius) const;
    
    /**
     * @brief Конвертация ключа в GmpRaii
     * 
     * @return Ключ в формате GmpRaii
     */
    GmpRaii convert_to_gmp_key() const;
    
    /**
     * @brief Проверка, что кривая является эквивалентной базовой
     * 
     * @param curve Кривая для проверки
     * @return true, если кривая эквивалентна базовой
     */
    bool is_equivalent_to_base_curve(const MontgomeryCurve& curve) const;
    
    // Константы безопасности
    static constexpr int GEOMETRIC_RADIUS = 3;
    static constexpr int MAX_SIGNATURE_RETRY = 5;
};

} // namespace toruscsidh

#endif // TORUSCSIDH_H
