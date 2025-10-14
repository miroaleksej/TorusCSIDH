#ifndef TORUSCSIDH_RFC6979_RNG_H
#define TORUSCSIDH_RFC6979_RNG_H

#include <vector>
#include <gmpxx.h>
#include <sodium.h>
#include "security_constants.h"
#include "elliptic_curve.h"
#include "postquantum_hash.h"

namespace toruscsidh {

/**
 * @brief Генератор случайных чисел по RFC6979
 * 
 * Реализует детерминированный алгоритм генерации случайных чисел для цифровых подписей,
 * как описано в RFC6979. Этот алгоритм предотвращает утечки секретного ключа через
 * недостаток энтропии и обеспечивает детерминированность процесса подписания.
 */
class RFC6979_RNG {
public:
    /**
     * @brief Генерация случайного числа по RFC6979
     * 
     * Генерирует детерминированное случайное число для использования в подписи.
     * 
     * @param private_key Приватный ключ
     * @param message Хешированное сообщение
     * @param curve_params Параметры кривой
     * @return Случайное число
     */
    GmpRaii generate(const GmpRaii& private_key,
                    const std::vector<unsigned char>& message,
                    const SecurityConstants::CurveParams& curve_params);
    
    /**
     * @brief Генерация случайного числа для изогении
     * 
     * Генерирует детерминированное случайное число, подходящее для вычисления изогений.
     * 
     * @param private_key Приватный ключ
     * @param message Хешированное сообщение
     * @param curve_params Параметры кривой
     * @param prime Простое число для ограничения
     * @return Случайное число для изогении
     */
    GmpRaii generate_for_isogeny(const GmpRaii& private_key,
                               const std::vector<unsigned char>& message,
                               const SecurityConstants::CurveParams& curve_params,
                               const GmpRaii& prime);
    
    /**
     * @brief Генерация случайного числа с учетом геометрических ограничений
     * 
     * Генерирует случайное число, соответствующее требованиям геометрического валидатора.
     * 
     * @param private_key Приватный ключ
     * @param message Хешированное сообщение
     * @param curve_params Параметры кривой
     * @param geometric_validator Геометрический валидатор
     * @param primes Простые числа для системы
     * @return Случайное число
     */
    GmpRaii generate_with_geometric_constraints(
        const GmpRaii& private_key,
        const std::vector<unsigned char>& message,
        const SecurityConstants::CurveParams& curve_params,
        const GeometricValidator& geometric_validator,
        const std::vector<GmpRaii>& primes);
    
    /**
     * @brief Проверка, что сгенерированное число безопасно
     * 
     * Проверяет, что случайное число соответствует всем требованиям безопасности.
     * 
     * @param k Сгенерированное число
     * @param curve_params Параметры кривой
     * @return true, если число безопасно
     */
    bool is_safe_random(const GmpRaii& k, const SecurityConstants::CurveParams& curve_params) const;
    
    /**
     * @brief Проверка на слабые значения
     * 
     * Обнаруживает значения, которые могут сделать систему уязвимой к атакам.
     * 
     * @param k Сгенерированное число
     * @return true, если значение слабое
     */
    bool is_weak_value(const GmpRaii& k) const;
    
    /**
     * @brief Проверка, что число соответствует геометрическим ограничениям
     * 
     * @param k Сгенерированное число
     * @param geometric_validator Геометрический валидатор
     * @param primes Простые числа для системы
     * @return true, если число соответствует ограничениям
     */
    bool satisfies_geometric_constraints(
        const GmpRaii& k,
        const GeometricValidator& geometric_validator,
        const std::vector<GmpRaii>& primes) const;
    
    /**
     * @brief Генерация соли для дополнительной защиты
     * 
     * @return Случайная соль
     */
    static std::vector<unsigned char> generate_salt();
    
    /**
     * @brief Генерация случайного числа с постоянным временем выполнения
     * 
     * Обеспечивает, что операция выполняется за строго определенное время,
     * предотвращая атаки по времени.
     * 
     * @param private_key Приватный ключ
     * @param message Хешированное сообщение
     * @param curve_params Параметры кривой
     * @param target_time Целевое время выполнения
     * @return Случайное число
     */
    GmpRaii generate_constant_time(
        const GmpRaii& private_key,
        const std::vector<unsigned char>& message,
        const SecurityConstants::CurveParams& curve_params,
        const std::chrono::microseconds& target_time);
    
    /**
     * @brief Проверка целостности генератора
     * 
     * @return true, если генератор цел
     */
    bool verify_integrity() const;
    
    /**
     * @brief Проверка, что генератор готов к использованию
     * 
     * @return true, если генератор готов
     */
    bool is_ready() const;
    
    /**
     * @brief Инициализация генератора
     */
    void initialize();
    
    /**
     * @brief Деинициализация генератора
     */
    void finalize();
    
    /**
     * @brief Получение текущего состояния генератора
     * 
     * @return Состояние генератора
     */
    std::vector<unsigned char> get_state() const;
    
    /**
     * @brief Восстановление состояния генератора
     * 
     * @param state Состояние генератора
     */
    void restore_state(const std::vector<unsigned char>& state);
    
private:
    /**
     * @brief Выполнение шага алгоритма RFC6979
     * 
     * @param h1 Хеш сообщения
     * @param x Приватный ключ
     * @param q Порядок группы
     * @param alg Хеш-алгоритм
     * @return Случайное число
     */
    GmpRaii rfc6979_step(const std::vector<unsigned char>& h1,
                        const GmpRaii& x,
                        const GmpRaii& q,
                        const std::string& alg) const;
    
    /**
     * @brief Вычисление V и K для алгоритма RFC6979
     * 
     * @param h1 Хеш сообщения
     * @param x Приватный ключ
     * @param q Порядок группы
     * @param alg Хеш-алгоритм
     * @param V Выходной параметр V
     * @param K Выходной параметр K
     */
    void compute_v_k(const std::vector<unsigned char>& h1,
                    const GmpRaii& x,
                    const GmpRaii& q,
                    const std::string& alg,
                    std::vector<unsigned char>& V,
                    std::vector<unsigned char>& K) const;
    
    /**
     * @brief Генерация случайного числа с использованием V и K
     * 
     * @param V Параметр V
     * @param K Параметр K
     * @param h1 Хеш сообщения
     * @param x Приватный ключ
     * @param q Порядок группы
     * @return Случайное число
     */
    GmpRaii generate_from_v_k(const std::vector<unsigned char>& V,
                            const std::vector<unsigned char>& K,
                            const std::vector<unsigned char>& h1,
                            const GmpRaii& x,
                            const GmpRaii& q) const;
    
    /**
     * @brief Проверка, что число находится в допустимом диапазоне
     * 
     * @param k Число для проверки
     * @param q Порядок группы
     * @return true, если число в допустимом диапазоне
     */
    bool is_in_range(const GmpRaii& k, const GmpRaii& q) const;
    
    /**
     * @brief Проверка, что число не является слабым
     * 
     * @param k Число для проверки
     * @return true, если число не слабое
     */
    bool is_not_weak(const GmpRaii& k) const;
    
    /**
     * @brief Вычисление хеша для алгоритма RFC6979
     * 
     * @param V Параметр V
     * @param T Буфер данных
     * @param alg Хеш-алгоритм
     * @return Хеш
     */
    std::vector<unsigned char> compute_hmac(const std::vector<unsigned char>& V,
                                         const std::vector<unsigned char>& T,
                                         const std::string& alg) const;
    
    /**
     * @brief Инициализация HMAC ключа
     * 
     * @param K HMAC ключ
     * @param alg Хеш-алгоритм
     */
    void init_hmac_key(std::vector<unsigned char>& K, const std::string& alg) const;
    
    /**
     * @brief Выполнение шага HMAC
     * 
     * @param K HMAC ключ
     * @param V Параметр V
     * @param alg Хеш-алгоритм
     * @param h1 Хеш сообщения
     * @param x Приватный ключ
     * @param t Битовый флаг
     */
    void hmac_step(std::vector<unsigned char>& K,
                 std::vector<unsigned char>& V,
                 const std::string& alg,
                 const std::vector<unsigned char>& h1,
                 const GmpRaii& x,
                 unsigned char t) const;
    
    /**
     * @brief Обеспечение постоянного времени выполнения
     * 
     * Добавляет задержку, чтобы операция выполнялась за строго определенное время.
     * 
     * @param target_time Целевое время выполнения
     */
    void ensure_constant_time(const std::chrono::microseconds& target_time) const;
    
    // Флаг инициализации
    bool is_initialized_;
    
    // Текущее время для обеспечения постоянного времени
    mutable std::chrono::high_resolution_clock::time_point start_time_;
    
    // Константы безопасности
    static constexpr size_t MAX_RETRIES = 1000;
    static constexpr size_t HMAC_KEY_SIZE = 64;
    static constexpr size_t SALT_SIZE = 32;
};

} // namespace toruscsidh

#endif // TORUSCSIDH_RFC6979_RNG_H
