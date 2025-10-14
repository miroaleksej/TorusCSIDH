#ifndef TORUSCSIDH_POSTQUANTUM_HASH_H
#define TORUSCSIDH_POSTQUANTUM_HASH_H

#include <vector>
#include <gmpxx.h>
#include <sodium.h>
#include "security_constants.h"
#include "elliptic_curve.h"

namespace toruscsidh {

/**
 * @brief Класс для постквантового хеширования
 * 
 * Реализует безопасное хеширование с использованием комбинации
 * BLAKE3 и дополнительных защитных механизмов против квантовых атак.
 */
class PostQuantumHash {
public:
    /**
     * @brief Хеширование данных
     * 
     * Использует BLAKE3 с дополнительными защитными слоями для постквантовой безопасности.
     * 
     * @param data Данные для хеширования
     * @return Хеш-значение
     */
    static std::vector<unsigned char> hash(const std::vector<unsigned char>& data);
    
    /**
     * @brief Хеширование данных в GmpRaii
     * 
     * Конвертирует хеш в GMP число для использования в криптографических операциях.
     * 
     * @param data Данные для хеширования
     * @param modulus Модуль для ограничения результата
     * @return Хеш-значение в виде GmpRaii
     */
    static GmpRaii hash_to_gmp(const std::vector<unsigned char>& data, const GmpRaii& modulus);
    
    /**
     * @brief Хеширование сообщения для подписи
     * 
     * Создает хеш, подходящий для использования в схеме цифровой подписи.
     * 
     * @param message Сообщение
     * @param ephemeral_curve_j j-инвариант эфемерной кривой
     * @param public_curve_j j-инвариант публичной кривой
     * @return Хеш для подписи
     */
    static std::vector<unsigned char> hash_for_signature(
        const std::vector<unsigned char>& message,
        const GmpRaii& ephemeral_curve_j,
        const GmpRaii& public_curve_j
    );
    
    /**
     * @brief Проверка целостности хеш-функции
     * 
     * Проверяет, что хеш-функция не была модифицирована.
     * 
     * @return true, если хеш-функция цела
     */
    static bool verify_integrity();
    
    /**
     * @brief Получение HMAC ключа
     * 
     * @return HMAC ключ
     */
    static const std::vector<unsigned char>& get_hmac_key();
    
    /**
     * @brief Создание HMAC для данных
     * 
     * @param data Данные
     * @return HMAC
     */
    static std::vector<unsigned char> create_hmac(const std::vector<unsigned char>& data);
    
    /**
     * @brief Проверка HMAC
     * 
     * @param data Данные
     * @param mac Проверяемый MAC
     * @return true, если MAC верен
     */
    static bool verify_hmac(const std::vector<unsigned char>& data, 
                          const std::vector<unsigned char>& mac);
    
    /**
     * @brief Хеширование для генерации случайного числа
     * 
     * Используется в RFC6979 для генерации детерминированного случайного числа.
     * 
     * @param private_key Приватный ключ
     * @param message Хешированное сообщение
     * @param curve_params Параметры кривой
     * @return Случайное число в виде хеша
     */
    static std::vector<unsigned char> hash_for_rfc6979(
        const GmpRaii& private_key,
        const std::vector<unsigned char>& message,
        const SecurityConstants::CurveParams& curve_params
    );
    
    /**
     * @brief Хеширование для проверки структуры графа
     * 
     * Создает хеш, отражающий структурные свойства графа изогений.
     * 
     * @param graph Граф изогений
     * @return Структурный хеш
     */
    static std::vector<unsigned char> hash_graph_structure(
        const GeometricValidator::Graph& graph
    );
    
    /**
     * @brief Проверка, что хеш имеет достаточную энтропию
     * 
     * @param hash Хеш для проверки
     * @return true, если энтропия достаточна
     */
    static bool has_sufficient_entropy(const std::vector<unsigned char>& hash);
    
    /**
     * @brief Хеширование с добавлением соли
     * 
     * Добавляет случайную соль к данным перед хешированием.
     * 
     * @param data Данные
     * @param salt Соль
     * @return Хеш со солью
     */
    static std::vector<unsigned char> hash_with_salt(
        const std::vector<unsigned char>& data,
        const std::vector<unsigned char>& salt
    );
    
    /**
     * @brief Проверка, что хеш соответствует требованиям безопасности
     * 
     * @param hash Хеш для проверки
     * @return true, если хеш безопасен
     */
    static bool is_secure_hash(const std::vector<unsigned char>& hash);
    
private:
    /**
     * @brief Инициализация хеш-функции
     */
    static void initialize();
    
    /**
     * @brief Генерация случайной соли
     * 
     * @return Случайная соль
     */
    static std::vector<unsigned char> generate_salt();
    
    /**
     * @brief Применение дополнительных защитных преобразований
     * 
     * @param hash Исходный хеш
     * @return Защищенный хеш
     */
    static std::vector<unsigned char> apply_security_transformations(
        const std::vector<unsigned char>& hash
    );
    
    // Статический флаг инициализации
    static bool is_initialized_;
    
    // HMAC ключ для проверки целостности
    static std::vector<unsigned char> hmac_key_;
    
    // Соль для дополнительной защиты
    static std::vector<unsigned char> salt_;
    
    // Константы безопасности
    static constexpr size_t SALT_SIZE = 32;
    static constexpr size_t MIN_ENTROPY_BITS = 256;
};

} // namespace toruscsidh

#endif // TORUSCSIDH_POSTQUANTUM_HASH_H
