#ifndef TORUSCSIDH_BECH32M_H
#define TORUSCSIDH_BECH32M_H

#include <string>
#include <vector>
#include <cstdint>
#include "security_constants.h"

namespace toruscsidh {

/**
 * @brief Класс для кодирования и декодирования адресов в формате Bech32m
 * 
 * Реализует формат адресов, совместимый с BIP-350 (Bech32m), с дополнительными
 * проверками безопасности для постквантовой криптографии TorusCSIDH.
 */
class Bech32m {
public:
    /**
     * @brief Кодирование данных в формат Bech32m
     * 
     * @param hrp Человекочитаемый префикс (например, "tcidh")
     * @param values Данные для кодирования
     * @return Закодированная строка в формате Bech32m
     */
    static std::string encode(const std::string& hrp, const std::vector<unsigned char>& values);
    
    /**
     * @brief Декодирование адреса Bech32m
     * 
     * @param addr Адрес для декодирования
     * @param hrp_out Выходной параметр для человекочитаемого префикса
     * @param values_out Выходной параметр для данных
     * @return true, если декодирование успешно
     */
    static bool decode(const std::string& addr, std::string& hrp_out, std::vector<unsigned char>& values_out);
    
    /**
     * @brief Проверка контрольной суммы Bech32m
     * 
     * @param values Данные с контрольной суммой
     * @return true, если контрольная сумма верна
     */
    static bool verify_checksum(const std::vector<uint5>& values);
    
    /**
     * @brief Создание контрольной суммы Bech32m
     * 
     * @param hrp Человекочитаемый префикс
     * @param values Данные
     * @return Контрольная сумма
     */
    static std::vector<uint5> create_checksum(const std::string& hrp, const std::vector<uint5>& values);
    
    /**
     * @brief Конвертация из 8-битных байтов в 5-битные символы
     * 
     * @param data Входные данные
     * @param pad Добавлять ли дополнительные нулевые биты
     * @return Преобразованные данные
     */
    static std::vector<uint5> convert_bits(const std::vector<unsigned char>& data, bool pad);
    
    /**
     * @brief Конвертация из 5-битных символов в 8-битные байты
     * 
     * @param data Входные данные
     * @param pad Добавлять ли дополнительные нулевые биты
     * @return Преобразованные данные
     */
    static std::vector<unsigned char> convert_bits_back(const std::vector<uint5>& data, bool pad);
    
    /**
     * @brief Проверка, что адрес соответствует требованиям безопасности
     * 
     * @param addr Адрес для проверки
     * @return true, если адрес безопасен
     */
    static bool is_secure_address(const std::string& addr);
    
    /**
     * @brief Проверка, что адрес соответствует формату TorusCSIDH
     * 
     * @param addr Адрес для проверки
     * @return true, если адрес соответствует формату
     */
    static bool is_toruscsidh_address(const std::string& addr);
    
    /**
     * @brief Получение человекочитаемого префикса из адреса
     * 
     * @param addr Адрес
     * @return Человекочитаемый префикс
     */
    static std::string get_hrp(const std::string& addr);
    
    /**
     * @brief Проверка, что адрес не содержит подозрительных паттернов
     * 
     * @param addr Адрес для проверки
     * @return true, если адрес не содержит подозрительных паттернов
     */
    static bool check_for_suspicious_patterns(const std::string& addr);
    
    /**
     * @brief Проверка, что адрес имеет правильную длину
     * 
     * @param addr Адрес для проверки
     * @return true, если длина правильная
     */
    static bool has_valid_length(const std::string& addr);
    
    /**
     * @brief Проверка, что адрес использует безопасный алфавит
     * 
     * @param addr Адрес для проверки
     * @return true, если алфавит безопасен
     */
    static bool uses_secure_alphabet(const std::string& addr);
    
    /**
     * @brief Проверка, что адрес не является слабым
     * 
     * @param addr Адрес для проверки
     * @return true, если адрес не слабый
     */
    static bool is_not_weak(const std::string& addr);
    
    /**
     * @brief Получение данных из адреса
     * 
     * @param addr Адрес
     * @param data_out Выходной параметр для данных
     * @return true, если получение данных успешно
     */
    static bool get_data(const std::string& addr, std::vector<unsigned char>& data_out);
    
    /**
     * @brief Вычисление полиномиального модуля для Bech32m
     * 
     * @param values Данные
     * @param generator Генератор
     * @return Результат полиномиального модуля
     */
    static uint32_t bech32m_polymod(const std::vector<uint5>& values, const uint32_t* generator);
    
    /**
     * @brief Проверка, что адрес соответствует требованиям TorusCSIDH
     * 
     * @param addr Адрес для проверки
     * @return true, если адрес соответствует требованиям
     */
    static bool validate_toruscsidh_address(const std::string& addr);
    
    /**
     * @brief Проверка, что адрес не уязвим к атакам через геометрическую структуру
     * 
     * @param addr Адрес для проверки
     * @return true, если адрес не уязвим
     */
    static bool is_not_vulnerable_to_geometric_attacks(const std::string& addr);
    
    /**
     * @brief Проверка, что адрес не содержит паттернов, уязвимых к атакам
     * 
     * @param addr Адрес для проверки
     * @return true, если адрес не содержит уязвимых паттернов
     */
    static bool check_for_vulnerable_patterns(const std::string& addr);
    
private:
    // Тип для 5-битных значений
    using uint5 = uint8_t;
    
    // Алфавит Bech32m
    static const char* CHARSET;
    
    // Генератор для полиномиального модуля
    static const uint32_t BECH32M_GENERATOR[5];
    
    // Константы безопасности
    static constexpr size_t MIN_ADDRESS_LENGTH = 15;
    static constexpr size_t MAX_ADDRESS_LENGTH = 90;
    static constexpr size_t MIN_DATA_LENGTH = 10;
    static constexpr size_t MAX_DATA_LENGTH = 64;
    static constexpr size_t MAX_CONSECUTIVE_SAME_CHAR = 3;
    static constexpr size_t MIN_UNIQUE_CHARS = 5;
};

} // namespace toruscsidh

#endif // TORUSCSIDH_BECH32M_H
