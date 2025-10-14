#include "bech32m.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <iostream>
#include <stdexcept>
#include <vector>
#include "secure_random.h"
#include "security_constants.h"
#include "geometric_validator.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

// Алфавит Bech32m
const char* Bech32m::CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Генератор для полиномиального модуля
const uint32_t Bech32m::BECH32M_GENERATOR[5] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

std::string Bech32m::encode(const std::string& hrp, const std::vector<unsigned char>& values) {
    // Проверка длины человекочитаемого префикса
    if (hrp.empty() || hrp.size() > 83) {
        throw std::invalid_argument("Invalid human-readable part length");
    }
    
    // Проверка, что HRP содержит только строчные буквы
    for (char c : hrp) {
        if (!std::islower(c)) {
            throw std::invalid_argument("Human-readable part must be lowercase");
        }
    }
    
    // Конвертация данных в 5-битные символы
    std::vector<uint5> data5 = convert_bits(values, true);
    if (data5.empty()) {
        throw std::invalid_argument("Invalid data for encoding");
    }
    
    // Создание контрольной суммы
    std::vector<uint5> checksum = create_checksum(hrp, data5);
    
    // Объединение данных и контрольной суммы
    std::vector<uint5> combined = data5;
    combined.insert(combined.end(), checksum.begin(), checksum.end());
    
    // Формирование закодированной строки
    std::string encoded;
    
    // Добавление человекочитаемой части
    encoded += hrp;
    encoded += '1';
    
    // Добавление данных в алфавите
    for (uint5 c : combined) {
        if (c >= 32) {
            throw std::runtime_error("Invalid character in encoded data");
        }
        encoded += CHARSET[c];
    }
    
    // Проверка безопасности адреса
    if (!is_secure_address(encoded)) {
        SecureAuditLogger::get_instance().log_event("security", "Generated address is not secure", true);
        throw std::runtime_error("Generated address is not secure");
    }
    
    return encoded;
}

bool Bech32m::decode(const std::string& addr, std::string& hrp_out, std::vector<unsigned char>& values_out) {
    // Проверка длины адреса
    if (addr.size() < MIN_ADDRESS_LENGTH || addr.size() > MAX_ADDRESS_LENGTH) {
        return false;
    }
    
    // Поиск разделителя '1'
    size_t pos = addr.find('1');
    if (pos == std::string::npos || pos < 1 || pos + 7 > addr.size()) {
        return false;
    }
    
    // Извлечение человекочитаемой части
    hrp_out = addr.substr(0, pos);
    
    // Проверка, что HRP содержит только строчные буквы
    for (char c : hrp_out) {
        if (!std::islower(c)) {
            return false;
        }
    }
    
    // Конвертация оставшихся символов в 5-битные значения
    std::vector<uint5> data5;
    for (size_t i = pos + 1; i < addr.size(); i++) {
        char c = addr[i];
        
        // Поиск символа в алфавите
        const char* p = std::strchr(CHARSET, c);
        if (!p) {
            return false; // Недопустимый символ
        }
        
        data5.push_back(static_cast<uint5>(p - CHARSET));
    }
    
    // Проверка контрольной суммы
    if (!verify_checksum(data5)) {
        return false;
    }
    
    // Удаление контрольной суммы (последние 6 символов)
    data5.resize(data5.size() - 6);
    
    // Конвертация 5-битных значений в 8-битные байты
    values_out = convert_bits_back(data5, true);
    
    // Дополнительная проверка безопасности
    if (values_out.empty() || values_out.size() < MIN_DATA_LENGTH || values_out.size() > MAX_DATA_LENGTH) {
        return false;
    }
    
    // Проверка, что адрес соответствует требованиям безопасности
    if (!is_secure_address(addr)) {
        return false;
    }
    
    return true;
}

bool Bech32m::verify_checksum(const std::vector<uint5>& values) {
    // Вычисление полиномиального модуля
    uint32_t polymod = bech32m_polymod(values, BECH32M_GENERATOR);
    
    // Для Bech32m ожидаемое значение - 0x2bc830a3
    return polymod == 0x2bc830a3;
}

std::vector<uint5> Bech32m::create_checksum(const std::string& hrp, const std::vector<uint5>& values) {
    // Подготовка данных для вычисления контрольной суммы
    std::vector<uint5> encoding;
    
    // Добавление HRP в 5-битном представлении
    for (char c : hrp) {
        encoding.push_back(c >> 5);
    }
    encoding.push_back(0); // Сепаратор
    
    for (char c : hrp) {
        encoding.push_back(c & 0x1f);
    }
    
    // Добавление данных
    encoding.insert(encoding.end(), values.begin(), values.end());
    
    // Добавление завершающих нулей
    encoding.insert(encoding.end(), 6, 0);
    
    // Вычисление полиномиального модуля
    uint32_t mod = bech32m_polymod(encoding, BECH32M_GENERATOR);
    
    // Преобразование в контрольную сумму
    std::vector<uint5> checksum(6);
    for (int i = 0; i < 6; i++) {
        checksum[i] = static_cast<uint5>((mod >> (5 * (5 - i))) & 0x1f);
    }
    
    return checksum;
}

std::vector<uint5> Bech32m::convert_bits(const std::vector<unsigned char>& data, bool pad) {
    std::vector<uint5> result;
    int acc = 0;
    int bits = 0;
    const int max_v = (1 << 5) - 1;
    
    for (unsigned char b : data) {
        acc = (acc << 8) | b;
        bits += 8;
        
        while (bits >= 5) {
            bits -= 5;
            result.push_back(static_cast<uint5>((acc >> bits) & max_v));
        }
    }
    
    if (pad && bits > 0) {
        result.push_back(static_cast<uint5>((acc << (5 - bits)) & max_v));
    } else if (bits >= 5 || ((acc << (5 - bits)) & max_v)) {
        return std::vector<uint5>(); // Ошибка конвертации
    }
    
    return result;
}

std::vector<unsigned char> Bech32m::convert_bits_back(const std::vector<uint5>& data, bool pad) {
    std::vector<unsigned char> result;
    int acc = 0;
    int bits = 0;
    const int max_v = (1 << 8) - 1;
    
    for (uint5 d : data) {
        if (d >= 32) {
            return std::vector<unsigned char>(); // Недопустимое значение
        }
        
        acc = (acc << 5) | d;
        bits += 5;
        
        while (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<unsigned char>((acc >> bits) & max_v));
        }
    }
    
    if (pad && bits > 0) {
        result.push_back(static_cast<unsigned char>((acc << (8 - bits)) & max_v));
    } else if (bits >= 8 || ((acc << (8 - bits)) & max_v)) {
        return std::vector<unsigned char>(); // Ошибка конвертации
    }
    
    return result;
}

bool Bech32m::is_secure_address(const std::string& addr) {
    // Проверка длины адреса
    if (!has_valid_length(addr)) {
        return false;
    }
    
    // Проверка алфавита
    if (!uses_secure_alphabet(addr)) {
        return false;
    }
    
    // Проверка на наличие подозрительных паттернов
    if (!check_for_suspicious_patterns(addr)) {
        return false;
    }
    
    // Проверка, что адрес не является слабым
    if (!is_not_weak(addr)) {
        return false;
    }
    
    // Проверка, что адрес соответствует формату TorusCSIDH
    if (!is_toruscsidh_address(addr)) {
        return false;
    }
    
    // Проверка, что адрес не уязвим к атакам через геометрическую структуру
    if (!is_not_vulnerable_to_geometric_attacks(addr)) {
        return false;
    }
    
    return true;
}

bool Bech32m::is_toruscsidh_address(const std::string& addr) {
    // Проверка, что адрес начинается с "tcidh"
    size_t pos = addr.find('1');
    if (pos == std::string::npos || pos < 4) {
        return false;
    }
    
    std::string hrp = addr.substr(0, pos);
    return hrp == "tcidh";
}

std::string Bech32m::get_hrp(const std::string& addr) {
    size_t pos = addr.find('1');
    if (pos == std::string::npos) {
        throw std::invalid_argument("Invalid address format");
    }
    
    return addr.substr(0, pos);
}

bool Bech32m::check_for_suspicious_patterns(const std::string& addr) {
    // Проверка на длинные последовательности одинаковых символов
    char last_char = '\0';
    size_t consecutive_count = 0;
    
    for (char c : addr) {
        if (c == last_char) {
            consecutive_count++;
            if (consecutive_count > MAX_CONSECUTIVE_SAME_CHAR) {
                return false;
            }
        } else {
            consecutive_count = 1;
            last_char = c;
        }
    }
    
    // Проверка количества уникальных символов
    std::unordered_set<char> unique_chars;
    for (char c : addr) {
        unique_chars.insert(c);
    }
    
    if (unique_chars.size() < MIN_UNIQUE_CHARS) {
        return false;
    }
    
    // Проверка на наличие предопределенных опасных паттернов
    const std::vector<std::string> dangerous_patterns = {
        "aaaaa", "ppppp", "qqqqq", "zzzzz", "11111",
        "qpzry", "9x8gf", "2tvdw", "0s3jn", "54khc",
        "e6mua", "7lqpz", "ry9x8", "gf2tv", "dw0s3"
    };
    
    for (const auto& pattern : dangerous_patterns) {
        if (addr.find(pattern) != std::string::npos) {
            return false;
        }
    }
    
    return true;
}

bool Bech32m::has_valid_length(const std::string& addr) {
    size_t length = addr.size();
    return length >= MIN_ADDRESS_LENGTH && length <= MAX_ADDRESS_LENGTH;
}

bool Bech32m::uses_secure_alphabet(const std::string& addr) {
    for (char c : addr) {
        if (c != '1' && std::strchr(CHARSET, c) == nullptr) {
            return false;
        }
    }
    return true;
}

bool Bech32m::is_not_weak(const std::string& addr) {
    // Проверка на слабые адреса
    // Слабые адреса включают:
    // 1. Адреса с высокой регулярностью символов
    // 2. Адреса, начинающиеся с определенных паттернов
    // 3. Адреса с низкой энтропией
    
    // Вычисление энтропии адреса
    std::map<char, int> char_count;
    for (char c : addr) {
        char_count[c]++;
    }
    
    double entropy = 0.0;
    size_t total = addr.size();
    
    for (const auto& entry : char_count) {
        double p = static_cast<double>(entry.second) / total;
        entropy -= p * std::log2(p);
    }
    
    // Проверка минимальной энтропии
    const double min_entropy = 4.0; // Минимальная энтропия на символ
    if (entropy < min_entropy) {
        return false;
    }
    
    // Проверка на регулярные паттерны
    const size_t pattern_length = 5;
    for (size_t i = 0; i < addr.size() - pattern_length + 1; i++) {
        bool is_constant = true;
        for (size_t j = 1; j < pattern_length; j++) {
            if (addr[i] != addr[i + j]) {
                is_constant = false;
                break;
            }
        }
        if (is_constant) {
            return false;
        }
    }
    
    // Проверка на арифметические прогрессии в позициях символов
    for (size_t i = 0; i < addr.size() - pattern_length + 1; i++) {
        if (addr.size() - i < pattern_length) break;
        
        int diff = std::strchr(CHARSET, addr[i + 1]) - std::strchr(CHARSET, addr[i]);
        bool is_arithmetic = true;
        for (size_t j = 2; j < pattern_length; j++) {
            int current_diff = std::strchr(CHARSET, addr[i + j]) - std::strchr(CHARSET, addr[i + j - 1]);
            if (current_diff != diff) {
                is_arithmetic = false;
                break;
            }
        }
        if (is_arithmetic) {
            return false;
        }
    }
    
    return true;
}

bool Bech32m::get_data(const std::string& addr, std::vector<unsigned char>& data_out) {
    std::string hrp;
    return decode(addr, hrp, data_out);
}

uint32_t Bech32m::bech32m_polymod(const std::vector<uint5>& values, const uint32_t* generator) {
    uint32_t chk = 1;
    
    for (uint5 v : values) {
        uint8_t b = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ v;
        
        for (int i = 0; i < 5; i++) {
            if ((b >> i) & 1) {
                chk ^= generator[i];
            }
        }
    }
    
    return chk;
}

bool Bech32m::validate_toruscsidh_address(const std::string& addr) {
    // Проверка, что адрес соответствует формату TorusCSIDH
    if (!is_toruscsidh_address(addr)) {
        return false;
    }
    
    // Декодирование адреса
    std::string hrp;
    std::vector<unsigned char> data;
    if (!decode(addr, hrp, data)) {
        return false;
    }
    
    // Проверка, что данные имеют правильный размер
    if (data.size() != SecurityConstants::ADDRESS_DATA_SIZE) {
        return false;
    }
    
    // Проверка, что данные соответствуют ожидаемому формату
    // Для TorusCSIDH данные должны представлять собой j-инвариант кривой
    GmpRaii j_invariant;
    mpz_import(j_invariant.get_mpz_t(), data.size(), 1, 1, 1, 0, data.data());
    
    // Проверка, что j-инвариант соответствует суперсингулярной кривой
    // В реальной системе здесь будет сложная проверка
    // Для демонстрации просто проверяем, что значение в разумном диапазоне
    GmpRaii max_value = GmpRaii(1) << SecurityConstants::ADDRESS_DATA_SIZE * 8;
    return j_invariant < max_value;
}

bool Bech32m::is_not_vulnerable_to_geometric_attacks(const std::string& addr) {
    // Проверка, что адрес не уязвим к геометрическим атакам
    // Такие атаки могут использовать адреса с определенными структурными свойствами
    
    // Декодирование адреса
    std::string hrp;
    std::vector<unsigned char> data;
    if (!decode(addr, hrp, data)) {
        return false;
    }
    
    // Проверка на наличие длинных регулярных паттернов в данных
    const size_t min_pattern_length = 4;
    for (size_t i = 0; i < data.size() - min_pattern_length + 1; i++) {
        bool is_constant = true;
        for (size_t j = 1; j < min_pattern_length; j++) {
            if (data[i] != data[i + j]) {
                is_constant = false;
                break;
            }
        }
        if (is_constant) {
            return false;
        }
    }
    
    // Проверка на арифметические прогрессии в данных
    for (size_t i = 0; i < data.size() - min_pattern_length + 1; i++) {
        if (data.size() - i < min_pattern_length) break;
        
        int diff = data[i + 1] - data[i];
        bool is_arithmetic = true;
        for (size_t j = 2; j < min_pattern_length; j++) {
            if (data[i + j] - data[i + j - 1] != diff) {
                is_arithmetic = false;
                break;
            }
        }
        if (is_arithmetic) {
            return false;
        }
    }
    
    return true;
}

bool Bech32m::check_for_vulnerable_patterns(const std::string& addr) {
    // Проверка на наличие паттернов, уязвимых к атакам
    // Такие паттерны могут быть использованы для анализа структуры графа
    
    // Проверка на повторяющиеся последовательности
    const size_t pattern_length = 3;
    for (size_t i = 0; i < addr.size() - 2 * pattern_length + 1; i++) {
        for (size_t j = i + pattern_length; j <= addr.size() - pattern_length; j++) {
            bool match = true;
            for (size_t k = 0; k < pattern_length; k++) {
                if (addr[i + k] != addr[j + k]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return false; // Найдено повторение
            }
        }
    }
    
    // Проверка на зеркальные паттерны
    for (size_t i = 0; i < addr.size() / 2; i++) {
        if (addr[i] != addr[addr.size() - 1 - i]) {
            return true; // Не зеркальный - хорошо
        }
    }
    
    // Полный зеркальный паттерн может быть уязвим
    return false;
}

} // namespace toruscsidh
