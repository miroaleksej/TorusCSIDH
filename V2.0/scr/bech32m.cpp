#include "bech32m.h"
#include <vector>
#include <string>
#include <algorithm>
#include <stdexcept>

namespace bech32m {

// Генератор для Bech32m
const unsigned int BECH32M_GENERATOR[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

// Алфавит для Bech32m
const char* BECH32M_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/**
 * @brief Полиномиальное модулярное умножение для Bech32m
 * 
 * @param values Значения
 * @param generator Генератор
 * @return Результат полиномиального умножения
 */
unsigned int polymod(const std::vector<unsigned char>& values, const unsigned int* generator) {
    unsigned int chk = 1;
    for (unsigned char v : values) {
        unsigned int b = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ v;
        
        for (int i = 0; i < 5; i++) {
            if ((b >> i) & 1) {
                chk ^= generator[i];
            }
        }
    }
    
    return chk;
}

/**
 * @brief Создание контрольной суммы Bech32m
 * 
 * @param hrp Человекочитаемая часть
 * @param values Значения
 * @return Контрольная сумма
 */
std::vector<unsigned char> create_checksum(const std::string& hrp, const std::vector<unsigned char>& values) {
    std::vector<unsigned char> encoding;
    
    // Добавляем HRP в последовательность
    for (char c : hrp) {
        encoding.push_back(c >> 5);
    }
    encoding.push_back(0); // Сепаратор
    for (char c : hrp) {
        encoding.push_back(c & 0x1f);
    }
    
    // Добавляем данные
    encoding.insert(encoding.end(), values.begin(), values.end());
    
    // Добавляем фиксированные значения для контрольной суммы
    encoding.push_back(0);
    encoding.push_back(0);
    encoding.push_back(0);
    encoding.push_back(0);
    encoding.push_back(0);
    encoding.push_back(0);
    
    // Вычисляем контрольную сумму
    unsigned int chk = polymod(encoding, BECH32M_GENERATOR);
    chk = chk ^ 0x2bc830a3; // Модификатор для Bech32m
    
    std::vector<unsigned char> checksum(6);
    for (int i = 0; i < 6; i++) {
        checksum[i] = (chk >> (5 * (5 - i))) & 0x1f;
    }
    
    return checksum;
}

/**
 * @brief Проверка контрольной суммы Bech32m
 * 
 * @param hrp Человекочитаемая часть
 * @param values Значения
 * @return true, если контрольная сумма верна
 */
bool verify_checksum(const std::string& hrp, const std::vector<unsigned char>& values) {
    std::vector<unsigned char> encoding;
    
    // Добавляем HRP в последовательность
    for (char c : hrp) {
        encoding.push_back(c >> 5);
    }
    encoding.push_back(0); // Сепаратор
    for (char c : hrp) {
        encoding.push_back(c & 0x1f);
    }
    
    // Добавляем данные
    encoding.insert(encoding.end(), values.begin(), values.end());
    
    return polymod(encoding, BECH32M_GENERATOR) == 0x2bc830a3;
}

/**
 * @brief Преобразование 8-битных данных в 5-битные
 * 
 * @param data 8-битные данные
 * @param pad Добавление нулей
 * @return 5-битные данные
 */
std::vector<unsigned char> convert_bits(const std::vector<unsigned char>& data, bool pad) {
    int acc = 0;
    int bits = 0;
    std::vector<unsigned char> result;
    const int maxv = (1 << 5) - 1;
    
    for (unsigned char value : data) {
        if ((value >> 8) != 0) {
            throw std::invalid_argument("Invalid value for conversion");
        }
        
        acc = (acc << 8) | value;
        bits += 8;
        
        while (bits >= 5) {
            bits -= 5;
            result.push_back((acc >> bits) & maxv);
        }
    }
    
    if (pad) {
        if (bits > 0) {
            result.push_back((acc << (5 - bits)) & maxv);
        }
    } else if (bits >= 5 || ((acc << (5 - bits)) & maxv)) {
        throw std::invalid_argument("Illegal zero padding");
    }
    
    return result;
}

/**
 * @brief Преобразование 5-битных данных в 8-битные
 * 
 * @param data 5-битные данные
 * @param pad Добавление нулей
 * @return 8-битные данные
 */
std::vector<unsigned char> convert_bits_back(const std::vector<unsigned char>& data, bool pad) {
    int acc = 0;
    int bits = 0;
    std::vector<unsigned char> result;
    const int maxv = (1 << 8) - 1;
    
    for (unsigned char value : data) {
        if ((value >> 5) != 0) {
            throw std::invalid_argument("Invalid value for conversion");
        }
        
        acc = (acc << 5) | value;
        bits += 5;
        
        while (bits >= 8) {
            bits -= 8;
            result.push_back((acc >> bits) & maxv);
        }
    }
    
    if (pad) {
        if (bits > 0) {
            result.push_back((acc << (8 - bits)) & maxv);
        }
    } else if (bits >= 8 || ((acc << (8 - bits)) & maxv)) {
        throw std::invalid_argument("Illegal zero padding");
    }
    
    return result;
}

/**
 * @brief Кодирование в формат Bech32m
 * 
 * @param hrp Человекочитаемая часть
 * @param values Значения для кодирования
 * @return Закодированная строка
 */
std::string encode(const std::string& hrp, const std::vector<unsigned char>& values) {
    // Проверяем HRP
    if (hrp.size() < 1 || hrp.size() > 83) {
        throw std::invalid_argument("Invalid HRP length");
    }
    
    for (char c : hrp) {
        if (c < 33 || c > 126) {
            throw std::invalid_argument("Invalid character in HRP");
        }
    }
    
    // Конвертируем значения в 5-битные
    std::vector<unsigned char> values5 = convert_bits(values, true);
    
    // Создаем контрольную сумму
    std::vector<unsigned char> checksum = create_checksum(hrp, values5);
    
    // Формируем полные данные
    std::vector<unsigned char> combined = values5;
    combined.insert(combined.end(), checksum.begin(), checksum.end());
    
    // Формируем строку
    std::string result = hrp + "1";
    for (unsigned char c : combined) {
        if (c >= 32) {
            throw std::invalid_argument("Invalid value for Bech32m encoding");
        }
        result += BECH32M_CHARSET[c];
    }
    
    return result;
}

/**
 * @brief Декодирование из формата Bech32m
 * 
 * @param encoded Закодированная строка
 * @param hrp_out Человекочитаемая часть
 * @param values_out Значения
 * @return true, если декодирование прошло успешно
 */
bool decode(const std::string& encoded, std::string& hrp_out, std::vector<unsigned char>& values_out) {
    // Проверяем длину
    if (encoded.size() < 8 || encoded.size() > 90) {
        return false;
    }
    
    // Находим сепаратор
    size_t sep_pos = encoded.find('1');
    if (sep_pos == std::string::npos || sep_pos < 1 || sep_pos > 83) {
        return false;
    }
    
    // Проверяем HRP
    hrp_out = encoded.substr(0, sep_pos);
    for (char c : hrp_out) {
        if (c < 33 || c > 126) {
            return false;
        }
    }
    
    // Декодируем символы
    std::vector<unsigned char> values;
    for (size_t i = sep_pos + 1; i < encoded.size(); i++) {
        char c = encoded[i];
        
        // Находим индекс в алфавите
        size_t index = std::string(BECH32M_CHARSET).find(c);
        if (index == std::string::npos) {
            return false;
        }
        
        values.push_back(static_cast<unsigned char>(index));
    }
    
    // Проверяем контрольную сумму
    if (values.size() < 6) {
        return false;
    }
    
    std::vector<unsigned char> checksum(values.end() - 6, values.end());
    values.resize(values.size() - 6);
    
    // Создаем последовательность для проверки
    std::vector<unsigned char> encoding;
    for (char c : hrp_out) {
        encoding.push_back(c >> 5);
    }
    encoding.push_back(0); // Сепаратор
    for (char c : hrp_out) {
        encoding.push_back(c & 0x1f);
    }
    encoding.insert(encoding.end(), values.begin(), values.end());
    
    if (polymod(encoding, BECH32M_GENERATOR) != 0x2bc830a3) {
        return false;
    }
    
    // Конвертируем обратно в 8-битные данные
    try {
        values_out = convert_bits_back(values, true);
    } catch (const std::exception&) {
        return false;
    }
    
    return true;
}

} // namespace bech32m
