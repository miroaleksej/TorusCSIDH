#include <gtest/gtest.h>
#include "bech32m.h"
#include <vector>
#include <string>

class Bech32mTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Подготовка тестовых данных
        hrp = "tcidh";
        valid_data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
        invalid_data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xff}; // Последний байт с битом вне диапазона
    }
    
    std::string hrp;
    std::vector<unsigned char> valid_data;
    std::vector<unsigned char> invalid_data;
};

TEST_F(Bech32mTest, EncodeDecodeRoundTrip) {
    // Тестирование кодирования и декодирования
    std::string encoded = bech32m::encode(hrp, valid_data);
    
    // Проверка, что закодированная строка не пустая
    ASSERT_FALSE(encoded.empty());
    
    // Проверка, что строка начинается с HRP
    size_t sep_pos = encoded.find('1');
    ASSERT_NE(sep_pos, std::string::npos);
    ASSERT_EQ(encoded.substr(0, sep_pos), hrp);
    
    // Декодирование
    std::string hrp_out;
    std::vector<unsigned char> values_out;
    bool success = bech32m::decode(encoded, hrp_out, values_out);
    
    // Проверка успешности декодирования
    EXPECT_TRUE(success);
    
    // Проверка HRP
    EXPECT_EQ(hrp_out, hrp);
    
    // Проверка данных
    ASSERT_EQ(values_out.size(), valid_data.size());
    for (size_t i = 0; i < valid_data.size(); i++) {
        EXPECT_EQ(values_out[i], valid_data[i]);
    }
}

TEST_F(Bech32mTest, InvalidChecksum) {
    // Тестирование неверной контрольной суммы
    std::string encoded = bech32m::encode(hrp, valid_data);
    
    // Меняем последний символ (контрольную сумму)
    if (encoded.size() > 1) {
        encoded[encoded.size() - 1] = (encoded[encoded.size() - 1] == 'q') ? 'p' : 'q';
    }
    
    // Декодирование
    std::string hrp_out;
    std::vector<unsigned char> values_out;
    bool success = bech32m::decode(encoded, hrp_out, values_out);
    
    // Проверка неуспешности декодирования
    EXPECT_FALSE(success);
}

TEST_F(Bech32mTest, InvalidHRP) {
    // Тестирование недопустимого HRP
    std::string invalid_hrp = "t cidh"; // Пробел в HRP
    
    // Попытка кодирования
    try {
        bech32m::encode(invalid_hrp, valid_data);
        FAIL() << "Expected std::invalid_argument";
    } catch (const std::invalid_argument&) {
        // Ожидаемое исключение
    }
}

TEST_F(Bech32mTest, InvalidData) {
    // Тестирование недопустимых данных
    try {
        bech32m::encode(hrp, invalid_data);
        FAIL() << "Expected std::invalid_argument";
    } catch (const std::invalid_argument&) {
        // Ожидаемое исключение
    }
}

TEST_F(Bech32mTest, ShortData) {
    // Тестирование коротких данных
    std::vector<unsigned char> short_data = {0x01};
    std::string encoded = bech32m::encode(hrp, short_data);
    
    // Декодирование
    std::string hrp_out;
    std::vector<unsigned char> values_out;
    bool success = bech32m::decode(encoded, hrp_out, values_out);
    
    // Проверка успешности декодирования
    EXPECT_TRUE(success);
    
    // Проверка данных
    ASSERT_EQ(values_out.size(), short_data.size());
    EXPECT_EQ(values_out[0], short_data[0]);
}

TEST_F(Bech32mTest, LongData) {
    // Тестирование длинных данных
    std::vector<unsigned char> long_data(100);
    for (size_t i = 0; i < long_data.size(); i++) {
        long_data[i] = static_cast<unsigned char>(i % 256);
    }
    
    std::string encoded = bech32m::encode(hrp, long_data);
    
    // Декодирование
    std::string hrp_out;
    std::vector<unsigned char> values_out;
    bool success = bech32m::decode(encoded, hrp_out, values_out);
    
    // Проверка успешности декодирования
    EXPECT_TRUE(success);
    
    // Проверка данных
    ASSERT_EQ(values_out.size(), long_data.size());
    for (size_t i = 0; i < long_data.size(); i++) {
        EXPECT_EQ(values_out[i], long_data[i]);
    }
}

TEST_F(Bech32mTest, PolymodCalculation) {
    // Тестирование вычисления polymod
    std::vector<unsigned char> values = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    
    unsigned int result = bech32m::polymod(values, bech32m::BECH32M_GENERATOR);
    
    // Проверка, что результат не равен модификатору (иначе контрольная сумма будет нулевой)
    EXPECT_NE(result, 0x2bc830a3);
}

TEST_F(Bech32mTest, ChecksumValidation) {
    // Тестирование проверки контрольной суммы
    std::vector<unsigned char> values = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    
    // Создание контрольной суммы
    std::vector<unsigned char> checksum = bech32m::create_checksum(hrp, values);
    
    // Проверка, что контрольная сумма имеет правильный размер
    ASSERT_EQ(checksum.size(), 6);
    
    // Проверка, что контрольная сумма не пустая
    bool all_zeros = true;
    for (unsigned char c : checksum) {
        if (c != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros);
}

TEST_F(Bech32mTest, ConvertBits) {
    // Тестирование преобразования битов
    std::vector<unsigned char> data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    
    // Преобразование в 5-битные данные
    std::vector<unsigned char> data5 = bech32m::convert_bits(data, true);
    
    // Проверка, что данные преобразованы
    ASSERT_GT(data5.size(), 0);
    
    // Преобразование обратно в 8-битные данные
    std::vector<unsigned char> data8 = bech32m::convert_bits_back(data5, true);
    
    // Проверка, что данные совпадают с исходными
    ASSERT_EQ(data8.size(), data.size());
    for (size_t i = 0; i < data.size(); i++) {
        EXPECT_EQ(data8[i], data[i]);
    }
}

TEST_F(Bech32mTest, ConvertBitsNoPadding) {
    // Тестирование преобразования битов без дополнения
    std::vector<unsigned char> data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    
    // Преобразование в 5-битные данные без дополнения
    std::vector<unsigned char> data5 = bech32m::convert_bits(data, false);
    
    // Проверка, что данные преобразованы
    ASSERT_GT(data5.size(), 0);
    
    // Преобразование обратно в 8-битные данные без дополнения
    std::vector<unsigned char> data8 = bech32m::convert_bits_back(data5, false);
    
    // Проверка, что данные совпадают с исходными
    ASSERT_EQ(data8.size(), data.size());
    for (size_t i = 0; i < data.size(); i++) {
        EXPECT_EQ(data8[i], data[i]);
    }
}

TEST_F(Bech32mTest, ModularEquationDegree3) {
    // Тестирование модулярного уравнения для степени 3
    GmpRaii j1(1728); // j-инвариант для кривой y² = x³ + x
    GmpRaii j2(0);    // j-инвариант для кривой y² = x³ + 1
    GmpRaii p(101);  // Простое число для тестирования
    
    bool result = bech32m::verify_modular_equation(j1, j2, 3, p);
    
    // Проверка, что результат соответствует ожидаемому
    // Для j1=1728 и j2=0 модулярное уравнение для степени 3 должно выполняться
    EXPECT_TRUE(result);
}

TEST_F(Bech32mTest, ModularEquationDegree5) {
    // Тестирование модулярного уравнения для степени 5
    GmpRaii j1(1728);
    GmpRaii j2(0);
    GmpRaii p(101);
    
    bool result = bech32m::verify_modular_equation(j1, j2, 5, p);
    
    // Проверка, что результат соответствует ожидаемому
    // Для j1=1728 и j2=0 модулярное уравнение для степени 5 должно выполняться
    EXPECT_TRUE(result);
}

TEST_F(Bech32mTest, ModularEquationDegree7) {
    // Тестирование модулярного уравнения для степени 7
    GmpRaii j1(1728);
    GmpRaii j2(0);
    GmpRaii p(101);
    
    bool result = bech32m::verify_modular_equation(j1, j2, 7, p);
    
    // Проверка, что результат соответствует ожидаемому
    // Для j1=1728 и j2=0 модулярное уравнение для степени 7 должно выполняться
    EXPECT_TRUE(result);
}

TEST_F(Bech32mTest, ModularEquationInvalidDegree) {
    // Тестирование модулярного уравнения для недопустимой степени
    GmpRaii j1(1728);
    GmpRaii j2(0);
    GmpRaii p(101);
    
    // Попытка вычисления для недопустимой степени
    try {
        bech32m::verify_modular_equation(j1, j2, 4, p);
        FAIL() << "Expected std::invalid_argument";
    } catch (const std::invalid_argument&) {
        // Ожидаемое исключение
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
