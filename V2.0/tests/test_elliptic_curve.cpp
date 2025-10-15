#include <gtest/gtest.h>
#include "elliptic_curve.h"
#include "security_constants.h"
#include "secure_random.h"
#include "postquantum_hash.h"

class EllipticCurveTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Инициализация базовой кривой для уровня безопасности 128 бит
        base_curve = SecurityConstants::get_base_curve(SecurityConstants::LEVEL_128);
        
        // Получение параметров безопасности
        params = SecurityConstants::get_params(SecurityConstants::LEVEL_128);
    }
    
    MontgomeryCurve base_curve;
    SecurityConstants::SecurityParams params;
};

TEST_F(EllipticCurveTest, PointOnCurve) {
    // Проверка, что точка лежит на кривой
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    for (size_t i = 0; i < std::min(5UL, primes.size()); i++) {
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(primes[i].get_mpz_t()));
        EllipticCurvePoint point = base_curve.find_point_of_order(degree);
        
        // Проверка, что точка не является бесконечностью
        ASSERT_FALSE(point.is_infinity());
        
        // Проверка, что точка лежит на кривой
        EXPECT_TRUE(point.is_on_curve(base_curve));
        
        // Проверка, что точка имеет правильный порядок
        EXPECT_TRUE(point.has_small_order(degree, base_curve));
    }
}

TEST_F(EllipticCurveTest, CurveOperations) {
    // Проверка операций над кривой
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    // Выбираем первое простое число
    if (primes.empty()) {
        GTEST_SKIP() << "No primes available for testing";
    }
    
    unsigned int degree = static_cast<unsigned int>(mpz_get_ui(primes[0].get_mpz_t()));
    EllipticCurvePoint point = base_curve.find_point_of_order(degree);
    
    ASSERT_FALSE(point.is_infinity());
    
    // Проверка удвоения точки
    EllipticCurvePoint double_point = point.double_point(base_curve);
    EllipticCurvePoint add_point = point.add(point, base_curve);
    
    // Проверка, что удвоение и сложение дают одинаковый результат
    EXPECT_TRUE(double_point.is_equal_to(add_point));
    
    // Проверка умножения точки на скаляр
    GmpRaii scalar(2);
    EllipticCurvePoint multiply_point = point.multiply(scalar, base_curve);
    
    // Проверка, что умножение на 2 дает тот же результат
    EXPECT_TRUE(multiply_point.is_equal_to(double_point));
    
    // Проверка умножения на больший скаляр
    scalar = GmpRaii(5);
    multiply_point = point.multiply(scalar, base_curve);
    
    EllipticCurvePoint expected_point = double_point;
    for (int i = 0; i < 3; i++) {
        expected_point = expected_point.add(point, base_curve);
    }
    
    // Проверка, что умножение на 5 дает правильный результат
    EXPECT_TRUE(multiply_point.is_equal_to(expected_point));
}

TEST_F(EllipticCurveTest, IsogenyComputation) {
    // Проверка вычисления изогении
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    for (size_t i = 0; i < std::min(3UL, primes.size()); i++) {
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(primes[i].get_mpz_t()));
        EllipticCurvePoint kernel_point = base_curve.find_point_of_order(degree);
        
        if (kernel_point.is_infinity()) {
            continue;
        }
        
        // Вычисление изогении
        MontgomeryCurve isogeny_curve = base_curve.compute_isogeny(kernel_point, degree);
        
        // Проверка, что кривая суперсингулярна
        EXPECT_TRUE(isogeny_curve.is_supersingular());
        
        // Проверка, что кривая имеет правильный порядок
        GmpRaii curve_order = isogeny_curve.compute_order();
        GmpRaii expected_order = base_curve.get_p() + GmpRaii(1);
        EXPECT_EQ(curve_order, expected_order);
        
        // Проверка, что изогения сохраняет структуру кривой
        GmpRaii j1 = base_curve.compute_j_invariant();
        GmpRaii j2 = isogeny_curve.compute_j_invariant();
        
        // Проверка модулярного уравнения
        bool modular_eq = bech32m::verify_modular_equation(j1, j2, degree, base_curve.get_p());
        EXPECT_TRUE(modular_eq);
    }
}

TEST_F(EllipticCurveTest, IsogenyComposition) {
    // Проверка композиции изогений
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    if (primes.size() < 2) {
        GTEST_SKIP() << "Not enough primes for testing";
    }
    
    unsigned int degree1 = static_cast<unsigned int>(mpz_get_ui(primes[0].get_mpz_t()));
    unsigned int degree2 = static_cast<unsigned int>(mpz_get_ui(primes[1].get_mpz_t()));
    
    EllipticCurvePoint kernel_point1 = base_curve.find_point_of_order(degree1);
    EllipticCurvePoint kernel_point2 = base_curve.find_point_of_order(degree2);
    
    ASSERT_FALSE(kernel_point1.is_infinity());
    ASSERT_FALSE(kernel_point2.is_infinity());
    
    // Вычисление композиции изогений в одном порядке
    MontgomeryCurve curve1 = base_curve.compute_isogeny(kernel_point1, degree1);
    curve1 = curve1.compute_isogeny(kernel_point2, degree2);
    
    // Вычисление композиции изогений в другом порядке
    MontgomeryCurve curve2 = base_curve.compute_isogeny(kernel_point2, degree2);
    curve2 = curve2.compute_isogeny(kernel_point1, degree1);
    
    // Проверка коммутативности (для взаимно простых степеней)
    if (std::gcd(degree1, degree2) == 1) {
        GmpRaii j1 = curve1.compute_j_invariant();
        GmpRaii j2 = curve2.compute_j_invariant();
        
        EXPECT_EQ(j1, j2);
    }
}

TEST_F(EllipticCurveTest, CurveEquivalence) {
    // Проверка эквивалентности кривых
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    if (primes.empty()) {
        GTEST_SKIP() << "No primes available for testing";
    }
    
    unsigned int degree = static_cast<unsigned int>(mpz_get_ui(primes[0].get_mpz_t()));
    EllipticCurvePoint kernel_point = base_curve.find_point_of_order(degree);
    
    ASSERT_FALSE(kernel_point.is_infinity());
    
    // Вычисление изогении
    MontgomeryCurve isogeny_curve = base_curve.compute_isogeny(kernel_point, degree);
    
    // Проверка, что кривые не эквивалентны (так как это изогения)
    EXPECT_FALSE(base_curve.is_equivalent_to(isogeny_curve));
    
    // Вычисление обратной изогении
    EllipticCurvePoint inverse_kernel_point = isogeny_curve.find_point_of_order(degree);
    MontgomeryCurve inverse_curve = isogeny_curve.compute_isogeny(inverse_kernel_point, degree);
    
    // Проверка, что обратная изогения возвращает исходную кривую
    EXPECT_TRUE(base_curve.is_equivalent_to(inverse_curve));
}

TEST_F(EllipticCurveTest, ConstantTimeOperations) {
    // Проверка, что операции выполняются за постоянное время
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    if (primes.empty()) {
        GTEST_SKIP() << "No primes available for testing";
    }
    
    unsigned int degree = static_cast<unsigned int>(mpz_get_ui(primes[0].get_mpz_t()));
    EllipticCurvePoint kernel_point = base_curve.find_point_of_order(degree);
    
    ASSERT_FALSE(kernel_point.is_infinity());
    
    // Измеряем время вычисления изогении
    auto start1 = std::chrono::high_resolution_clock::now();
    MontgomeryCurve curve1 = base_curve.compute_isogeny(kernel_point, degree);
    auto end1 = std::chrono::high_resolution_clock::now();
    
    // Создаем другую точку и измеряем время
    EllipticCurvePoint kernel_point2 = base_curve.find_point_of_order(degree);
    auto start2 = std::chrono::high_resolution_clock::now();
    MontgomeryCurve curve2 = base_curve.compute_isogeny(kernel_point2, degree);
    auto end2 = std::chrono::high_resolution_clock::now();
    
    // Вычисляем разницу во времени
    auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(end1 - start1).count();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end2 - start2).count();
    auto time_diff = std::abs(duration1 - duration2);
    
    // Проверка, что разница во времени незначительна
    EXPECT_LT(time_diff, 10); // Допускаем разницу до 10 микросекунд
}

TEST_F(EllipticCurveTest, SmallKeyVerification) {
    // Проверка "малости" ключа
    std::vector<short> key(params.num_primes);
    
    // Генерация "малого" ключа
    int max_abs = params.max_key_magnitude;
    for (short& val : key) {
        val = static_cast<short>(SecureRandom::random_int(-max_abs, max_abs));
    }
    
    // Проверка, что ключ "малый"
    bool is_small = true;
    for (const short& val : key) {
        if (std::abs(val) > params.max_key_magnitude) {
            is_small = false;
            break;
        }
    }
    
    EXPECT_TRUE(is_small);
    
    // Генерация "большого" ключа
    std::vector<short> large_key(params.num_primes);
    for (short& val : large_key) {
        val = static_cast<short>(SecureRandom::random_int(-2*max_abs, 2*max_abs));
    }
    
    // Проверка, что ключ не "малый"
    bool is_large_small = true;
    for (const short& val : large_key) {
        if (std::abs(val) > params.max_key_magnitude) {
            is_large_small = false;
            break;
        }
    }
    
    EXPECT_FALSE(is_large_small);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
