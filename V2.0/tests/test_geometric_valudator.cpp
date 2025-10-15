#include <gtest/gtest.h>
#include "geometric_validator.h"
#include "elliptic_curve.h"
#include "security_constants.h"
#include "secure_random.h"

class GeometricValidatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Инициализация базовой кривой для уровня безопасности 128 бит
        base_curve = SecurityConstants::get_base_curve(SecurityConstants::LEVEL_128);
        
        // Создание валидатора
        validator = std::make_unique<GeometricValidator>();
        
        // Получение параметров безопасности
        params = SecurityConstants::get_geometric_params(SecurityConstants::LEVEL_128);
    }
    
    MontgomeryCurve base_curve;
    std::unique_ptr<GeometricValidator> validator;
    SecurityConstants::GeometricParams params;
};

TEST_F(GeometricValidatorTest, ValidateBaseCurve) {
    double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
    
    // Проверка базовой кривой
    bool is_valid = validator->validate_curve(
        base_curve, cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score);
    
    // Проверка, что кривая проходит геометрическую проверку
    EXPECT_TRUE(is_valid);
    
    // Проверка, что все показатели соответствуют критериям
    EXPECT_GE(cyclomatic_score, params.min_cyclomatic);
    EXPECT_GE(spectral_score, params.min_spectral_gap);
    EXPECT_GE(clustering_score, params.min_clustering_coeff);
    EXPECT_GE(entropy_score, params.min_degree_entropy);
    EXPECT_GE(distance_score, params.min_distance_entropy);
}

TEST_F(GeometricValidatorTest, ValidateLongPathCurve) {
    // Создаем кривую с длинным путем
    MontgomeryCurve long_path_curve = base_curve;
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    // Применяем длинный путь изогений
    for (size_t i = 0; i < primes.size(); i++) {
        int exp = 5; // Искусственно создаем длинный путь
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(primes[i].get_mpz_t()));
        
        for (int j = 0; j < std::abs(exp); j++) {
            EllipticCurvePoint kernel_point = long_path_curve.find_point_of_order(degree);
            if (!kernel_point.is_infinity()) {
                long_path_curve = long_path_curve.compute_isogeny(kernel_point, degree);
            }
        }
    }
    
    double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
    
    // Проверка кривой с длинным путем
    bool is_valid = validator->validate_curve(
        long_path_curve, cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score);
    
    // Проверка, что кривая НЕ проходит геометрическую проверку
    EXPECT_FALSE(is_valid);
    
    // Проверка, что показатели ниже критических значений
    EXPECT_LT(cyclomatic_score, params.min_cyclomatic);
    EXPECT_LT(spectral_score, params.min_spectral_gap);
}

TEST_F(GeometricValidatorTest, ValidateDegenerateTopologyCurve) {
    // Создаем кривую с вырожденной топологией
    MontgomeryCurve degenerate_curve = base_curve;
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    // Применяем изогении для создания вырожденной структуры
    for (size_t i = 0; i < primes.size(); i++) {
        int exp = (i % 2 == 0) ? 1 : 0; // Создаем вырожденную структуру
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(primes[i].get_mpz_t()));
        
        for (int j = 0; j < std::abs(exp); j++) {
            EllipticCurvePoint kernel_point = degenerate_curve.find_point_of_order(degree);
            if (!kernel_point.is_infinity()) {
                degenerate_curve = degenerate_curve.compute_isogeny(kernel_point, degree);
            }
        }
    }
    
    double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
    
    // Проверка кривой с вырожденной топологией
    bool is_valid = validator->validate_curve(
        degenerate_curve, cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score);
    
    // Проверка, что кривая НЕ проходит геометрическую проверку
    EXPECT_FALSE(is_valid);
    
    // Проверка, что показатели ниже критических значений
    EXPECT_LT(clustering_score, params.min_clustering_coeff);
    EXPECT_LT(entropy_score, params.min_degree_entropy);
}

TEST_F(GeometricValidatorTest, ValidateRandomCurve) {
    // Создаем случайную кривую
    MontgomeryCurve random_curve = base_curve;
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    // Применяем случайные изогении
    for (size_t i = 0; i < primes.size(); i++) {
        int exp = SecureRandom::random_int(-3, 3);
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(primes[i].get_mpz_t()));
        
        for (int j = 0; j < std::abs(exp); j++) {
            EllipticCurvePoint kernel_point = random_curve.find_point_of_order(degree);
            if (!kernel_point.is_infinity()) {
                random_curve = random_curve.compute_isogeny(kernel_point, degree);
            }
        }
    }
    
    double cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score;
    
    // Проверка случайной кривой
    bool is_valid = validator->validate_curve(
        random_curve, cyclomatic_score, spectral_score, clustering_score, entropy_score, distance_score);
    
    // Проверка, что кривая проходит геометрическую проверку
    EXPECT_TRUE(is_valid);
    
    // Проверка, что все показатели соответствуют критериям
    EXPECT_GE(cyclomatic_score, params.min_cyclomatic);
    EXPECT_GE(spectral_score, params.min_spectral_gap);
    EXPECT_GE(clustering_score, params.min_clustering_coeff);
    EXPECT_GE(entropy_score, params.min_degree_entropy);
    EXPECT_GE(distance_score, params.min_distance_entropy);
}

TEST_F(GeometricValidatorTest, ValidateSubgraphStructure) {
    // Создаем подграф изогений
    std::vector<MontgomeryCurve> subgraph;
    subgraph.push_back(base_curve);
    
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    // Добавляем несколько кривых в подграф
    for (size_t i = 0; i < 5 && i < primes.size(); i++) {
        MontgomeryCurve curve = base_curve;
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(primes[i].get_mpz_t()));
        
        for (int j = 0; j < 2; j++) {
            EllipticCurvePoint kernel_point = curve.find_point_of_order(degree);
            if (!kernel_point.is_infinity()) {
                curve = curve.compute_isogeny(kernel_point, degree);
            }
        }
        
        subgraph.push_back(curve);
    }
    
    // Проверка структуры подграфа
    bool structure_valid = validator->validate_subgraph_structure(subgraph);
    
    // Проверка, что структура подграфа корректна
    EXPECT_TRUE(structure_valid);
    
    // Проверка, что подграф имеет правильные свойства
    double cyclomatic_number = validator->compute_cyclomatic_number(subgraph);
    double spectral_gap = validator->compute_spectral_gap(subgraph);
    
    EXPECT_GE(cyclomatic_number, 0.0);
    EXPECT_GE(spectral_gap, 0.0);
}

TEST_F(GeometricValidatorTest, ValidateConstantTime) {
    // Проверка, что геометрическая проверка выполняется за постоянное время
    MontgomeryCurve curve1 = base_curve;
    MontgomeryCurve curve2 = base_curve;
    
    const auto& primes = SecurityConstants::get_primes(SecurityConstants::LEVEL_128);
    
    // Создаем две кривые с разной структурой
    for (size_t i = 0; i < 3 && i < primes.size(); i++) {
        unsigned int degree = static_cast<unsigned int>(mpz_get_ui(primes[i].get_mpz_t()));
        
        EllipticCurvePoint kernel_point1 = curve1.find_point_of_order(degree);
        if (!kernel_point1.is_infinity()) {
            curve1 = curve1.compute_isogeny(kernel_point1, degree);
        }
        
        for (int j = 0; j < 2; j++) {
            EllipticCurvePoint kernel_point2 = curve2.find_point_of_order(degree);
            if (!kernel_point2.is_infinity()) {
                curve2 = curve2.compute_isogeny(kernel_point2, degree);
            }
        }
    }
    
    // Измеряем время выполнения для первой кривой
    auto start1 = std::chrono::high_resolution_clock::now();
    double cyclomatic_score1, spectral_score1, clustering_score1, entropy_score1, distance_score1;
    validator->validate_curve(curve1, cyclomatic_score1, spectral_score1, clustering_score1, entropy_score1, distance_score1);
    auto end1 = std::chrono::high_resolution_clock::now();
    
    // Измеряем время выполнения для второй кривой
    auto start2 = std::chrono::high_resolution_clock::now();
    double cyclomatic_score2, spectral_score2, clustering_score2, entropy_score2, distance_score2;
    validator->validate_curve(curve2, cyclomatic_score2, spectral_score2, clustering_score2, entropy_score2, distance_score2);
    auto end2 = std::chrono::high_resolution_clock::now();
    
    // Вычисляем разницу во времени
    auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(end1 - start1).count();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end2 - start2).count();
    auto time_diff = std::abs(duration1 - duration2);
    
    // Проверка, что разница во времени незначительна
    EXPECT_LT(time_diff, 10); // Допускаем разницу до 10 микросекунд
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
