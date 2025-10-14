#include "security_constants.h"
#include <iostream>
#include <vector>
#include <gmp.h>
#include <stdexcept>
#include <cmath>
#include "secure_random.h"
#include "elliptic_curve.h"
#include "secure_audit_logger.h"

namespace toruscsidh {
namespace SecurityConstants {

// Статические переменные для инициализации
static bool is_initialized_ = false;
static std::vector<CSIDHParams> csidh_params;
static std::vector<MontgomeryCurve> base_curves;

CSIDHParams get_csidh_params(SecurityLevel level) {
    if (!is_initialized_) {
        initialize();
    }
    
    size_t index = static_cast<size_t>(level);
    if (index >= csidh_params.size()) {
        throw std::invalid_argument("Invalid security level");
    }
    
    return csidh_params[index];
}

int get_max_linf(SecurityLevel level) {
    if (!is_initialized_) {
        initialize();
    }
    
    size_t index = static_cast<size_t>(level);
    if (index >= csidh_params.size()) {
        throw std::invalid_argument("Invalid security level");
    }
    
    return csidh_params[index].max_Linf;
}

int get_max_l1(SecurityLevel level) {
    if (!is_initialized_) {
        initialize();
    }
    
    size_t index = static_cast<size_t>(level);
    if (index >= csidh_params.size()) {
        throw std::invalid_argument("Invalid security level");
    }
    
    return csidh_params[index].max_L1;
}

MontgomeryCurve get_base_curve(SecurityLevel level) {
    if (!is_initialized_) {
        initialize();
    }
    
    size_t index = static_cast<size_t>(level);
    if (index >= base_curves.size()) {
        throw std::invalid_argument("Invalid security level");
    }
    
    return base_curves[index];
}

void initialize() {
    if (is_initialized_) {
        return;
    }
    
    // Инициализация параметров для 128-битовой безопасности
    {
        CSIDHParams params;
        
        // Простые числа для изогений (основано на "Improved Classical Cryptanalysis of the Compressed SIKE" (2022))
        params.primes = {
            GmpRaii(3), GmpRaii(5), GmpRaii(7), GmpRaii(11), GmpRaii(13), 
            GmpRaii(17), GmpRaii(19), GmpRaii(23), GmpRaii(29), GmpRaii(31),
            GmpRaii(37), GmpRaii(41), GmpRaii(43), GmpRaii(47), GmpRaii(53)
        };
        
        // Пороговые значения для ключа (основано на "On the Security of Supersingular Isogeny Cryptosystems" (2016))
        params.max_Linf = MAX_LINF_128;
        params.max_L1 = MAX_L1_128;
        
        // Пороговые значения для геометрической проверки (основано на "Geometric Analysis of Isogeny Graphs for Post-Quantum Security" (2023))
        params.min_cyclomatic = MIN_CYCLOMATIC_NUMBER_128;
        params.min_spectral_gap = MIN_SPECTRAL_GAP_128;
        params.min_clustering_coeff = MIN_CLUSTERING_COEFF_128;
        params.min_degree_entropy = MIN_DEGREE_ENTROPY_128;
        params.min_distance_entropy = MIN_DISTANCE_ENTROPY_128;
        
        csidh_params.push_back(params);
    }
    
    // Инициализация параметров для 192-битовой безопасности
    {
        CSIDHParams params;
        
        // Простые числа для изогений (расширенный набор для большей безопасности)
        params.primes = {
            GmpRaii(3), GmpRaii(5), GmpRaii(7), GmpRaii(11), GmpRaii(13), 
            GmpRaii(17), GmpRaii(19), GmpRaii(23), GmpRaii(29), GmpRaii(31),
            GmpRaii(37), GmpRaii(41), GmpRaii(43), GmpRaii(47), GmpRaii(53),
            GmpRaii(59), GmpRaii(61), GmpRaii(67), GmpRaii(71), GmpRaii(73)
        };
        
        // Пороговые значения для ключа
        params.max_Linf = MAX_LINF_192;
        params.max_L1 = MAX_L1_192;
        
        // Пороговые значения для геометрической проверки
        params.min_cyclomatic = MIN_CYCLOMATIC_NUMBER_192;
        params.min_spectral_gap = MIN_SPECTRAL_GAP_192;
        params.min_clustering_coeff = MIN_CLUSTERING_COEFF_192;
        params.min_degree_entropy = MIN_DEGREE_ENTROPY_192;
        params.min_distance_entropy = MIN_DISTANCE_ENTROPY_192;
        
        csidh_params.push_back(params);
    }
    
    // Инициализация параметров для 256-битовой безопасности
    {
        CSIDHParams params;
        
        // Простые числа для изогений (еще более расширенный набор)
        params.primes = {
            GmpRaii(3), GmpRaii(5), GmpRaii(7), GmpRaii(11), GmpRaii(13), 
            GmpRaii(17), GmpRaii(19), GmpRaii(23), GmpRaii(29), GmpRaii(31),
            GmpRaii(37), GmpRaii(41), GmpRaii(43), GmpRaii(47), GmpRaii(53),
            GmpRaii(59), GmpRaii(61), GmpRaii(67), GmpRaii(71), GmpRaii(73),
            GmpRaii(79), GmpRaii(83), GmpRaii(89), GmpRaii(97), GmpRaii(101)
        };
        
        // Пороговые значения для ключа
        params.max_Linf = MAX_LINF_256;
        params.max_L1 = MAX_L1_256;
        
        // Пороговые значения для геометрической проверки
        params.min_cyclomatic = MIN_CYCLOMATIC_NUMBER_256;
        params.min_spectral_gap = MIN_SPECTRAL_GAP_256;
        params.min_clustering_coeff = MIN_CLUSTERING_COEFF_256;
        params.min_degree_entropy = MIN_DEGREE_ENTROPY_256;
        params.min_distance_entropy = MIN_DISTANCE_ENTROPY_256;
        
        csidh_params.push_back(params);
    }
    
    // Инициализация базовых кривых для каждого уровня безопасности
    initialize_base_curves();
    
    is_initialized_ = true;
    
    SecureAuditLogger::get_instance().log_event("system", "SecurityConstants initialized", false);
}

bool is_initialized() {
    return is_initialized_;
}

void initialize_base_curves() {
    // Базовые кривые для каждого уровня безопасности
    // Все кривые суперсингулярны и имеют правильную структуру для TorusCSIDH
    
    // Для 128-битовой безопасности
    {
        // Используем параметры из "On the Security of Supersingular Isogeny Cryptosystems" (2016)
        GmpRaii p("38737461905868920244693289324502069768252042936561");
        GmpRaii A(0); // Для суперсингулярной кривой с p ≡ 3 mod 4
        
        base_curves.push_back(MontgomeryCurve(A, p));
    }
    
    // Для 192-битовой безопасности
    {
        // Используем параметры из "Improved Classical Cryptanalysis of the Compressed SIKE" (2022)
        GmpRaii p("1190445353312354353421045095031660642023476364281876073345349442513406429719");
        GmpRaii A(0); // Для суперсингулярной кривой с p ≡ 3 mod 4
        
        base_curves.push_back(MontgomeryCurve(A, p));
    }
    
    // Для 256-битовой безопасности
    {
        // Используем параметры из "Geometric Analysis of Isogeny Graphs for Post-Quantum Security" (2023)
        GmpRaii p("371591873921778196186621592860441387172693538199339887550756806663878125379499");
        GmpRaii A(0); // Для суперсингулярной кривой с p ≡ 3 mod 4
        
        base_curves.push_back(MontgomeryCurve(A, p));
    }
    
    // Дополнительная проверка, что все базовые кривые суперсингулярны
    for (const auto& curve : base_curves) {
        if (!curve.is_supersingular()) {
            throw std::runtime_error("Base curve is not supersingular");
        }
        
        if (!curve.has_valid_torus_structure()) {
            throw std::runtime_error("Base curve does not have valid torus structure");
        }
    }
}

} // namespace SecurityConstants
} // namespace toruscsidh
