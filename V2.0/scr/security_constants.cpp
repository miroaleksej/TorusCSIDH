#include "security_constants.h"
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <gmp.h>
#include "elliptic_curve.h"
#include "secure_random.h"
#include "secure_audit_logger.h"

namespace toruscsidh {
namespace SecurityConstants {

// Статические переменные для хранения параметров безопасности
bool initialized_ = false;
CSIDHParams csidh_params_128;
CSIDHParams csidh_params_192;
CSIDHParams csidh_params_256;

// Инициализация параметров безопасности для уровня 128 бит
void initialize_128() {
    // Простые числа для изогений (пример, в реальной системе будут другие)
    csidh_params_128.primes = {
        GmpRaii(3), GmpRaii(5), GmpRaii(7), GmpRaii(11), GmpRaii(13),
        GmpRaii(17), GmpRaii(19), GmpRaii(23), GmpRaii(29), GmpRaii(31),
        GmpRaii(37), GmpRaii(41), GmpRaii(43), GmpRaii(47), GmpRaii(53),
        GmpRaii(59), GmpRaii(61), GmpRaii(67), GmpRaii(71), GmpRaii(73)
    };
    
    // Параметры для "малости" ключа
    csidh_params_128.max_Linf = MAX_LINF_128;
    csidh_params_128.max_L1 = MAX_L1_128;
    
    // Параметры для геометрической проверки
    csidh_params_128.min_cyclomatic = MIN_CYCLOMATIC_NUMBER_128;
    csidh_params_128.min_spectral_gap = MIN_SPECTRAL_GAP_128;
    csidh_params_128.min_clustering_coeff = MIN_CLUSTERING_COEFF_128;
    csidh_params_128.min_degree_entropy = MIN_DEGREE_ENTROPY_128;
    csidh_params_128.min_distance_entropy = MIN_DISTANCE_ENTROPY_128;
}

// Инициализация параметров безопасности для уровня 192 бит
void initialize_192() {
    // Простые числа для изогений (пример, в реальной системе будут другие)
    csidh_params_192.primes = {
        GmpRaii(3), GmpRaii(5), GmpRaii(7), GmpRaii(11), GmpRaii(13),
        GmpRaii(17), GmpRaii(19), GmpRaii(23), GmpRaii(29), GmpRaii(31),
        GmpRaii(37), GmpRaii(41), GmpRaii(43), GmpRaii(47), GmpRaii(53),
        GmpRaii(59), GmpRaii(61), GmpRaii(67), GmpRaii(71), GmpRaii(73),
        GmpRaii(79), GmpRaii(83), GmpRaii(89), GmpRaii(97), GmpRaii(101),
        GmpRaii(103), GmpRaii(107), GmpRaii(109), GmpRaii(113), GmpRaii(127)
    };
    
    // Параметры для "малости" ключа
    csidh_params_192.max_Linf = MAX_LINF_192;
    csidh_params_192.max_L1 = MAX_L1_192;
    
    // Параметры для геометрической проверки
    csidh_params_192.min_cyclomatic = MIN_CYCLOMATIC_NUMBER_192;
    csidh_params_192.min_spectral_gap = MIN_SPECTRAL_GAP_192;
    csidh_params_192.min_clustering_coeff = MIN_CLUSTERING_COEFF_192;
    csidh_params_192.min_degree_entropy = MIN_DEGREE_ENTROPY_192;
    csidh_params_192.min_distance_entropy = MIN_DISTANCE_ENTROPY_192;
}

// Инициализация параметров безопасности для уровня 256 бит
void initialize_256() {
    // Простые числа для изогений (пример, в реальной системе будут другие)
    csidh_params_256.primes = {
        GmpRaii(3), GmpRaii(5), GmpRaii(7), GmpRaii(11), GmpRaii(13),
        GmpRaii(17), GmpRaii(19), GmpRaii(23), GmpRaii(29), GmpRaii(31),
        GmpRaii(37), GmpRaii(41), GmpRaii(43), GmpRaii(47), GmpRaii(53),
        GmpRaii(59), GmpRaii(61), GmpRaii(67), GmpRaii(71), GmpRaii(73),
        GmpRaii(79), GmpRaii(83), GmpRaii(89), GmpRaii(97), GmpRaii(101),
        GmpRaii(103), GmpRaii(107), GmpRaii(109), GmpRaii(113), GmpRaii(127),
        GmpRaii(131), GmpRaii(137), GmpRaii(139), GmpRaii(149), GmpRaii(151),
        GmpRaii(157), GmpRaii(163), GmpRaii(167), GmpRaii(173), GmpRaii(179)
    };
    
    // Параметры для "малости" ключа
    csidh_params_256.max_Linf = MAX_LINF_256;
    csidh_params_256.max_L1 = MAX_L1_256;
    
    // Параметры для геометрической проверки
    csidh_params_256.min_cyclomatic = MIN_CYCLOMATIC_NUMBER_256;
    csidh_params_256.min_spectral_gap = MIN_SPECTRAL_GAP_256;
    csidh_params_256.min_clustering_coeff = MIN_CLUSTERING_COEFF_256;
    csidh_params_256.min_degree_entropy = MIN_DEGREE_ENTROPY_256;
    csidh_params_256.min_distance_entropy = MIN_DISTANCE_ENTROPY_256;
}

CSIDHParams get_csidh_params(SecurityLevel level) {
    if (!is_initialized()) {
        initialize();
    }
    
    switch (level) {
        case SecurityLevel::LEVEL_128:
            return csidh_params_128;
        case SecurityLevel::LEVEL_192:
            return csidh_params_192;
        case SecurityLevel::LEVEL_256:
            return csidh_params_256;
        default:
            throw std::invalid_argument("Invalid security level");
    }
}

int get_max_linf(SecurityLevel level) {
    CSIDHParams params = get_csidh_params(level);
    return params.max_Linf;
}

int get_max_l1(SecurityLevel level) {
    CSIDHParams params = get_csidh_params(level);
    return params.max_L1;
}

MontgomeryCurve get_base_curve(SecurityLevel level) {
    // Определение характеристики поля в зависимости от уровня безопасности
    GmpRaii p;
    
    switch (level) {
        case SecurityLevel::LEVEL_128:
            p = GmpRaii("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF......"); // Здесь должно быть конкретное простое число
            
            // Для демонстрации используем упрощенное значение
            p = GmpRaii("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386D59BB2616B5144C92602DB19710A09E6A7C6A91E8C9452923B51001E5272A70E5D74380CA722D8B0521D3C92A0FFD25A2D8460348F6A81");
            break;
            
        case SecurityLevel::LEVEL_192:
            p = GmpRaii("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF......"); // Здесь должно быть конкретное простое число
            
            // Для демонстрации используем упрощенное значение
            p = GmpRaii("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386D59BB2616B5144C92602DB19710A09E6A7C6A91E8C9452923B51001E5272A70E5D74380CA722D8B0521D3C92A0FFD25A2D8460348F6A812B7C92440D92C162B6BDEBFF9AF0CACE1CD8E819F8041");
            break;
            
        case SecurityLevel::LEVEL_256:
            p = GmpRaii("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF......"); // Здесь должно быть конкретное простое число
            
            // Для демонстрации используем упрощенное значение
            p = GmpRaii("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386D59BB2616B5144C92602DB19710A09E6A7C6A91E8C9452923B51001E5272A70E5D74380CA722D8B0521D3C92A0FFD25A2D8460348F6A812B7C92440D92C162B6BDEBFF9AF0CACE1CD8E819F8041E93B5D5DC1E5968BCBF5C6B50A999F74E76463E953E879A2DDFDA2D2A4C03A4BC463428347A49341CF91A992A12B");
            break;
            
        default:
            throw std::invalid_argument("Invalid security level");
    }
    
    // Параметр A для базовой кривой (должен быть 0 для суперсингулярных кривых)
    GmpRaii A(0);
    
    // Создание базовой кривой
    MontgomeryCurve base_curve(A, p);
    
    // Проверка, что кривая суперсингулярна
    if (!base_curve.is_supersingular()) {
        SecureAuditLogger::get_instance().log_event("security", "Base curve is not supersingular", true);
        throw std::runtime_error("Base curve is not supersingular");
    }
    
    // Проверка, что кривая имеет правильную структуру для TorusCSIDH
    if (!base_curve.has_valid_torus_structure()) {
        SecureAuditLogger::get_instance().log_event("security", "Base curve does not have valid torus structure", true);
        throw std::runtime_error("Base curve does not have valid torus structure");
    }
    
    return base_curve;
}

void initialize() {
    if (initialized_) {
        return;
    }
    
    try {
        // Инициализация параметров для всех уровней безопасности
        initialize_128();
        initialize_192();
        initialize_256();
        
        initialized_ = true;
        
        SecureAuditLogger::get_instance().log_event("system", "Security constants initialized", false);
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "Failed to initialize security constants: " + std::string(e.what()), true);
        throw;
    }
}

bool is_initialized() {
    return initialized_;
}

} // namespace SecurityConstants
} // namespace toruscsidh
