#include "postquantum_hash.h"
#include <iostream>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <cmath>
#include <sodium.h>
#include "secure_random.h"
#include "security_constants.h"
#include "geometric_validator.h"
#include "secure_audit_logger.h"

namespace toruscsidh {

bool PostQuantumHash::is_initialized_ = false;
std::vector<unsigned char> PostQuantumHash::hmac_key_;
std::vector<unsigned char> PostQuantumHash::salt_;

void PostQuantumHash::initialize() {
    if (is_initialized_) {
        return;
    }
    
    // Инициализация libsodium
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
    
    // Генерация HMAC ключа
    hmac_key_.resize(SecurityConstants::HMAC_KEY_SIZE);
    randombytes_buf(hmac_key_.data(), hmac_key_.size());
    
    // Генерация соли
    salt_ = generate_salt();
    
    is_initialized_ = true;
    
    SecureAuditLogger::get_instance().log_event("system", "PostQuantumHash initialized", false);
}

std::vector<unsigned char> PostQuantumHash::hash(const std::vector<unsigned char>& data) {
    if (!is_initialized_) {
        initialize();
    }
    
    // Добавление соли к данным
    std::vector<unsigned char> salted_data = data;
    salted_data.insert(salted_data.end(), salt_.begin(), salt_.end());
    
    // Базовое хеширование с использованием BLAKE3
    std::vector<unsigned char> hash(SecurityConstants::HASH_SIZE);
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, salted_data.data(), salted_data.size());
    blake3_hasher_finalize(&hasher, hash.data(), hash.size());
    
    // Применение дополнительных защитных преобразований
    std::vector<unsigned char> protected_hash = apply_security_transformations(hash);
    
    // Проверка энтропии
    if (!has_sufficient_entropy(protected_hash)) {
        SecureAuditLogger::get_instance().log_event("security", "Hash has insufficient entropy", true);
        throw std::runtime_error("Hash has insufficient entropy");
    }
    
    return protected_hash;
}

GmpRaii PostQuantumHash::hash_to_gmp(const std::vector<unsigned char>& data, const GmpRaii& modulus) {
    if (!is_initialized_) {
        initialize();
    }
    
    // Хеширование данных
    std::vector<unsigned char> hash = hash(data);
    
    // Конвертация хеша в GMP число
    GmpRaii result;
    mpz_import(result.get_mpz_t(), hash.size(), 1, 1, 1, 0, hash.data());
    
    // Применение модуля
    mpz_mod(result.get_mpz_t(), result.get_mpz_t(), modulus.get_mpz_t());
    
    return result;
}

std::vector<unsigned char> PostQuantumHash::hash_for_signature(
    const std::vector<unsigned char>& message,
    const GmpRaii& ephemeral_curve_j,
    const GmpRaii& public_curve_j) {
    
    if (!is_initialized_) {
        initialize();
    }
    
    // Конвертация j-инвариантов в байты
    std::vector<unsigned char> ephemeral_j_bytes;
    size_t count;
    mpz_export(nullptr, &count, 1, 1, 1, 0, ephemeral_curve_j.get_mpz_t());
    ephemeral_j_bytes.resize(count);
    mpz_export(ephemeral_j_bytes.data(), nullptr, 1, 1, 1, 0, ephemeral_curve_j.get_mpz_t());
    
    std::vector<unsigned char> public_j_bytes;
    mpz_export(nullptr, &count, 1, 1, 1, 0, public_curve_j.get_mpz_t());
    public_j_bytes.resize(count);
    mpz_export(public_j_bytes.data(), nullptr, 1, 1, 1, 0, public_curve_j.get_mpz_t());
    
    // Объединение данных для хеширования
    std::vector<unsigned char> combined_data;
    combined_data.insert(combined_data.end(), message.begin(), message.end());
    combined_data.insert(combined_data.end(), ephemeral_j_bytes.begin(), ephemeral_j_bytes.end());
    combined_data.insert(combined_data.end(), public_j_bytes.begin(), public_j_bytes.end());
    
    // Добавление временного штампа для защиты от replay-атак
    uint64_t timestamp = SecureRandom::get_current_time_us();
    std::vector<unsigned char> timestamp_bytes(sizeof(uint64_t));
    std::memcpy(timestamp_bytes.data(), &timestamp, sizeof(uint64_t));
    combined_data.insert(combined_data.end(), timestamp_bytes.begin(), timestamp_bytes.end());
    
    // Добавление случайного nonce
    std::vector<unsigned char> nonce = SecureRandom::generate_random_bytes(16);
    combined_data.insert(combined_data.end(), nonce.begin(), nonce.end());
    
    // Хеширование комбинированных данных
    return hash(combined_data);
}

bool PostQuantumHash::verify_integrity() {
    if (!is_initialized_) {
        initialize();
    }
    
    try {
        // Создаем тестовые данные
        std::vector<unsigned char> test_data = SecureRandom::generate_random_bytes(32);
        
        // Вычисляем хеш
        std::vector<unsigned char> hash1 = hash(test_data);
        std::vector<unsigned char> hash2 = hash(test_data);
        
        // Проверяем, что хеш детерминирован
        if (hash1 != hash2) {
            SecureAuditLogger::get_instance().log_event("security", "Hash function is not deterministic", true);
            return false;
        }
        
        // Проверяем, что хеш имеет правильный размер
        if (hash1.size() != SecurityConstants::HASH_SIZE) {
            SecureAuditLogger::get_instance().log_event("security", "Hash has incorrect size", true);
            return false;
        }
        
        // Проверяем энтропию
        if (!has_sufficient_entropy(hash1)) {
            SecureAuditLogger::get_instance().log_event("security", "Hash has insufficient entropy", true);
            return false;
        }
        
        // Проверяем HMAC
        std::vector<unsigned char> mac = create_hmac(test_data);
        if (!verify_hmac(test_data, mac)) {
            SecureAuditLogger::get_instance().log_event("security", "HMAC verification failed", true);
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "Hash integrity check failed: " + std::string(e.what()), true);
        return false;
    }
}

const std::vector<unsigned char>& PostQuantumHash::get_hmac_key() {
    if (!is_initialized_) {
        initialize();
    }
    
    return hmac_key_;
}

std::vector<unsigned char> PostQuantumHash::create_hmac(const std::vector<unsigned char>& data) {
    if (!is_initialized_) {
        initialize();
    }
    
    // Создание HMAC с использованием BLAKE3
    std::vector<unsigned char> mac(SecurityConstants::HMAC_SIZE);
    blake3_hasher hasher;
    blake3_keyed_hasher keyed_hasher;
    
    // Инициализация ключевого хеширования
    blake3_keyed_hasher_init(&keyed_hasher, hmac_key_.data());
    
    // Обновление хеша данными
    blake3_keyed_hasher_update(&keyed_hasher, data.data(), data.size());
    
    // Финализация и получение HMAC
    blake3_keyed_hasher_finalize(&keyed_hasher, mac.data(), mac.size());
    
    return mac;
}

bool PostQuantumHash::verify_hmac(const std::vector<unsigned char>& data, 
                                const std::vector<unsigned char>& mac) {
    if (!is_initialized_) {
        initialize();
    }
    
    // Создание ожидаемого HMAC
    std::vector<unsigned char> expected_mac = create_hmac(data);
    
    // Постоянное время сравнение
    return crypto_verify_32(mac.data(), expected_mac.data()) == 0;
}

std::vector<unsigned char> PostQuantumHash::hash_for_rfc6979(
    const GmpRaii& private_key,
    const std::vector<unsigned char>& message,
    const SecurityConstants::CurveParams& curve_params) {
    
    if (!is_initialized_) {
        initialize();
    }
    
    // Конвертация приватного ключа в байты
    std::vector<unsigned char> key_bytes;
    size_t count;
    mpz_export(nullptr, &count, 1, 1, 1, 0, private_key.get_mpz_t());
    key_bytes.resize(count);
    mpz_export(key_bytes.data(), nullptr, 1, 1, 1, 0, private_key.get_mpz_t());
    
    // Конвертация параметров кривой в байты
    std::vector<unsigned char> curve_bytes;
    curve_bytes.insert(curve_bytes.end(), 
                      reinterpret_cast<const unsigned char*>(&curve_params.p), 
                      reinterpret_cast<const unsigned char*>(&curve_params.p) + sizeof(curve_params.p));
    curve_bytes.insert(curve_bytes.end(), 
                      reinterpret_cast<const unsigned char*>(&curve_params.A), 
                      reinterpret_cast<const unsigned char*>(&curve_params.A) + sizeof(curve_params.A));
    
    // Объединение данных
    std::vector<unsigned char> combined_data;
    combined_data.insert(combined_data.end(), key_bytes.begin(), key_bytes.end());
    combined_data.insert(combined_data.end(), message.begin(), message.end());
    combined_data.insert(combined_data.end(), curve_bytes.begin(), curve_bytes.end());
    
    // Добавление дополнительных данных для усиления безопасности
    std::vector<unsigned char> additional_data = SecureRandom::generate_random_bytes(32);
    combined_data.insert(combined_data.end(), additional_data.begin(), additional_data.end());
    
    // Хеширование комбинированных данных
    return hash(combined_data);
}

std::vector<unsigned char> PostQuantumHash::hash_graph_structure(
    const GeometricValidator::Graph& graph) {
    
    if (!is_initialized_) {
        initialize();
    }
    
    try {
        // Анализ структуры графа
        size_t num_vertices = boost::num_vertices(graph);
        size_t num_edges = boost::num_edges(graph);
        
        // Вычисление цикломатического числа
        double cyclomatic_number = num_edges - num_vertices + 1; // Предполагаем, что граф связный
        
        // Вычисление коэффициента кластеризации
        double clustering_coeff = 0.0;
        {
            size_t triangles = 0;
            size_t triples = 0;
            
            for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
                size_t degree = boost::degree(v, graph);
                if (degree < 2) continue;
                
                triples += degree * (degree - 1) / 2;
                
                for (auto u : boost::make_iterator_range(boost::adjacent_vertices(v, graph))) {
                    for (auto w : boost::make_iterator_range(boost::adjacent_vertices(v, graph))) {
                        if (u < w && boost::edge(u, w, graph).second) {
                            triangles++;
                        }
                    }
                }
            }
            
            clustering_coeff = (triples > 0) ? static_cast<double>(3 * triangles) / triples : 0.0;
        }
        
        // Вычисление спектрального зазора
        double spectral_gap = 0.0;
        {
            // Получение матрицы Лапласа
            Eigen::MatrixXd laplacian = get_laplacian_matrix(graph);
            
            // Вычисление собственных значений
            Eigen::SelfAdjointEigenSolver<Eigen::MatrixXd> solver(laplacian);
            Eigen::VectorXd eigenvalues = solver.eigenvalues();
            
            // Сортировка собственных значений
            std::vector<double> sorted_eigenvalues;
            for (int i = 0; i < eigenvalues.size(); ++i) {
                sorted_eigenvalues.push_back(eigenvalues(i));
            }
            std::sort(sorted_eigenvalues.begin(), sorted_eigenvalues.end());
            
            // Спектральный зазор = λ₂ - λ₁
            for (size_t i = 1; i < sorted_eigenvalues.size(); ++i) {
                if (sorted_eigenvalues[i] > 1e-10) {
                    spectral_gap = sorted_eigenvalues[i] - sorted_eigenvalues[i-1];
                    break;
                }
            }
        }
        
        // Вычисление энтропии степеней
        double degree_entropy = 0.0;
        {
            std::map<int, int> degree_count;
            for (auto v : boost::make_iterator_range(boost::vertices(graph))) {
                degree_count[boost::degree(v, graph)]++;
            }
            
            int total = num_vertices;
            for (const auto& entry : degree_count) {
                double p = static_cast<double>(entry.second) / total;
                if (p > 0) {
                    degree_entropy -= p * std::log2(p);
                }
            }
        }
        
        // Вычисление диаметра графа
        int diameter = 0;
        {
            std::vector<std::vector<double>> distances;
            boost::floyd_warshall_all_pairs_shortest_paths(graph, distances);
            
            for (int i = 0; i < num_vertices; ++i) {
                for (int j = i + 1; j < num_vertices; ++j) {
                    if (distances[i][j] < std::numeric_limits<double>::infinity()) {
                        diameter = std::max(diameter, static_cast<int>(distances[i][j]));
                    }
                }
            }
        }
        
        // Создание данных для хеширования
        std::vector<unsigned char> graph_data;
        
        // Добавление численных характеристик
        auto append_double = [&](double value) {
            unsigned char buffer[sizeof(double)];
            std::memcpy(buffer, &value, sizeof(double));
            graph_data.insert(graph_data.end(), buffer, buffer + sizeof(double));
        };
        
        auto append_int = [&](int value) {
            unsigned char buffer[sizeof(int)];
            std::memcpy(buffer, &value, sizeof(int));
            graph_data.insert(graph_data.end(), buffer, buffer + sizeof(int));
        };
        
        append_double(cyclomatic_number);
        append_double(clustering_coeff);
        append_double(spectral_gap);
        append_double(degree_entropy);
        append_int(diameter);
        append_int(static_cast<int>(num_vertices));
        append_int(static_cast<int>(num_edges));
        
        // Хеширование структурных данных
        return hash(graph_data);
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", "Failed to hash graph structure: " + std::string(e.what()), true);
        throw;
    }
}

bool PostQuantumHash::has_sufficient_entropy(const std::vector<unsigned char>& hash) {
    if (!is_initialized_) {
        initialize();
    }
    
    // Вычисление энтропии хеша
    std::map<unsigned char, int> byte_count;
    for (unsigned char byte : hash) {
        byte_count[byte]++;
    }
    
    double entropy = 0.0;
    size_t total = hash.size();
    
    for (const auto& entry : byte_count) {
        double p = static_cast<double>(entry.second) / total;
        entropy -= p * std::log2(p);
    }
    
    // Проверка, что энтропия достаточна
    bool sufficient = (entropy * 8 * hash.size() >= SecurityConstants::MIN_ENTROPY_BITS);
    
    if (!sufficient) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Hash entropy too low: " + std::to_string(entropy * 8 * hash.size()) + 
            " bits (required: " + std::to_string(SecurityConstants::MIN_ENTROPY_BITS) + ")", true);
    }
    
    return sufficient;
}

std::vector<unsigned char> PostQuantumHash::hash_with_salt(
    const std::vector<unsigned char>& data,
    const std::vector<unsigned char>& salt) {
    
    if (!is_initialized_) {
        initialize();
    }
    
    // Объединение данных и соли
    std::vector<unsigned char> salted_data = data;
    salted_data.insert(salted_data.end(), salt.begin(), salt.end());
    
    // Хеширование с солью
    return hash(salted_data);
}

bool PostQuantumHash::is_secure_hash(const std::vector<unsigned char>& hash) {
    if (!is_initialized_) {
        initialize();
    }
    
    // Проверка размера хеша
    if (hash.size() != SecurityConstants::HASH_SIZE) {
        return false;
    }
    
    // Проверка энтропии
    if (!has_sufficient_entropy(hash)) {
        return false;
    }
    
    // Проверка на наличие слабых шаблонов
    const size_t pattern_length = 4;
    for (size_t i = 0; i < hash.size() - pattern_length + 1; i++) {
        bool is_constant = true;
        for (size_t j = 1; j < pattern_length; j++) {
            if (hash[i] != hash[i + j]) {
                is_constant = false;
                break;
            }
        }
        if (is_constant) {
            return false;
        }
    }
    
    return true;
}

std::vector<unsigned char> PostQuantumHash::generate_salt() {
    return SecureRandom::generate_random_bytes(SALT_SIZE);
}

std::vector<unsigned char> PostQuantumHash::apply_security_transformations(
    const std::vector<unsigned char>& hash) {
    
    if (!is_initialized_) {
        initialize();
    }
    
    std::vector<unsigned char> transformed_hash = hash;
    
    // Применение преобразований для усиления безопасности
    // 1. Битовый сдвиг
    for (size_t i = 0; i < transformed_hash.size(); i++) {
        transformed_hash[i] = (transformed_hash[i] << 3) | (transformed_hash[i] >> 5);
    }
    
    // 2. Нелинейное преобразование
    for (size_t i = 0; i < transformed_hash.size(); i++) {
        transformed_hash[i] = static_cast<unsigned char>(
            (transformed_hash[i] * transformed_hash[i] + 3 * transformed_hash[i] + 1) % 256
        );
    }
    
    // 3. Перемешивание байтов
    for (size_t i = 0; i < transformed_hash.size(); i++) {
        size_t j = (i * 13 + 7) % transformed_hash.size();
        std::swap(transformed_hash[i], transformed_hash[j]);
    }
    
    // 4. Добавление случайного шума
    std::vector<unsigned char> noise = SecureRandom::generate_random_bytes(transformed_hash.size());
    for (size_t i = 0; i < transformed_hash.size(); i++) {
        transformed_hash[i] ^= noise[i];
    }
    
    // 5. Проверка и корректировка энтропии
    if (!has_sufficient_entropy(transformed_hash)) {
        // Дополнительное перемешивание для увеличения энтропии
        for (size_t i = 0; i < transformed_hash.size(); i++) {
            transformed_hash[i] = static_cast<unsigned char>(
                transformed_hash[i] ^ transformed_hash[(i + transformed_hash.size() / 2) % transformed_hash.size()]
            );
        }
    }
    
    return transformed_hash;
}

Eigen::MatrixXd PostQuantumHash::get_laplacian_matrix(const GeometricValidator::Graph& graph) const {
    int n = boost::num_vertices(graph);
    Eigen::MatrixXd laplacian = Eigen::MatrixXd::Zero(n, n);
    
    // Заполняем матрицу смежности
    for (auto edge : boost::make_iterator_range(boost::edges(graph))) {
        auto u = boost::source(edge, graph);
        auto v = boost::target(edge, graph);
        
        laplacian(u, v) = -1.0;
        laplacian(v, u) = -1.0;
        laplacian(u, u) += 1.0;
        laplacian(v, v) += 1.0;
    }
    
    return laplacian;
}

} // namespace toruscsidh
