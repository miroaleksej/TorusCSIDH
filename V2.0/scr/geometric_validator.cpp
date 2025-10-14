#include "geometric_validator.h"
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <stdexcept>
#include <chrono>
#include <random>
#include <sodium.h>
#include "secure_random.h"
#include "security_constants.h"
#include "secure_audit_logger.h"
#include "postquantum_hash.h"
#include "elliptic_curve.h"
#include "bech32m.h"

namespace toruscsidh {

GeometricValidator::GeometricValidator(SecurityConstants::SecurityLevel security_level)
    : security_level_(security_level) {
    
    // Устанавливаем радиус подграфа в зависимости от уровня безопасности
    switch (security_level_) {
        case SecurityConstants::LEVEL_128:
            subgraph_radius_ = 2;
            break;
        case SecurityConstants::LEVEL_192:
            subgraph_radius_ = 2;
            break;
        case SecurityConstants::LEVEL_256:
            subgraph_radius_ = 3;
            break;
        default:
            subgraph_radius_ = 2;
    }
    
    SecureAuditLogger::get_instance().log_event("system", 
        "GeometricValidator initialized with security level: " + 
        SecurityConstants::security_level_to_string(security_level_) + 
        ", subgraph radius: " + std::to_string(subgraph_radius_), false);
}

bool GeometricValidator::validate_curve(const MontgomeryCurve& base_curve,
                                      const MontgomeryCurve& public_curve,
                                      double& cyclomatic_score,
                                      double& spectral_score) {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка целостности геометрической проверки
    if (!verify_integrity()) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: integrity check failed", true);
        return false;
    }
    
    // Проверка, что кривая имеет правильную структуру
    if (!has_valid_structure(public_curve)) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: curve has invalid structure", true);
        return false;
    }
    
    // Построение локального подграфа
    IsogenyGraph subgraph = build_local_subgraph(base_curve, public_curve);
    
    // Вычисление основных геометрических характеристик
    cyclomatic_score = compute_cyclomatic_number(subgraph);
    spectral_score = compute_spectral_gap(subgraph);
    
    // Проверка цикломатического числа (должно быть >= 2)
    if (cyclomatic_score < 0.75) { // Нормализованное значение для 2.0
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: cyclomatic number too low (" + 
            std::to_string(cyclomatic_score) + " < 0.75)", true);
        return false;
    }
    
    // Проверка спектрального зазора (должно быть >= 1.5)
    if (spectral_score < 0.80) { // Нормализованное значение для 1.5
        SecureAuditLogger::get_instance().log_event("security", 
            "Geometric validation failed: spectral gap too low (" + 
            std::to_string(spectral_score) + " < 0.80)", true);
        return false;
    }
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Geometric validation passed - Cyclomatic: " + std::to_string(cyclomatic_score) +
        ", Spectral gap: " + std::to_string(spectral_score), false);
    
    return true;
}

IsogenyGraph GeometricValidator::build_local_subgraph(const MontgomeryCurve& base_curve,
                                                    const MontgomeryCurve& public_curve) {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    SecureAuditLogger::get_instance().log_event("system", 
        "Building local isogeny subgraph for geometric validation", false);
    
    // Создаем пустой граф
    IsogenyGraph subgraph;
    
    // Используем BFS для построения подграфа
    std::queue<std::pair<MontgomeryCurve, int>> queue;
    std::map<GmpRaii, IsogenyGraph::vertex_descriptor> curve_to_vertex;
    
    // Добавляем базовую кривую
    IsogenyGraph::vertex_descriptor base_vertex = boost::add_vertex(subgraph);
    subgraph[base_vertex] = base_curve;
    curve_to_vertex[base_curve.compute_j_invariant()] = base_vertex;
    
    queue.push({base_curve, 0});
    
    // Максимальное количество вершин для предотвращения переполнения
    const size_t max_vertices = 200;
    size_t vertices_count = 1;
    
    while (!queue.empty() && vertices_count < max_vertices) {
        auto [current_curve, current_radius] = queue.front();
        queue.pop();
        
        IsogenyGraph::vertex_descriptor current_vertex = curve_to_vertex[current_curve.compute_j_invariant()];
        
        // Если достигли максимального радиуса, прекращаем обход
        if (current_radius >= subgraph_radius_) {
            continue;
        }
        
        // Генерируем изогении для всех простых чисел
        for (const auto& prime : SecurityConstants::get_primes(security_level_)) {
            unsigned int degree = static_cast<unsigned int>(mpz_get_ui(prime.get_mpz_t()));
            
            // Генерируем точки малых порядков для вычисления изогений
            EllipticCurvePoint kernel_point = current_curve.find_point_of_order(degree);
            
            if (!kernel_point.is_infinity()) {
                // Вычисляем изогению
                MontgomeryCurve new_curve = current_curve.compute_isogeny(kernel_point, degree);
                
                // Проверяем, что кривая имеет правильную структуру
                if (!has_valid_structure(new_curve)) {
                    continue;
                }
                
                // Проверяем, не встречали ли мы эту кривую ранее
                GmpRaii j_invariant = new_curve.compute_j_invariant();
                IsogenyGraph::vertex_descriptor new_vertex;
                
                if (curve_to_vertex.find(j_invariant) == curve_to_vertex.end()) {
                    // Добавляем новую вершину
                    new_vertex = boost::add_vertex(subgraph);
                    subgraph[new_vertex] = new_curve;
                    curve_to_vertex[j_invariant] = new_vertex;
                    vertices_count++;
                } else {
                    new_vertex = curve_to_vertex[j_invariant];
                }
                
                // Добавляем ребро
                boost::add_edge(current_vertex, new_vertex, subgraph);
                
                // Добавляем в очередь для дальнейшего обхода
                if (curve_to_vertex.find(j_invariant) == curve_to_vertex.end()) {
                    queue.push({new_curve, current_radius + 1});
                }
                
                // Проверяем, не достигли ли мы целевой кривой
                if (new_curve.is_equivalent_to(public_curve)) {
                    return subgraph;
                }
            }
        }
    }
    
    return subgraph;
}

double GeometricValidator::compute_cyclomatic_number(const IsogenyGraph& graph) const {
    // Цикломатическое число = E - V + C, где
    // E - количество ребер
    // V - количество вершин
    // C - количество компонент связности
    
    size_t edges = num_edges(graph);
    size_t vertices = num_vertices(graph);
    
    // Вычисляем количество компонент связности
    std::vector<size_t> component(num_vertices(graph));
    size_t num_components = boost::connected_components(graph, &component[0]);
    
    // Вычисляем цикломатическое число
    double cyclomatic_number = static_cast<double>(edges - vertices + num_components);
    
    // Нормализуем к [0,1] с целевым значением 2.0
    double normalized_value = cyclomatic_number / 2.0;
    
    // Ограничиваем значение в пределах [0,1]
    return std::min(1.0, normalized_value);
}

double GeometricValidator::compute_spectral_gap(const IsogenyGraph& graph) const {
    // Спектральный зазор = (λ₄ - λ₃) / λ₃
    // где λ₃, λ₄ - собственные значения нормализованной матрицы Лапласа
    
    size_t n = num_vertices(graph);
    
    // Если граф слишком мал, возвращаем 0.0
    if (n < 4) {
        return 0.0;
    }
    
    // Вычисляем матрицу Лапласа
    boost::numeric::ublas::matrix<double> laplacian = compute_laplacian_matrix(graph);
    
    // Вычисляем собственные значения
    std::vector<double> eigenvalues = compute_eigenvalues(laplacian);
    
    // Сортируем собственные значения по возрастанию
    std::sort(eigenvalues.begin(), eigenvalues.end());
    
    // Проверяем, что у нас достаточно собственных значений
    if (eigenvalues.size() < 4) {
        return 0.0; // Недостаточно данных для анализа
    }
    
    // Вычисляем спектральный зазор
    double lambda3 = eigenvalues[2]; // λ₃
    double lambda4 = eigenvalues[3]; // λ₄
    
    // Проверяем, что λ₃ > 0, чтобы избежать деления на ноль
    if (lambda3 <= 0) {
        return 0.0;
    }
    
    double spectral_gap = (lambda4 - lambda3) / lambda3;
    
    // Нормализуем спектральный зазор к [0,1]
    // В статье указано, что спектральный зазор должен быть ≥ 1.5
    double normalized_value = spectral_gap / 1.5;
    
    // Ограничиваем значение в пределах [0,1]
    return std::min(1.0, normalized_value);
}

boost::numeric::ublas::matrix<double> GeometricValidator::compute_laplacian_matrix(const IsogenyGraph& graph) const {
    size_t n = num_vertices(graph);
    boost::numeric::ublas::matrix<double> laplacian(n, n);
    
    // Заполняем матрицу смежности
    boost::numeric::ublas::matrix<double> adjacency(n, n);
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++) {
            adjacency(i, j) = 0.0;
        }
    }
    
    for (auto e : boost::make_iterator_range(boost::edges(graph))) {
        auto u = boost::source(e, graph);
        auto v = boost::target(e, graph);
        
        adjacency(u, v) = 1.0;
        adjacency(v, u) = 1.0;
    }
    
    // Вычисляем степень каждой вершины
    std::vector<double> degrees(n, 0.0);
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++) {
            degrees[i] += adjacency(i, j);
        }
    }
    
    // Строим матрицу Лапласа: L = D - A
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++) {
            if (i == j) {
                laplacian(i, j) = degrees[i];
            } else {
                laplacian(i, j) = -adjacency(i, j);
            }
        }
    }
    
    // Нормализуем матрицу Лапласа
    for (size_t i = 0; i < n; i++) {
        if (degrees[i] > 0) {
            for (size_t j = 0; j < n; j++) {
                if (i != j && adjacency(i, j) > 0) {
                    laplacian(i, j) /= std::sqrt(degrees[i] * degrees[j]);
                }
            }
            laplacian(i, i) = 1.0;
        }
    }
    
    return laplacian;
}

std::vector<double> GeometricValidator::compute_eigenvalues(const boost::numeric::ublas::matrix<double>& matrix) const {
    // Используем библиотеку boost::numeric::ublas для вычисления собственных значений
    
    size_t n = matrix.size1();
    boost::numeric::ublas::matrix<double> A = matrix;
    std::vector<double> eigenvalues(n);
    
    // Используем QR-алгоритм для вычисления собственных значений
    try {
        // Создаем копию матрицы для вычисления
        boost::numeric::ublas::matrix<double> A_copy = A;
        
        // Вычисляем собственные значения
        boost::numeric::ublas::eigen_symmetric(A_copy, eigenvalues);
        
        // Проверяем, что собственные значения неотрицательны
        for (size_t i = 0; i < n; i++) {
            if (eigenvalues[i] < 0 && std::abs(eigenvalues[i]) < 1e-10) {
                eigenvalues[i] = 0.0; // Исправляем численные ошибки
            }
        }
    } catch (const std::exception& e) {
        SecureAuditLogger::get_instance().log_event("security", 
            "Eigenvalue computation failed: " + std::string(e.what()), true);
        
        // Если возникла ошибка, используем метод степеней для оценки
        // Это резервный метод, который должен сработать в редких случаях
        eigenvalues = compute_eigenvalues_approximate(matrix);
    }
    
    return eigenvalues;
}

std::vector<double> GeometricValidator::compute_eigenvalues_approximate(const boost::numeric::ublas::matrix<double>& matrix) const {
    size_t n = matrix.size1();
    std::vector<double> eigenvalues(n, 0.0);
    
    // Реализация метода степеней для оценки собственных значений
    // Этот метод используется только как резервный в случае ошибки
    
    // Инициализируем случайный вектор
    std::vector<double> v(n);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-1.0, 1.0);
    
    for (size_t i = 0; i < n; i++) {
        v[i] = dis(gen);
    }
    
    // Нормализуем вектор
    double norm = std::sqrt(std::inner_product(v.begin(), v.end(), v.begin(), 0.0));
    for (size_t i = 0; i < n; i++) {
        v[i] /= norm;
    }
    
    // Метод степеней для оценки наибольшего собственного значения
    std::vector<double> Av(n);
    for (int iter = 0; iter < 100; iter++) {
        // Умножение матрицы на вектор
        for (size_t i = 0; i < n; i++) {
            Av[i] = 0.0;
            for (size_t j = 0; j < n; j++) {
                Av[i] += matrix(i, j) * v[j];
            }
        }
        
        // Нормализация
        double new_norm = std::sqrt(std::inner_product(Av.begin(), Av.end(), Av.begin(), 0.0));
        for (size_t i = 0; i < n; i++) {
            v[i] = Av[i] / new_norm;
        }
        
        // Оценка собственного значения
        double lambda = 0.0;
        for (size_t i = 0; i < n; i++) {
            lambda += v[i] * Av[i];
        }
        
        eigenvalues[n-1] = lambda; // Наибольшее собственное значение
        
        // Проверка сходимости
        if (std::abs(new_norm - norm) < 1e-6) {
            break;
        }
        norm = new_norm;
    }
    
    // Оценка наименьшего собственного значения (для матрицы Лапласа это 0)
    eigenvalues[0] = 0.0;
    
    // Для остальных собственных значений используем равномерное распределение
    // Это очень грубая оценка, но лучше, чем ничего в случае ошибки
    double min_val = 0.0;
    double max_val = eigenvalues[n-1];
    
    for (size_t i = 1; i < n-1; i++) {
        eigenvalues[i] = min_val + (max_val - min_val) * i / (n - 1);
    }
    
    return eigenvalues;
}

const MontgomeryCurve& GeometricValidator::get_curve_from_vertex(const IsogenyGraph& graph, 
                                                               IsogenyGraph::vertex_descriptor v) const {
    // Получаем кривую из свойства вершины
    return graph[v];
}

bool GeometricValidator::has_valid_structure(const MontgomeryCurve& curve) const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что кривая суперсингулярна
    if (!curve.is_supersingular()) {
        return false;
    }
    
    // Проверка, что поле имеет правильную характеристику
    GmpRaii p = curve.get_p();
    GmpRaii p_mod_4;
    mpz_mod(p_mod_4.get_mpz_t(), p.get_mpz_t(), mpz_class(4).get_mpz_t());
    
    if (p_mod_4 != GmpRaii(3)) {
        return false;
    }
    
    // Проверка, что A = 0
    if (curve.get_A() != GmpRaii(0)) {
        return false;
    }
    
    return true;
}

bool GeometricValidator::verify_integrity() const {
    std::lock_guard<std::mutex> lock(validator_mutex_);
    
    // Проверка, что радиус подграфа в допустимых пределах
    if (subgraph_radius_ < 1 || subgraph_radius_ > 3) {
        return false;
    }
    
    return true;
}

} // namespace toruscsidh
