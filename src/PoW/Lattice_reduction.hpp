#ifndef LATTICE_REDUCTION_HPP
#define LATTICER_EDUCTION_HPP

#pragma once

#include <iostream>
#include <cmath>
#include <random>
#include <chrono>
#include <vector>
#include <string>

#include "PoW.hpp"

void idealLatticeReduction(std::vector<std::vector<int>>& lattice) {
    int n = lattice.size();
    int m = lattice[0].size();

    // Gram-Schmidt orthogonalization
    std::vector<std::vector<double>> mu(n, std::vector<double>(m, 0.0));
    std::vector<std::vector<double>> ortho(n, std::vector<double>(m, 0.0));

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < i; j++) {
            double dotProduct = 0.0;
            double normSquare = 0.0;
            for (int k = 0; k < m; k++) {
                dotProduct += lattice[i][k] * ortho[j][k];
                normSquare += ortho[j][k] * ortho[j][k];
            }
            mu[i][j] = dotProduct / normSquare;
            for (int k = 0; k < m; k++) {
                lattice[i][k] -= std::round(mu[i][j] * ortho[j][k]);
            }
        }

        double normSquare = 0.0;
        for (int k = 0; k < m; k++) {
            normSquare += lattice[i][k] * lattice[i][k];
        }
        ortho[i] = lattice[i];
        for (int j = 0; j < i; j++) {
            for (int k = 0; k < m; k++) {
                ortho[i][k] -= std::round(mu[i][j] * ortho[j][k]);
            }
        }
    }

    // LLL reduction
    const double delta = 0.99;
    const double eta = 0.51;

    std::vector<std::vector<double>> gs(n, std::vector<double>(m, 0.0));
    std::vector<std::vector<double>> ort(n, std::vector<double>(m, 0.0));
    std::vector<double> u(m, 0.0);
    std::vector<double> c(m, 0.0);

    for (int i = 0; i < n; i++) {
        double normSquare = 0.0;
        for (int k = 0; k < m; k++) {
            normSquare += ortho[i][k] * ortho[i][k];
        }
        gs[i] = ortho[i];
        for (int j = 0; j < i; j++) {
            for (int k = 0; k < m; k++) {
                gs[i][k] -= std::round(u[j] * gs[j][k]);
            }
        }

        for (int j = i - 1; j >= 0; j--) {
            double dotProduct = 0.0;
            double normSquare = 0.0;
            for (int k = 0; k < m; k++) {
                dotProduct += gs[i][k] * ort[j][k];
                normSquare += ort[j][k] * ort[j][k];
            }
            u[j] = dotProduct / normSquare;
            for (int k = 0; k < m; k++) {
                gs[i][k] -= std::round(u[j] * ort[j][k]);
            }
        }

        double normSquareGS = 0.0;
        for (int k = 0; k < m; k++) {
            normSquareGS += gs[i][k] * gs[i][k];
        }

        c[i] = normSquareGS;

        if (i > 0) {
            double dotProduct = 0.0;
            for (int k = 0; k < m; k++) {
                dotProduct += lattice[i][k] * gs[i][k];
            }
            double mu = dotProduct / c[i - 1];
            for (int k = 0; k < m; k++) {
                lattice[i][k] -= std::round(mu * lattice[i - 1][k]);
            }
            for (int k = 0; k < m; k++) {
                ortho[i][k] -= std::round(mu * ortho[i - 1][k]);
            }
        }

        double normSquareOrtho = 0.0;
        for (int k = 0; k < m; k++) {
            normSquareOrtho += ortho[i][k] * ortho[i][k];
        }

        if (c[i] < delta * normSquareOrtho) {
            for (int j = i - 1; j >= 0; j--) {
                double dotProduct = 0.0;
                for (int k = 0; k < m; k++) {
                    dotProduct += lattice[i][k] * ortho[j][k];
                }
                double mu = dotProduct / c[j];
                for (int k = 0; k < m; k++) {
                    lattice[i][k] -= std::round(mu * lattice[j][k]);
                }
                for (int k = 0; k < m; k++) {
                    ortho[i][k] -= std::round(mu * ortho[j][k]);
                }
            }

            gs[i] = ortho[i];

            for (int j = i - 1; j >= 0; j--) {
                for (int k = 0; k < m; k++) {
                    gs[i][k] -= std::round(u[j] * gs[j][k]);
                }
            }

            for (int j = i - 1; j >= 0; j--) {
                double dotProduct = 0.0;
                for (int k = 0; k < m; k++) {
                    dotProduct += gs[i][k] * ort[j][k];
                }
                u[j] = dotProduct / c[j];
                for (int k = 0; k < m; k++) {
                    gs[i][k] -= std::round(u[j] * ort[j][k]);
                }
            }

            c[i] = 0.0;
            for (int k = 0; k < m; k++) {
                c[i] += gs[i][k] * gs[i][k];
            }

            i = i - 1;
        }
    }
}

int main() {
    std::vector<std::vector<int>> lattice = {
        {1, 2, 3},
        {4, 5, 6},
        {7, 8, 9}
    };

    idealLatticeReduction(lattice);

    std::cout << "Reduced lattice:" << std::endl;
    for (const auto& row : lattice) {
        for (const auto& element : row) {
            std::cout << element << " ";
        }
        std::cout << std::endl;
    }

    return 0;
}


#endif // LATTICE_REDUCTION_HPP