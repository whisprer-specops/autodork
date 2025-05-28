use nalgebra::{Matrix2, Complex};
use num_complex::Complex64;
use primal::Sieve;
use std::collections::HashMap;
use crate::vulnerability_matcher::{VulnerabilityMatch, Finding};
use crate::entropy::shannon_entropy;

#[derive(Debug, Clone)]
pub struct QuantumScorer {
    factor_matrix: FactorMatrix,
    sieve: Sieve,
}

#[derive(Debug, Clone)]
struct FactorMatrix {
    matrix: Matrix2<Complex64>,
}

impl FactorMatrix {
    fn new() -> Self {
        let matrix = Matrix2::new(
            Complex64::new(1.0, 0.0), Complex64::new(0.0, 0.0),
            Complex64::new(0.0, 0.0), Complex64::new(1.0, 0.0),
        );
        FactorMatrix { matrix }
    }

    fn align(&self, input_vector: &[f64]) -> f64 {
        if input_vector.len() < 2 {
            return 0.0;
        }
        let input = Matrix2::new(
            Complex64::new(input_vector[0], 0.0), Complex64::new(0.0, 0.0),
            Complex64::new(0.0, 0.0), Complex64::new(input_vector[1], 0.0),
        );
        let result = self.matrix * input;
        result.norm()
    }
}

impl QuantumScorer {
    pub fn new(max_prime: usize) -> Self {
        QuantumScorer {
            factor_matrix: FactorMatrix::new(),
            sieve: Sieve::new(max_prime),
        }
    }

    pub fn score_vulnerability(&self, vuln_match: &VulnerabilityMatch) -> f64 {
        let severity_weight = match vuln_match.severity.as_str() {
            "Critical" => 4.0,
            "High" => 3.0,
            "Medium" => 2.0,
            "Low" => 1.0,
            _ => 0.5,
        };
        let context_tokens: Vec<u64> = vuln_match.context
            .split_whitespace()
            .map(|word| self.sieve.factor(word.len() as usize).unwrap_or(vec![(word.len() as u64, 1)]))
            .flat_map(|factors| factors.into_iter().map(|(p, _)| p))
            .collect();
        let entropy = shannon_entropy(&context_tokens);
        let input_vector = vec![severity_weight, entropy];
        self.factor_matrix.align(&input_vector)
    }

    pub fn rank_findings(&self, findings: &mut Vec<Finding>) {
        let mut scored: Vec<(Finding, f64)> = findings
            .drain(..)
            .map(|f| {
                let score = self.score_finding(&f);
                (f, score)
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        findings.extend(scored.into_iter().map(|(f, _)| f));
    }

    fn score_finding(&self, finding: &Finding) -> f64 {
        let severity_weight = match finding.severity.as_str() {
            "Critical" => 4.0,
            "High" => 3.0,
            "Medium" => 2.0,
            "Low" => 1.0,
            _ => 0.5,
        };
        let context = finding.description.as_str();
        let context_tokens: Vec<u64> = context
            .split_whitespace()
            .map(|word| self.sieve.factor(word.len() as usize).unwrap_or(vec![(word.len() as u64, 1)]))
            .flat_map(|factors| factors.into_iter().map(|(p, _)| p))
            .collect();
        let entropy = shannon_entropy(&context_tokens);
        let input_vector = vec![severity_weight, entropy];
        self.factor_matrix.align(&input_vector)
    }
}