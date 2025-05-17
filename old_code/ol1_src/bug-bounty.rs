// src/bug_bounty.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use tokio::time::sleep;
use crate::Finding;

/// Represents a bug bounty program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugBountyProgram {
    pub platform: String,
    pub name: String,
    pub url: String,
    pub in_scope_domains: Vec<String>,
    pub out_of_scope_domains: Vec<String>,
    pub vulnerability_types: HashMap<String, bool>,
    pub known_rewards: HashMap<String, f64>,
}

/// Represents a match between a finding and a bug bounty program
#[derive(Debug, Serialize, Deserialize)]
pub struct BountyMatch {
    pub finding_id: String,
    pub platform: String,
    pub program_name: String,
    pub estimated_reward: Option<f64>,
    pub submission_url: Option<String>,
}

/// Manager for bug bounty program matching
pub struct BugBountyManager {
    programs: Vec<BugBountyProgram>,
}

impl BugBountyManager {
    /// Create a new BugBountyManager with default programs
    pub fn new() -> Self {
        let mut programs = Vec::new();
        
        // Add some common bug bounty programs as examples
        // In a real implementation, these would be loaded from a database or API
        
        // HackerOne example programs
        programs.push(BugBountyProgram {
            platform: "HackerOne".to_string(),
            name: "Example Program 1".to_string(),
            url: "https://hackerone.com/example1".to_string(),
            in_scope_domains: vec!["example1.com".to_string(), "api.example1.com".to_string()],
            out_of_scope_domains: vec!["staging.example1.com".to_string()],
            vulnerability_types: {
                let mut types = HashMap::new();
                types.insert("XSS".to_string(), true);
                types.insert("CSRF".to_string(), true);
                types.insert("SQLi".to_string(), true);
                types.insert("Open Redirect".to_string(), true);
                types
            },
            known_rewards: {
                let mut rewards = HashMap::new();
                rewards.insert("XSS".to_string(), 500.0);
                rewards.insert("CSRF".to_string(), 300.0);
                rewards.insert("SQLi".to_string(), 1000.0);
                rewards.insert("Open Redirect".to_string(), 250.0);
                rewards
            },
        });
        
        // Bugcrowd example programs
        programs.push(BugBountyProgram {
            platform: "Bugcrowd".to_string(),
            name: "Example Program 2".to_string(),
            url: "https://bugcrowd.com/example2".to_string(),
            in_scope_domains: vec!["example2.com".to_string(), "*.example2.com".to_string()],
            out_of_scope_domains: vec!["internal.example2.com".to_string()],
            vulnerability_types: {
                let mut types = HashMap::new();
                types.insert("XSS".to_string(), true);
                types.insert("CSRF".to_string(), true);
                types.insert("SQLi".to_string(), true);
                types.insert("Information Disclosure".to_string(), true);
                types
            },
            known_rewards: {
                let mut rewards = HashMap::new();
                rewards.insert("XSS".to_string(), 700.0);
                rewards.insert("CSRF".to_string(), 400.0);
                rewards.insert("SQLi".to_string(), 1500.0);
                rewards.insert("Information Disclosure".to_string(), 600.0);
                rewards
            },
        });
        
        BugBountyManager { programs }
    }

    /// Find programs that match a given domain and vulnerability type
    pub fn find_matching_programs(&self, domain: &str, vulnerability_type: &str) -> Vec<&BugBountyProgram> {
        self.programs.iter()
            .filter(|p| {
                // Check if domain is in scope
                p.in_scope_domains.iter().any(|d| {
                    if d.starts_with("*.") {
                        // Wildcard domain matching
                        let base_domain = &d[2..]; // Remove the "*." prefix
                        domain.ends_with(base_domain)
                    } else {
                        // Exact domain matching
                        domain == d
                    }
                }) &&
                // Check if domain is not out of scope
                !p.out_of_scope_domains.iter().any(|d| domain == d) &&
                // Check if vulnerability type is accepted
                p.vulnerability_types.get(vulnerability_type).copied().unwrap_or(false)
            })
            .collect()
    }

    /// Estimate the reward for a finding
    pub fn estimate_reward(&self, program: &BugBountyProgram, vulnerability_type: &str, severity: &str) -> Option<f64> {
        // Get the base reward for the vulnerability type
        let base_reward = program.known_rewards.get(vulnerability_type).copied();
        
        // Adjust based on severity
        match base_reward {
            Some(reward) => {
                let severity_multiplier = match severity.to_lowercase().as_str() {
                    "critical" => 2.0,
                    "high" => 1.5,
                    "medium" => 1.0,
                    "low" => 0.5,
                    _ => 1.0,
                };
                
                Some(reward * severity_multiplier)
            },
            None => None,
        }
    }

    /// Generate a submission template for a finding
    pub fn generate_submission_template(&self, program: &BugBountyProgram, finding: &Finding) -> String {
        let platform = &program.platform;
        
        // Create a platform-specific template
        match platform.as_str() {
            "HackerOne" => {
                format!(
                    "# Vulnerability Report\n\n## Title\n{}\n\n## Description\n{}\n\n## Steps to Reproduce\n1. \n2. \n3. \n\n## Impact\n\n## Proof of Concept\n{}\n",
                    finding.finding_type,
                    finding.description,
                    finding.url.as_deref().unwrap_or("N/A"),
                )
            },
            "Bugcrowd" => {
                format!(
                    "### Title\n{}\n\n### Vulnerability Type\n{}\n\n### Description\n{}\n\n### Steps to Reproduce\n\n### Impact\n\n### Remediation\n",
                    finding.finding_type,
                    finding.finding_type,
                    finding.description,
                )
            },
            _ => {
                format!(
                    "# Bug Report\n\n## Title\n{}\n\n## Description\n{}\n\n## URL\n{}\n\n## Steps to Reproduce\n\n## Impact\n",
                    finding.finding_type,
                    finding.description,
                    finding.url.as_deref().unwrap_or("N/A"),
                )
            },
        }
    }

    /// Update programs from public sources
    pub async fn update_programs(&mut self) -> Result<(), Box<dyn Error>> {
        println!("Updating bug bounty programs from public sources...");
        
        // In a real implementation, this would fetch data from APIs or scrape websites
        // For this example, we'll just simulate a delay
        sleep(Duration::from_secs(1)).await;
        
        // Simulated update finished
        println!("Updated bug bounty programs");
        
        Ok(())
    }

    /// Match findings to bug bounty programs
    pub async fn match_to_bug_bounty_programs(&self, findings: &[Finding]) -> Result<Vec<BountyMatch>, Box<dyn Error>> {
        println!("Matching {} findings to bug bounty programs...", findings.len());
        
        let mut matches = Vec::new();
        
        for finding in findings {
            // Get domain from URL or description
            let domain = if let Some(url) = &finding.url {
                if let Ok(parsed_url) = url::Url::parse(url) {
                    parsed_url.host_str().unwrap_or("").to_string()
                } else {
                    continue;
                }
            } else if finding.description.contains("http") {
                // Try to extract a domain from the description
                if let Some(url_start) = finding.description.find("http") {
                    let url_substring = &finding.description[url_start..];
                    if let Some(url_end) = url_substring.find(' ').or_else(|| Some(url_substring.len())) {
                        let potential_url = &url_substring[..url_end];
                        if let Ok(parsed_url) = url::Url::parse(potential_url) {
                            parsed_url.host_str().unwrap_or("").to_string()
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            } else {
                continue;
            };
            
            if domain.is_empty() {
                continue;
            }
            
            // Extract vulnerability type from finding
            let vulnerability_type = match finding.finding_type.as_str() {
                t if t.contains("XSS") => "XSS",
                t if t.contains("SQL") => "SQLi",
                t if t.contains("CSRF") => "CSRF",
                t if t.contains("Redirect") => "Open Redirect",
                t if t.contains("Information") => "Information Disclosure",
                t if t.contains("Sensitive") => "Information Disclosure",
                _ => "Other",
            };
            
            // Find matching programs
            let matching_programs = self.find_matching_programs(&domain, vulnerability_type);
            
            for program in matching_programs {
                // Estimate reward
                let estimated_reward = self.estimate_reward(program, vulnerability_type, &finding.severity);
                
                // Create match
                matches.push(BountyMatch {
                    finding_id: finding.id.clone(),
                    platform: program.platform.clone(),
                    program_name: program.name.clone(),
                    estimated_reward,
                    submission_url: Some(program.url.clone()),
                });
            }
        }
        
        println!("Found {} bug bounty matches", matches.len());
        
        Ok(matches)
    }
}
