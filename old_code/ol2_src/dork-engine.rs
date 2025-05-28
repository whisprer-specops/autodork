// src/dork_engine.rs
use reqwest::Client;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::time::Duration;

/// Represents a result from a dork query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkResult {
    pub url: String,
    pub title: String,
    pub snippet: String,
    pub content_type: Option<String>,
    pub found_dork: String,
}

/// Main dork engine struct for generating and executing dorks
pub struct DorkEngine {
    client: Client,
    dork_categories: HashMap<String, Vec<String>>,
    regex_patterns: HashMap<String, Regex>,
}

impl DorkEngine {
    /// Create a new DorkEngine instance with default configurations
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        // Initialize HTTP client with custom user agent and timeouts
        let client = Client::builder()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .timeout(Duration::from_secs(30))
            .build()?;
        
        // Initialize dork categories with templates
        let mut dork_categories = HashMap::new();
        
        // Domain discovery dorks
        dork_categories.insert("domain_discovery".to_string(), vec![
            "site:*.{domain} -www".to_string(),
            "site:{domain} inurl:subdomain".to_string(),
            "site:{domain} inurl:dev".to_string(),
            "site:{domain} inurl:test".to_string(),
            "site:{domain} inurl:staging".to_string(),
            "ip:{ip} -site:{domain}".to_string(),
            "site:{domain} port:(8080|8443|3000|8000|8081|8888)".to_string(),
        ]);
        
        // Sensitive content dorks
        dork_categories.insert("sensitive_content".to_string(), vec![
            "site:{domain} (filetype:pdf|filetype:doc|filetype:docx|filetype:xls|filetype:xlsx) (confidential|internal|private|secret)".to_string(),
            "site:{domain} inurl:(internal|private|confidential|secret) ext:(pdf|doc|docx|xls|xlsx)".to_string(),
            "site:{domain} ext:(conf|cfg|config|env|ini|json|xml|yml|yaml)".to_string(),
            "site:{domain} (inurl:config|inurl:configuration) ext:(php|txt|xml|json)".to_string(),
            "site:{domain} ext:(bak|backup|old|save|swp|temp|tmp)".to_string(),
            "site:{domain} inurl:(backup|bak|old|save|archive)".to_string(),
            "site:{domain} ext:log".to_string(),
            "site:{domain} inurl:(log|logs) ext:(txt|log)".to_string(),
        ]);
        
        // Vulnerability detection dorks
        dork_categories.insert("vulnerability".to_string(), vec![
            "site:{domain} (intext:\"sql syntax near\"|intext:\"syntax error has occurred\"|intext:\"incorrect syntax near\"|intext:\"unexpected end of SQL command\"|intext:\"Warning: mysql_fetch_array()\"|intext:\"Error Executing Database Query\"|intext:\"Microsoft OLE DB Provider for ODBC Drivers error\")".to_string(),
            "site:{domain} \"Whitelabel Error Page\"".to_string(),
            "site:{domain} \"PHP Error\"".to_string(),
            "site:{domain} inurl:(admin|cp|dashboard|portal|manage) (intext:username|intext:password|intext:login)".to_string(),
            "site:{domain} intitle:(admin|administration|login|backend|cp)".to_string(),
            "site:s3.amazonaws.com {domain}".to_string(),
            "site:{domain} inurl:s3.amazonaws.com".to_string(),
            "site:{domain} inurl:r2.dev".to_string(),
            "site:{domain} inurl:actuator".to_string(),
            "site:{domain} inurl:wp-content".to_string(),
            "site:{domain} inurl:phpinfo".to_string(),
            "site:{domain} \"Call to undefined function\"".to_string(),
        ]);
        
        // API and endpoint dorks
        dork_categories.insert("api".to_string(), vec![
            "site:{domain} inurl:api".to_string(),
            "site:{domain} (inurl:api/v1|inurl:api/v2|inurl:api/v3)".to_string(),
            "site:{domain} inurl:graphql".to_string(),
            "site:{domain} inurl:swagger".to_string(),
            "site:{domain} inurl:redoc".to_string(),
            "site:{domain} ext:js (api|endpoint|token|key|secret|password|credentials)".to_string(),
            "site:{domain} ext:js (fetch|axios|xhr|ajax)".to_string(),
            "site:{domain} inurl:(oauth|auth|login|signin)".to_string(),
            "site:{domain} inurl:(token|jwt|bearer)".to_string(),
        ]);
        
        // Initialize regex patterns (empty for now, will be compiled as needed)
        let regex_patterns = HashMap::new();
        
        Ok(DorkEngine {
            client,
            dork_categories,
            regex_patterns,
        })
    }
    
    /// Execute a specific dork against a domain
    pub async fn execute_dork(&self, dork: &str, domain: &str) -> Result<Vec<DorkResult>, Box<dyn Error>> {
        // Use custom user agent to prevent blocking
        let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        
        // Replace {domain} placeholder with actual domain
        let dork_query = dork.replace("{domain}", domain);
        
        println!("Executing dork: {}", dork_query);
        
        // Simulate delay to avoid rate limiting
        tokio::time::sleep(Duration::from_millis(1000 + rand::random::<u64>() % 2000)).await;
        
        // Prepare search URL (using DuckDuckGo as an example)
        let search_url = format!("https://html.duckduckgo.com/html/?q={}", 
                               urlencoding::encode(&dork_query));
                            }
                        },
                        Err(e) => {
                            eprintln!("Error executing credential dork {}: {}", dork, e);
                        }
                    }
                    
                    // Add delay to avoid rate limiting
                    sleep(Duration::from_secs(2)).await;
                }
            })
            .buffer_unordered(self.config.concurrency)
            .collect::<Vec<_>>();
        
        // Wait for all tasks to complete
        tasks.await;
        
        // Extract results
        let result = Arc::try_unwrap(credential_results)
            .unwrap_or_else(|_| panic!("Failed to unwrap Arc"))
            .into_inner();
        
        println!("Found {} potential credential exposures", result.len());
        Ok(result)
    }
    
    /// Generate a comprehensive report for a target
    pub async fn generate_report(&self, target: &str, findings: &[serde_json::Value]) -> Result<String, Box<dyn Error>> {
        println!("Generating comprehensive report for target: {}", target);
        
        // Count findings by category
        let mut counts = HashMap::new();
        for finding in findings {
            let category = finding.get("category")
                .and_then(|c| c.as_str())
                .unwrap_or("Unknown");
            
            *counts.entry(category).or_insert(0) += 1;
        }
        
        // Generate markdown report
        let mut report = String::new();
        
        // Add header
        report.push_str(&format!("# Security Assessment Report for {}\n\n", target));
        report.push_str(&format!("Generated on: {}\n\n", chrono::Local::now().to_rfc3339()));
        
        // Add summary
        report.push_str("## Summary\n\n");
        report.push_str(&format!("Target domain: {}\n\n", target));
        report.push_str(&format!("Total findings: {}\n\n", findings.len()));
        
        // Add findings breakdown
        report.push_str("### Findings by Category\n\n");
        report.push_str("| Category | Count |\n");
        report.push_str("|----------|-------|\n");
        
        for (category, count) in counts {
            report.push_str(&format!("| {} | {} |\n", category, count));
        }
        
        report.push_str("\n");
        
        // Add detailed findings
        report.push_str("## Detailed Findings\n\n");
        
        for (i, finding) in findings.iter().enumerate() {
            let title = finding.get("title")
                .and_then(|t| t.as_str())
                .unwrap_or("Unknown Finding");
            
            let url = finding.get("url")
                .and_then(|u| u.as_str())
                .unwrap_or("N/A");
            
            let description = finding.get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("No description available");
            
            let severity = finding.get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("Unknown");
            
            report.push_str(&format!("### Finding {}: {}\n\n", i + 1, title));
            report.push_str(&format!("**Severity**: {}\n\n", severity));
            report.push_str(&format!("**URL**: {}\n\n", url));
            report.push_str(&format!("**Description**: {}\n\n", description));
            
            // Add recommendation if available
            if let Some(recommendation) = finding.get("recommendation").and_then(|r| r.as_str()) {
                report.push_str(&format!("**Recommendation**: {}\n\n", recommendation));
            }
            
            report.push_str("---\n\n");
        }
        
        // Add recommendations section
        report.push_str("## Recommendations\n\n");
        report.push_str("Based on the findings, the following recommendations are suggested:\n\n");
        
        // Add common recommendations
        report.push_str("1. **Secure Sensitive Information**: Ensure that no sensitive information such as API keys, credentials, or internal paths are exposed in public repositories or client-side code.\n\n");
        report.push_str("2. **Implement Proper Security Headers**: Add security headers such as Content-Security-Policy, X-Frame-Options, and X-XSS-Protection to all web pages.\n\n");
        report.push_str("3. **Regular Security Scanning**: Implement regular security scanning and monitoring for the domain to quickly identify and remediate new vulnerabilities.\n\n");
        report.push_str("4. **Secure Cloud Storage**: Review all cloud storage settings to ensure proper access controls are in place.\n\n");
        report.push_str("5. **Implement Email Security**: Configure SPF, DKIM, and DMARC records for improved email security and to prevent spoofing.\n\n");
        
        println!("Report generated successfully");
        Ok(report)
    }
    
    /// Helper method to enable cloning for async operations
    fn clone(&self) -> Self {
        // Create a new client instance
        let client = Client::builder()
            .user_agent(&self.config.user_agents[0])
            .timeout(Duration::from_secs(self.config.timeout_seconds))
            .build()
            .unwrap_or_else(|_| Client::new());
        
        // Clone the DorkEngine with the new client
        DorkEngine {
            client,
            dork_categories: self.dork_categories.clone(),
            regex_patterns: self.regex_patterns.clone(),
            config: self.config.clone(),
            result_cache: Arc::clone(&self.result_cache),
        }
    }
}

impl fmt::Debug for DorkEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DorkEngine")
            .field("dork_categories", &self.dork_categories.len())
            .field("regex_patterns", &self.regex_patterns.len())
            .field("config", &self.config)
            .field("cache_size", &{
                match self.result_cache.try_lock() {
                    Ok(cache) => cache.len(),
                    Err(_) => 0,
                }
            })
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;
    
    #[test]
    async fn test_new() {
        let engine = DorkEngine::new().await;
        assert!(engine.is_ok());
        
        let engine = engine.unwrap();
        assert!(!engine.dork_categories.is_empty());
    }
    
    #[test]
    async fn test_generate_dorks() {
        let engine = DorkEngine::new().await.unwrap();
        let dorks = engine.generate_dorks_for_domain("example.com");
        
        assert!(!dorks.is_empty());
        assert!(dorks.iter().any(|d| d.contains("example.com")));
    }
    
    #[test]
    async fn test_parse_results() {
        let engine = DorkEngine::new().await.unwrap();
        
        // Sample HTML for testing
        let html = r#"
        <div class="result">
            <h2><a href="https://example.com">Example Title</a></h2>
            <div class="result__snippet">This is a sample snippet.</div>
        </div>
        "#;
        
        let results = engine.parse_duckduckgo_results(html);
        assert!(results.is_ok());
        
        let results = results.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com");
        assert_eq!(results[0].title, "Example Title");
        assert_eq!(results[0].snippet, "This is a sample snippet.");
    }
    
    #[test]
    #[ignore] // Ignore by default to avoid external requests during testing
    async fn test_execute_dork() {
        let engine = DorkEngine::new().await.unwrap();
        let results = engine.execute_dork("site:{domain}", "example.com").await;
        
        // This test makes external requests, so we don't make strict assertions
        match results {
            Ok(r) => println!("Found {} results", r.len()),
            Err(e) => println!("Error: {}", e),
        }
    }
    
    #[test]
    async fn test_extract_domain() {
        assert_eq!(extract_domain("https://example.com/path"), Some("example.com"));
        assert_eq!(extract_domain("http://sub.example.com"), Some("sub.example.com"));
        assert_eq!(extract_domain("example.com"), None); // No scheme
    }
    
    // Helper function to extract domain from URL
    fn extract_domain(url: &str) -> Option<&str> {
        if let Some(host_start) = url.find("://") {
            let host_part = &url[host_start + 3..];
            if let Some(path_start) = host_part.find('/') {
                return Some(&host_part[..path_start]);
            } else {
                return Some(host_part);
            }
        }
        None
    }
}
