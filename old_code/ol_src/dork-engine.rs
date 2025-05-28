// src/dork_engine.rs
use reqwest::Client;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::time::Duration;

/// Represents a result from a dork query
#[derive(Debug, Serialize, Deserialize)]
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
    regex_patterns: HashMap<String, Vec<Regex>>,
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
        
        // Execute the search
        let response = self.client.get(&search_url)
            .header("User-Agent", user_agent)
            .send()
            .await?;
        
        let status = response.status();
        if !status.is_success() {
            return Err(format!("Search failed with status code: {}", status).into());
        }
        
        let html = response.text().await?;
        
        // Parse results using scraper
        let document = scraper::Html::parse_document(&html);
        
        // Extract search results (this selector is for DuckDuckGo, would need to be adapted for other engines)
        let result_selector = scraper::Selector::parse(".result").unwrap_or_else(|_| {
            scraper::Selector::parse("div").unwrap()
        });
        
        let title_selector = scraper::Selector::parse("h2").unwrap_or_else(|_| {
            scraper::Selector::parse("a").unwrap()
        });
        
        let link_selector = scraper::Selector::parse("a").unwrap();
        let snippet_selector = scraper::Selector::parse(".result__snippet").unwrap_or_else(|_| {
            scraper::Selector::parse("p").unwrap()
        });
        
        let mut results = Vec::new();
        
        for result_element in document.select(&result_selector) {
            // Extract title
            let title = result_element
                .select(&title_selector)
                .next()
                .map(|e| e.text().collect::<String>())
                .unwrap_or_else(|| "No title".to_string())
                .trim()
                .to_string();
            
            // Extract URL
            let url = result_element
                .select(&link_selector)
                .next()
                .and_then(|e| e.value().attr("href"))
                .map(|href| {
                    if href.starts_with("http") {
                        href.to_string()
                    } else {
                        format!("https:{}", href)
                    }
                })
                .unwrap_or_else(|| "#".to_string());
            
            // Extract snippet
            let snippet = result_element
                .select(&snippet_selector)
                .next()
                .map(|e| e.text().collect::<String>())
                .unwrap_or_else(|| "".to_string())
                .trim()
                .to_string();
            
            // Skip ad results or results without proper URLs
            if url == "#" || url.contains("duckduckgo.com/y.js") {
                continue;
            }
            
            // Create DorkResult
            results.push(DorkResult {
                url,
                title,
                snippet,
                content_type: None, // Will be determined later if needed
                found_dork: dork_query.clone(),
            });
        }
        
        Ok(results)
    }
    
    /// Generate dorks for a domain based on predefined templates
    pub fn generate_dorks_for_domain(&self, domain: &str) -> Vec<String> {
        let mut dorks = Vec::new();
        
        for (_, dork_templates) in &self.dork_categories {
            for template in dork_templates {
                // Replace placeholders with domain
                let dork = template.replace("{domain}", domain);
                dorks.push(dork);
            }
        }
        
        dorks
    }
    
    /// Discover subdomains for a target domain
    pub async fn discover_subdomains(&self, target: &str) -> Result<Vec<String>, Box<dyn Error>> {
        println!("Discovering subdomains for target: {}", target);
        
        let mut subdomains = Vec::new();
        let subdomain_dorks = vec![
            format!("site:*.{} -www", target),
            format!("site:{} inurl:subdomain", target),
            format!("site:{} inurl:dev", target),
            format!("site:{} inurl:staging", target),
            format!("site:{} inurl:test", target),
        ];
        
        for dork in &subdomain_dorks {
            match self.execute_dork(dork, target).await {
                Ok(results) => {
                    for result in results {
                        if let Ok(url) = url::Url::parse(&result.url) {
                            if let Some(host) = url.host_str() {
                                if host.contains(target) && !subdomains.contains(&host.to_string()) {
                                    subdomains.push(host.to_string());
                                }
                            }
                        }
                    }
                },
                Err(e) => {
                    eprintln!("Error executing subdomain dork {}: {}", dork, e);
                }
            }
            
            // Add delay to avoid rate limiting
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        
        // Add the main domain if not already in the list
        if !subdomains.contains(&target.to_string()) {
            subdomains.push(target.to_string());
        }
        
        println!("Discovered {} subdomains", subdomains.len());
        Ok(subdomains)
    }
    
    /// Execute all dorks against a target domain and its subdomains
    pub async fn execute_all_dorks(&self, target: &str, subdomains: &[String]) -> Result<Vec<DorkResult>, Box<dyn Error>> {
        println!("Executing all dorks against target: {}", target);
        
        let mut all_results = Vec::new();
        let dorks = self.generate_dorks_for_domain(target);
        
        println!("Generated {} dorks to execute", dorks.len());
        
        // Execute dorks against main domain
        for dork in &dorks {
            match self.execute_dork(dork, target).await {
                Ok(results) => {
                    all_results.extend(results);
                },
                Err(e) => {
                    eprintln!("Error executing dork {}: {}", dork, e);
                }
            }
            
            // Add delay to avoid rate limiting
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        
        // Execute dorks against subdomains (with a limit to avoid too many requests)
        for subdomain in subdomains.iter().take(5) {
            for dork in &dorks {
                match self.execute_dork(dork, subdomain).await {
                    Ok(results) => {
                        all_results.extend(results);
                    },
                    Err(e) => {
                        eprintln!("Error executing dork {} against subdomain {}: {}", dork, subdomain, e);
                    }
                }
                
                // Add delay to avoid rate limiting
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        
        println!("Executed dorks with {} total results", all_results.len());
        Ok(all_results)
    }
    
    /// Query Shodan for information about a domain and its subdomains
    pub async fn query_shodan(&self, target: &str, subdomains: &[String]) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        println!("Querying Shodan for target: {}", target);
        
        let mut results = Vec::new();
        
        // Note: In a real implementation, you would need a Shodan API key
        // For now, we'll use a simulated response
        
        // Simulate Shodan responses for the target and its subdomains
        for domain in std::iter::once(target).chain(subdomains.iter().map(|s| s.as_str())) {
            // Create a simulated Shodan response
            let response = serde_json::json!({
                "ip_str": format!("123.45.67.{}", rand::random::<u8>()),
                "ports": [80, 443, 8080],
                "hostnames": [domain],
                "domains": [domain.split('.').skip(1).collect::<Vec<_>>().join(".")],
                "vulns": {
                    "CVE-2021-1234": {
                        "summary": "Example vulnerability for simulation",
                        "severity": "Medium"
                    }
                }
            });
            
            results.push(response);
            
            // Add delay between requests
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        println!("Retrieved {} Shodan results", results.len());
        Ok(results)
    }
    
    /// Query URLScan.io for information about a domain and its subdomains
    pub async fn query_urlscan(&self, target: &str, subdomains: &[String]) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        println!("Querying URLScan.io for target: {}", target);
        
        let mut results = Vec::new();
        
        // Note: In a real implementation, you would query the URLScan.io API
        // For now, we'll use a simulated response
        
        // Simulate URLScan responses for the target and a few subdomains
        for domain in std::iter::once(target).chain(subdomains.iter().take(3).map(|s| s.as_str())) {
            // Create a simulated URLScan response
            let response = serde_json::json!({
                "page": {
                    "url": format!("https://{}", domain),
                    "domain": domain,
                    "ip": format!("123.45.67.{}", rand::random::<u8>())
                },
                "lists": {
                    "urls": [
                        format!("https://{}/index.html", domain),
                        format!("https://{}/about.html", domain),
                        format!("https://{}/contact.html", domain)
                    ],
                    "domains": [domain],
                    "ips": [format!("123.45.67.{}", rand::random::<u8>())]
                }
            });
            
            results.push(response);
            
            // Add delay between requests
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        println!("Retrieved {} URLScan results", results.len());
        Ok(results)
    }
    
    /// Gather DNS information about a domain and its subdomains
    pub async fn gather_dns_info(&self, target: &str, subdomains: &[String]) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        println!("Gathering DNS information for target: {}", target);
        
        let mut results = Vec::new();
        
        // Note: In a real implementation, you would use a DNS resolver
        // For now, we'll use simulated responses
        
        // Simulate DNS info for the target and its subdomains
        for domain in std::iter::once(target).chain(subdomains.iter().map(|s| s.as_str())) {
            // Create a simulated DNS info response
            let response = serde_json::json!({
                "domain": domain,
                "records": {
                    "A": [format!("123.45.67.{}", rand::random::<u8>())],
                    "MX": [format!("mail.{}", domain)],
                    "NS": [format!("ns1.{}", domain), format!("ns2.{}", domain)],
                    "TXT": ["v=spf1 include:_spf.google.com ~all"]
                }
            });
            
            results.push(response);
            
            // Add delay between requests
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        
        println!("Retrieved DNS information for {} domains", results.len());
        Ok(results)
    }
    
    /// Extract JavaScript files from dork results
    pub async fn extract_javascript_files(&self, dork_results: &[DorkResult]) -> Result<Vec<String>, Box<dyn Error>> {
        println!("Extracting JavaScript files from dork results");
        
        let mut js_files = Vec::new();
        
        // Extract URLs of JavaScript files from the dork results
        for result in dork_results {
            if result.url.ends_with(".js") {
                js_files.push(result.url.clone());
                continue;
            }
            
            // For HTML pages, try to find linked JavaScript files
            if result.url.ends_with(".html") || !result.url.contains('.') {
                // Fetch the page content
                match self.client.get(&result.url)
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await {
                    Ok(response) => {
                        if response.status().is_success() {
                            let html = response.text().await?;
                            let document = scraper::Html::parse_document(&html);
                            let script_selector = scraper::Selector::parse("script[src]").unwrap_or_else(|_| {
                                scraper::Selector::parse("script").unwrap()
                            });
                            
                            for script_elem in document.select(&script_selector) {
                                if let Some(src) = script_elem.value().attr("src") {
                                    let js_url = if src.starts_with("http") {
                                        src.to_string()
                                    } else if src.starts_with("//") {
                                        format!("https:{}", src)
                                    } else if src.starts_with('/') {
                                        // Resolve relative URL
                                        if let Ok(base_url) = url::Url::parse(&result.url) {
                                            if let Ok(resolved) = base_url.join(src) {
                                                resolved.to_string()
                                            } else {
                                                continue;
                                            }
                                        } else {
                                            continue;
                                        }
                                    } else {
                                        // Resolve relative URL (without leading slash)
                                        if let Ok(base_url) = url::Url::parse(&result.url) {
                                            if let Ok(resolved) = base_url.join(src) {
                                                resolved.to_string()
                                            } else {
                                                continue;
                                            }
                                        } else {
                                            continue;
                                        }
                                    };
                                    
                                    if js_url.ends_with(".js") && !js_files.contains(&js_url) {
                                        js_files.push(js_url);
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("Error fetching {}: {}", result.url, e);
                    }
                }
                
                // Add delay to avoid rate limiting
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        
        println!("Extracted {} JavaScript files", js_files.len());
        Ok(js_files)
    }
    
    /// Analyze JavaScript files for sensitive information
    pub async fn analyze_javascript_files(&self, js_files: &[String]) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        println!("Analyzing {} JavaScript files", js_files.len());
        
        let mut analysis_results = Vec::new();
        
        // Define regex patterns for sensitive information
        let api_key_regex = Regex::new(r"(?i)(api[_-]?key|apikey|secret[_-]?key|token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]+)[\"']").unwrap();
        let endpoint_regex = Regex::new(r"(?i)(fetch|axios|ajax)\.?(get|post|put|delete)?\s*\(\s*[\"']([^\"']+)[\"']").unwrap();
        let url_regex = Regex::new(r"(?i)(url|endpoint|api)[\"']?\s*[:=]\s*[\"']([^\"']+)[\"']").unwrap();
        
        // Analyze each JavaScript file
        for js_url in js_files {
            // Fetch the JavaScript file
            match self.client.get(js_url)
                .timeout(Duration::from_secs(10))
                .send()
                .await {
                Ok(response) => {
                    if response.status().is_success() {
                        let js_content = response.text().await?;
                        
                        // Look for API keys
                        let api_keys = api_key_regex.captures_iter(&js_content)
                            .filter_map(|cap| {
                                if let (Some(key_type), Some(key_value)) = (cap.get(1), cap.get(2)) {
                                    Some(serde_json::json!({
                                        "type": key_type.as_str(),
                                        "value": key_value.as_str()
                                    }))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>();
                        
                        // Look for API endpoints
                        let endpoints = endpoint_regex.captures_iter(&js_content)
                            .chain(url_regex.captures_iter(&js_content))
                            .filter_map(|cap| {
                                if let Some(url) = cap.get(3) {
                                    Some(serde_json::json!({
                                        "url": url.as_str(),
                                        "method": cap.get(2).map_or("GET", |m| m.as_str().to_uppercase())
                                    }))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>();
                        
                        // Create analysis result
                        let analysis = serde_json::json!({
                            "url": js_url,
                            "api_keys": api_keys,
                            "endpoints": endpoints,
                            "size_bytes": js_content.len()
                        });
                        
                        analysis_results.push(analysis);
                    }
                },
                Err(e) => {
                    eprintln!("Error fetching JavaScript file {}: {}", js_url, e);
                }
            }
            
            // Add delay to avoid rate limiting
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        println!("Completed analysis of JavaScript files");
        Ok(analysis_results)
    }
    
    /// Check for cloud storage resources related to the target
    pub async fn check_cloud_storage(&self, target: &str) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        println!("Checking cloud storage for target: {}", target);
        
        let mut storage_results = Vec::new();
        
        // Define cloud storage dorks
        let storage_dorks = vec![
            format!("site:s3.amazonaws.com {}", target),
            format!("site:{} inurl:s3.amazonaws.com", target),
            format!("site:{} inurl:storage.googleapis.com", target),
            format!("site:{} inurl:blob.core.windows.net", target),
            format!("site:{} inurl:r2.dev", target),
        ];
        
        // Execute each cloud storage dork
        for dork in &storage_dorks {
            match self.execute_dork(dork, target).await {
                Ok(results) => {
                    for result in results {
                        let storage_type = if result.url.contains("s3.amazonaws.com") {
                            "AWS S3"
                        } else if result.url.contains("storage.googleapis.com") {
                            "Google Cloud Storage"
                        } else if result.url.contains("blob.core.windows.net") {
                            "Azure Blob Storage"
                        } else if result.url.contains("r2.dev") {
                            "Cloudflare R2"
                        } else {
                            "Unknown"
                        };
                        
                        let storage_result = serde_json::json!({
                            "url": result.url,
                            "title": result.title,
                            "snippet": result.snippet,
                            "storage_type": storage_type
                        });
                        
                        storage_results.push(storage_result);
                    }
                },
                Err(e) => {
                    eprintln!("Error executing cloud storage dork {}: {}", dork, e);
                }
            }
            
            // Add delay to avoid rate limiting
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        
        println!("Found {} cloud storage resources", storage_results.len());
        Ok(storage_results)
    }
}
