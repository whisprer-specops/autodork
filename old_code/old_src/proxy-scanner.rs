// Now we'll continue with the completed file that includes both parts together

// src/proxy_scanner.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::timeout;
use rand::Rng;
use reqwest::Client;
use url::Url;
use futures::stream::{self, StreamExt};

/// Represents a proxy server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyInfo {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub anonymity: String,
    pub response_time: f64,
    pub country: String,
    pub last_checked: u64,
}

/// The main proxy scanner implementation
pub struct ProxyScanner {
    client: Client,
    proxy_sources: Vec<String>,
    connection_limit: usize,
    validation_rounds: usize,
    timeout_duration: f64,
    check_anonymity: bool,
}

impl ProxyScanner {
    /// Create a new ProxyScanner with default configuration
    pub fn new() -> Self {
        Self::new_with_config(
            150,  // 150 concurrent connections
            3,    // 3 validation rounds
            5.0,  // 5 second timeout
            true, // Check anonymity
        )
    }

    /// Create a new ProxyScanner with custom configuration
    pub fn new_with_config(
        connection_limit: usize,
        validation_rounds: usize,
        timeout_seconds: f64,
        check_anonymity: bool,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());

        // Default proxy sources
        let proxy_sources = vec![
            "https://www.freeproxylists.net/".to_string(),
            "https://free-proxy-list.net/".to_string(),
            "https://www.sslproxies.org/".to_string(),
            "https://www.us-proxy.org/".to_string(),
            "https://free-proxy-list.net/uk-proxy.html".to_string(),
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt".to_string(),
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt".to_string(),
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt".to_string(),
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt".to_string(),
        ];

        ProxyScanner {
            client,
            proxy_sources,
            connection_limit,
            validation_rounds,
            timeout_duration: timeout_seconds,
            check_anonymity,
        }
    }

    /// Scan for working proxies
    pub async fn scan_proxies(&self) -> Result<Vec<ProxyInfo>, Box<dyn Error>> {
        println!("Starting proxy scan...");
        
        // Fetch proxies from sources
        let proxies = self.fetch_proxies_from_sources().await?;
        println!("Fetched {} potential proxies from sources", proxies.len());
        
        // Validate proxies
        let validated_proxies = self.validate_proxies(proxies).await?;
        println!("Found {} working proxies", validated_proxies.len());
        
        Ok(validated_proxies)
    }

    /// Fetch proxies from configured sources
    async fn fetch_proxies_from_sources(&self) -> Result<Vec<ProxyInfo>, Box<dyn Error>> {
        let mut all_proxies = Vec::new();
        
        for source in &self.proxy_sources {
            println!("Fetching proxies from source: {}", source);
            
            match self.client.get(source)
                .timeout(Duration::from_secs(15))
                .send()
                .await {
                Ok(response) => {
                    if response.status().is_success() {
                        let content = response.text().await?;
                        let proxies = self.parse_proxy_list(&content);
                        println!("Found {} proxies from {}", proxies.len(), source);
                        all_proxies.extend(proxies);
                    } else {
                        println!("Failed to fetch from {}: HTTP {}", source, response.status());
                    }
                },
                Err(e) => {
                    println!("Error fetching from {}: {}", source, e);
                }
            }
            
            // Add delay between requests
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        
        // Deduplicate proxies
        let mut unique_proxies = Vec::new();
        let mut seen = std::collections::HashSet::new();
        
        for proxy in all_proxies {
            let key = format!("{}:{}", proxy.ip, proxy.port);
            if !seen.contains(&key) {
                seen.insert(key);
                unique_proxies.push(proxy);
            }
        }
        
        Ok(unique_proxies)
    }

    /// Parse a proxy list from various formats
    fn parse_proxy_list(&self, content: &str) -> Vec<ProxyInfo> {
        let mut proxies = Vec::new();
        
        // Try parsing each line as an IP:PORT combination
        for line in content.lines() {
            let line = line.trim();
            
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Parse IP:PORT format
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                if let Ok(port) = parts[1].parse::<u16>() {
                    proxies.push(ProxyInfo {
                        ip: parts[0].to_string(),
                        port,
                        protocol: "http".to_string(),
                        anonymity: "unknown".to_string(),
                        response_time: 0.0,
                        country: "Unknown".to_string(),
                        last_checked: 0,
                    });
                }
            }
        }
        
        // If no proxies found, try parsing as HTML
        if proxies.is_empty() {
            let document = scraper::Html::parse_document(content);
            
            // Try different selector patterns common in proxy list websites
            let selectors = [
                "table tr",
                ".table tbody tr",
                "#proxylisttable tbody tr",
            ];
            
            for selector_str in &selectors {
                if let Ok(selector) = scraper::Selector::parse(selector_str) {
                    for row in document.select(&selector) {
                        // Extract IP address
                        let ip = if let Ok(ip_selector) = scraper::Selector::parse("td:nth-child(1)") {
                            row.select(&ip_selector)
                                .next()
                                .map(|e| e.text().collect::<String>().trim().to_string())
                        } else {
                            None
                        };
                        
                        // Extract port
                        let port = if let Ok(port_selector) = scraper::Selector::parse("td:nth-child(2)") {
                            row.select(&port_selector)
                                .next()
                                .and_then(|e| e.text().collect::<String>().trim().parse::<u16>().ok())
                        } else {
                            None
                        };
                        
                        if let (Some(ip), Some(port)) = (ip, port) {
                            if !ip.is_empty() && port > 0 {
                                proxies.push(ProxyInfo {
                                    ip,
                                    port,
                                    protocol: "http".to_string(),
                                    anonymity: "unknown".to_string(),
                                    response_time: 0.0,
                                    country: "Unknown".to_string(),
                                    last_checked: 0,
                                });
                            }
                        }
                    }
                }
                
                // If we found proxies with this selector, no need to try others
                if !proxies.is_empty() {
                    break;
                }
            }
        }
        
        proxies
    }

    /// Validate proxies concurrently
    async fn validate_proxies(&self, proxies: Vec<ProxyInfo>) -> Result<Vec<ProxyInfo>, Box<dyn Error>> {
        println!("Validating {} proxies with {} concurrent connections...", 
                 proxies.len(), self.connection_limit);
        
        // Store validated proxies
        let validated_proxies = Arc::new(Mutex::new(Vec::new()));
        
        // Process proxies concurrently with limited concurrency
        stream::iter(proxies)
            .map(|proxy| {
                let validated_proxies = Arc::clone(&validated_proxies);
                
                async move {
                    if let Ok(is_valid) = self.validate_proxy(&proxy).await {
                        if is_valid {
                            // Get response time and details
                            if let Ok((response_time, country, anonymity)) = self.measure_proxy_performance(&proxy).await {
                                let mut validated_proxy = proxy.clone();
                                validated_proxy.response_time = response_time;
                                validated_proxy.country = country;
                                validated_proxy.anonymity = anonymity;
                                validated_proxy.last_checked = chrono::Utc::now().timestamp() as u64;
                                
                                // Add to validated proxies
                                let mut proxies = validated_proxies.lock().await;
                                proxies.push(validated_proxy);
                                
                                // Print progress
                                println!("Found working proxy: {}:{} ({:.2}ms, {})", 
                                         proxy.ip, proxy.port, response_time, country);
                            }
                        }
                    }
                }
            })
            .buffer_unordered(self.connection_limit)
            .collect::<Vec<()>>()
            .await;
        
        // Sort proxies by response time
        let mut result = Arc::try_unwrap(validated_proxies)
            .unwrap_or_else(|_| panic!("Failed to unwrap Arc"))
            .into_inner();
        
        result.sort_by(|a, b| a.response_time.partial_cmp(&b.response_time).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(result)
    }

    /// Validate a single proxy
    async fn validate_proxy(&self, proxy: &ProxyInfo) -> Result<bool, Box<dyn Error>> {
        let proxy_url = format!("{}://{}:{}", proxy.protocol, proxy.ip, proxy.port);
        
        // Try multiple validation rounds
        let mut successful_rounds = 0;
        
        for _ in 0..self.validation_rounds {
            // Select a random test URL
            let test_urls = [
                "http://httpbin.org/ip",
                "https://api.ipify.org/?format=json",
                "http://ip-api.com/json/",
                "https://www.cloudflare.com/cdn-cgi/trace"
            ];
            
            let test_url = test_urls[rand::thread_rng().gen_range(0..test_urls.len())];
            
            // Create a client with proxy
            let proxy_client = match Client::builder()
                .proxy(reqwest::Proxy::all(&proxy_url)?)
                .timeout(Duration::from_secs_f64(self.timeout_duration))
                .build() {
                Ok(client) => client,
                Err(_) => continue,
            };
            
            // Test the proxy
            match timeout(
                Duration::from_secs_f64(self.timeout_duration),
                proxy_client.get(test_url).send()
            ).await {
                Ok(Ok(response)) => {
                    if response.status().is_success() {
                        successful_rounds += 1;
                    }
                },
                _ => {}
            }
            
            // Add small delay between rounds
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        // Determine if proxy is valid based on successful rounds
        let is_valid = match self.validation_rounds {
            1 => successful_rounds == 1,
            2 => successful_rounds >= 1,
            _ => successful_rounds >= (self.validation_rounds / 2),
        };
        
        Ok(is_valid)
    }

    /// Measure proxy performance (response time, country, anonymity)
    async fn measure_proxy_performance(&self, proxy: &ProxyInfo) -> Result<(f64, String, String), Box<dyn Error>> {
        let proxy_url = format!("{}://{}:{}", proxy.protocol, proxy.ip, proxy.port);
        
        // Create a client with proxy
        let proxy_client = Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url)?)
            .timeout(Duration::from_secs_f64(self.timeout_duration))
            .build()?;
        
        // Measure response time
        let start = Instant::now();
        let response = proxy_client.get("http://ip-api.com/json/").send().await?;
        let response_time = start.elapsed().as_secs_f64() * 1000.0; // Convert to ms
        
        // Parse country information
        let mut country = "Unknown".to_string();
        let mut anonymity = "unknown".to_string();
        
        if response.status().is_success() {
            if let Ok(data) = response.json::<serde_json::Value>().await {
                if let Some(country_value) = data.get("country").and_then(|v| v.as_str()) {
                    country = country_value.to_string();
                }
                
                // Check anonymity if enabled
                if self.check_anonymity {
                    anonymity = self.determine_anonymity(&proxy_client).await?;
                }
            }
        }
        
        Ok((response_time, country, anonymity))
    }

    /// Determine the anonymity level of a proxy
    async fn determine_anonymity(&self, proxy_client: &Client) -> Result<String, Box<dyn Error>> {
        // Fetch anonymity test URL
        let response = match proxy_client.get("https://httpbin.org/headers").send().await {
            Ok(resp) => resp,
            Err(_) => return Ok("unknown".to_string()),
        };
        
        if !response.status().is_success() {
            return Ok("unknown".to_string());
        }
        
        // Parse headers
        let headers = match response.json::<serde_json::Value>().await {
            Ok(json) => json.get("headers").and_then(|h| h.as_object()).map(|h| h.clone()),
            Err(_) => None,
        };
        
        if let Some(headers) = headers {
            // Check for proxy-related headers
            let has_via = headers.contains_key("Via");
            let has_forwarded = headers.contains_key("X-Forwarded-For") || headers.contains_key("Forwarded");
            let has_proxy_headers = headers.iter().any(|(k, _)| k.to_lowercase().contains("proxy"));
            
            // Determine anonymity level
            if !has_via && !has_forwarded && !has_proxy_headers {
                return Ok("elite".to_string());
            } else if !has_forwarded {
                return Ok("anonymous".to_string());
            } else {
                return Ok("transparent".to_string());
            }
        }
        
        Ok("unknown".to_string())
    }

    /// Run speed tests on a list of proxies
    pub async fn run_speed_test(&self, proxies: &[ProxyInfo]) -> Result<Vec<(ProxyInfo, f64)>, Box<dyn Error>> {
        println!("Running speed test on {} proxies...", proxies.len());
        
        let mut results = Vec::new();
        let results_mutex = Arc::new(Mutex::new(&mut results));
        
        // Test proxies concurrently with limited concurrency
        stream::iter(proxies)
            .map(|proxy| {
                let results = Arc::clone(&results_mutex);
                
                async move {
                    // Measure response time
                    if let Ok(speed) = self.measure_proxy_speed(proxy).await {
                        let mut results_lock = results.lock().await;
                        results_lock.push((proxy.clone(), speed));
                    }
                }
            })
            .buffer_unordered(self.connection_limit)
            .collect::<Vec<()>>()
            .await;
        
        // Sort results by speed
        results.sort_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        
        Ok(results)
    }

    /// Measure the speed of a single proxy
    async fn measure_proxy_speed(&self, proxy: &ProxyInfo) -> Result<f64, Box<dyn Error>> {
        let proxy_url = format!("{}://{}:{}", proxy.protocol, proxy.ip, proxy.port);
        
        // Create a client with proxy
        let proxy_client = Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url)?)
            .timeout(Duration::from_secs_f64(self.timeout_duration))
            .build()?;
        
        // Use a small file to test download speed
        let test_url = "https://www.google.com/";
        
        // Measure download time
        let start = Instant::now();
        let response = proxy_client.get(test_url).send().await?;
        
        if response.status().is_success() {
            // Read the full response body
            let _body = response.bytes().await?;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0; // Convert to ms
            return Ok(elapsed);
        }
        
        Err("Proxy test failed".into())
    }
}
