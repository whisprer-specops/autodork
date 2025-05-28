// src/proxy_scanner.rs - Optimized implementation (full version)
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, BinaryHeap};
use std::cmp::Ordering;
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH}; // Added SystemTime, UNIX_EPOCH
use std::net::IpAddr;
use tokio::sync::Mutex;
use tokio::time::timeout;
use rand::Rng;
use reqwest::Client;
use url::Url;
use futures::stream::{self, StreamExt};
use std::cmp::Reverse;
use tokio::time::sleep;
use log::{info, warn, debug};
use ipnet::IpNet;
use scraper::{Html, Selector}; // Added for HTML parsing

/// Proxy information with enhanced metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyInfo {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub anonymity: String,
    pub response_time: f64,
    pub country: String,
    pub last_checked: u64,
    pub success_rate: f32,          // Success rate from 0.0 to 1.0
    pub stability_score: f32,       // Stability score from 0.0 to 1.0
    pub region: Option<String>,     // Geographic region for smarter batching
    pub asn: Option<String>,        // Autonomous System Number for provider grouping
}

impl PartialEq for ProxyInfo {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip && self.port == other.port
    }
}

impl Eq for ProxyInfo {}

/// For priority queue ordering - sort by response time
impl PartialOrd for ProxyInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.response_time.partial_cmp(&self.response_time)
    }
}

impl Ord for ProxyInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        other.response_time.partial_cmp(&self.response_time).unwrap_or(Ordering::Equal)
    }
}

/// Network information for grouping proxies
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkInfo {
    cidr: IpNet,
    country: String,
    asn: String,
    provider: String,
    reliability: f32,
}

/// The main proxy scanner with optimized algorithms
pub struct ProxyScanner {
    client: Client,
    proxy_sources: Vec<ProxySource>,
    connection_limit: usize,
    validation_rounds: usize,
    timeout_duration: f64,
    check_anonymity: bool,
    network_info: HashMap<String, NetworkInfo>,
    blacklisted_ranges: Vec<IpNet>,
    last_scan_results: Option<Vec<ProxyInfo>>,
    user_agents: Vec<String>,
    test_urls: Vec<String>,
}

/// Proxy source definition with metadata
#[derive(Debug, Clone)]
struct ProxySource {
    url: String,
    format: ProxyFormat,
    reliability: f32,
    parse_strategy: ParseStrategy,
}

/// Format of proxy list for smarter parsing
#[derive(Debug, Clone)]
enum ProxyFormat {
    PlainText,
    HTML,
    JSON,
    XML,
}

/// Strategy for parsing different proxy formats
#[derive(Debug, Clone)]
enum ParseStrategy {
    LineByLine,
    TableRows { selector: String },
    JSONPath { path: String },
    Custom { pattern: String },
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
        // Build a robust HTTP client
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(connection_limit)
            .tcp_keepalive(Some(Duration::from_secs(10)))
            .build()
            .unwrap_or_else(|_| Client::new());

        // Configure proxy sources with appropriate parsing strategies
        let proxy_sources = vec![
            ProxySource {
                url: "https://www.freeproxylists.net/".to_string(),
                format: ProxyFormat::HTML,
                reliability: 0.7,
                parse_strategy: ParseStrategy::TableRows {
                    selector: "table.DataGrid tr".to_string()
                },
            },
            ProxySource {
                url: "https://free-proxy-list.net/".to_string(),
                format: ProxyFormat::HTML,
                reliability: 0.8,
                parse_strategy: ParseStrategy::TableRows {
                    selector: "#proxylisttable tbody tr".to_string()
                },
            },
            ProxySource {
                url: "https://www.sslproxies.org/".to_string(),
                format: ProxyFormat::HTML,
                reliability: 0.75,
                parse_strategy: ParseStrategy::TableRows {
                    selector: "#proxylisttable tbody tr".to_string()
                },
            },
            ProxySource {
                url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt".to_string(),
                format: ProxyFormat::PlainText,
                reliability: 0.9,
                parse_strategy: ParseStrategy::LineByLine,
            },
            ProxySource {
                url: "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt".to_string(),
                format: ProxyFormat::PlainText,
                reliability: 0.85,
                parse_strategy: ParseStrategy::LineByLine,
            },
            ProxySource {
                url: "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt".to_string(),
                format: ProxyFormat::PlainText,
                reliability: 0.8,
                parse_strategy: ParseStrategy::LineByLine,
            },
            ProxySource {
                url: "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt".to_string(),
                format: ProxyFormat::PlainText,
                reliability: 0.85,
                parse_strategy: ParseStrategy::LineByLine,
            },
        ];

        // Common user-agent strings for rotation
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36".to_string(),
        ];

        // Test URLs that are reliable for proxy validation
        let test_urls = vec![
            "http://httpbin.org/ip".to_string(),
            "https://api.ipify.org/?format=json".to_string(),
            "http://ip-api.com/json/".to_string(),
            "https://www.cloudflare.com/cdn-cgi/trace".to_string(),
            "https://ifconfig.me/ip".to_string(),
        ];

        // Known problematic IP ranges to avoid
        let blacklisted_ranges = vec![
            // Sample ranges - you'd want to populate this with actual problematic ranges
            "198.51.100.0/24".parse().unwrap_or_else(|_| "0.0.0.0/0".parse().unwrap()),
            "203.0.113.0/24".parse().unwrap_or_else(|_| "0.0.0.0/0".parse().unwrap()),
        ];

        ProxyScanner {
            client,
            proxy_sources,
            connection_limit,
            validation_rounds,
            timeout_duration: timeout_seconds,
            check_anonymity,
            network_info: HashMap::new(),
            blacklisted_ranges,
            last_scan_results: None,
            user_agents,
            test_urls,
        }
    }

    /// Scan for working proxies with optimized parallel processing
    pub async fn scan_proxies(&mut self) -> Result<Vec<ProxyInfo>, Box<dyn Error>> {
        info!("Starting optimized proxy scan...");

        // Fetch proxies from sources - parallel processing
        let fetched_proxies = self.parallel_fetch_proxies().await?;
        info!("Fetched {} potential proxies from sources", fetched_proxies.len());

        // Filter out blacklisted ranges
        let filtered_proxies = self.filter_blacklisted(fetched_proxies);
        info!("Filtered to {} proxies after removing blacklisted ranges", filtered_proxies.len());

        // Group proxies by network for smarter validation
        let proxy_groups = self.group_by_network(&filtered_proxies);
        info!("Grouped proxies into {} networks for efficient validation", proxy_groups.len());

        // Validate proxies with adaptive parallelism
        let validated_proxies = self.adaptive_validate_proxies(proxy_groups).await?;
        info!("Found {} working proxies after validation", validated_proxies.len());

        // Store the results for future use
        self.last_scan_results = Some(validated_proxies.clone());

        Ok(validated_proxies)
    }

    /// Fetch proxies from all sources in parallel
    async fn parallel_fetch_proxies(&self) -> Result<Vec<ProxyInfo>, Box<dyn Error>> {
        info!("Fetching proxies from {} sources in parallel", self.proxy_sources.len());

        // Prepare thread-safe collection for results
        let all_proxies = Arc::new(Mutex::new(Vec::new()));

        // Process sources in parallel
        let mut tasks = Vec::new();
        for source in &self.proxy_sources {
            let all_proxies = Arc::clone(&all_proxies);
            let client = self.client.clone();
            let source = source.clone();
            let user_agents = self.user_agents.clone();

            // Spawn a task for each source
            tasks.push(tokio::spawn(async move {
                // Select a random user agent
                let user_agent = user_agents[rand::thread_rng().gen_range(0..user_agents.len())].clone();

                // Attempt to fetch from the source
                match client.get(&source.url)
                    .header("User-Agent", user_agent)
                    .timeout(Duration::from_secs(15))
                    .send()
                    .await {
                    Ok(response) => {
                        if response.status().is_success() {
                            let content = response.text().await.unwrap_or_default();

                            // Parse based on format
                            let proxies = match source.format {
                                ProxyFormat::PlainText => {
                                    parse_plaintext_proxies(&content, source.reliability)
                                },
                                ProxyFormat::HTML => {
                                    parse_html_proxies(&content, &source.parse_strategy, source.reliability)
                                },
                                ProxyFormat::JSON => {
                                    parse_json_proxies(&content, &source.parse_strategy, source.reliability)
                                },
                                ProxyFormat::XML => {
                                    parse_xml_proxies(&content, &source.parse_strategy, source.reliability)
                                },
                            };

                            // Add to collection
                            if !proxies.is_empty() {
                                info!("Found {} proxies from {}", proxies.len(), source.url);
                                let mut all_proxies = all_proxies.lock().await;
                                all_proxies.extend(proxies);
                            }
                        } else {
                            warn!("Failed to fetch from {}: HTTP {}", source.url, response.status());
                        }
                    },
                    Err(e) => {
                        warn!("Error fetching from {}: {}", source.url, e);
                    }
                }

                // Adaptive delay based on source reliability
                let delay = if source.reliability > 0.8 {
                    Duration::from_millis(200)
                } else {
                    Duration::from_secs(1)
                };
                sleep(delay).await;
            }));
        }

        // Wait for all tasks to complete
        for task in tasks {
            let _ = task.await;
        }

        // Deduplicate proxies
        let mut result = Arc::try_unwrap(all_proxies)
            .unwrap_or_else(|_| panic!("Failed to unwrap Arc"))
            .into_inner();

        // Deduplicate using HashSet
        let mut unique_keys = HashSet::new();
        result.retain(|proxy| {
            let key = format!("{}:{}", proxy.ip, proxy.port);
            unique_keys.insert(key)
        });

        Ok(result)
    }

    /// Filter out proxies in blacklisted ranges
    fn filter_blacklisted(&self, proxies: Vec<ProxyInfo>) -> Vec<ProxyInfo> {
        proxies.into_iter().filter(|proxy| {
            // Parse IP address
            if let Ok(ip) = proxy.ip.parse::<IpAddr>() {
                // Check if IP is in any blacklisted range
                !self.blacklisted_ranges.iter().any(|range| range.contains(&ip))
            } else {
                // If we can't parse the IP, let it through for now
                true
            }
        }).collect()
    }

    /// Group proxies by network for smarter validation
    fn group_by_network(&self, proxies: &[ProxyInfo]) -> HashMap<String, Vec<ProxyInfo>> {
        let mut groups = HashMap::new();

        for proxy in proxies {
            // Try to determine network group
            let group = if let Some(region) = &proxy.region {
                region.clone()
            } else if let Some(asn) = &proxy.asn {
                asn.clone()
            } else {
                // Group by IP prefix as fallback
                let parts: Vec<&str> = proxy.ip.split('.').collect();
                if parts.len() >= 2 {
                    format!("{}.{}", parts[0], parts[1])
                } else {
                    "unknown".to_string()
                }
            };

            groups.entry(group).or_insert_with(Vec::new).push(proxy.clone());
        }

        groups
    }

    /// Validate proxies with adaptive parallelism based on network groups
    async fn adaptive_validate_proxies(
        &self,
        proxy_groups: HashMap<String, Vec<ProxyInfo>>
    ) -> Result<Vec<ProxyInfo>, Box<dyn Error>> {
        info!("Validating proxies with adaptive concurrency...");

        // Thread-safe collection for validated proxies
        let validated_proxies = Arc::new(Mutex::new(Vec::new()));

        // Create priority queue for scheduling network groups
        let mut priority_queue: Vec<(String, Vec<ProxyInfo>)> = proxy_groups.into_iter().collect();

        // Sort network groups by reliability (if known) or size (smaller first for quick wins)
        priority_queue.sort_by(|(group_a, proxies_a), (group_b, proxies_b)| {
            // Get network info if available
            let reliability_a = self.network_info.get(group_a).map_or(0.5, |info| info.reliability);
            let reliability_b = self.network_info.get(group_b).map_or(0.5, |info| info.reliability);

            // Sort by reliability (descending), then by size (ascending)
            reliability_b.partial_cmp(&reliability_a)
                .unwrap_or(Ordering::Equal)
                .then_with(|| proxies_a.len().cmp(&proxies_b.len()))
        });

        // Process network groups in batches for maximum efficiency
        for (group_idx, (group_name, group_proxies)) in priority_queue.into_iter().enumerate() {
            // Determine optimal concurrency for this group
            let optimal_concurrency = self.determine_optimal_concurrency(&group_name, group_proxies.len());

            // Determine optimal timeouts for this group
            let (initial_timeout, full_timeout) = self.determine_optimal_timeouts(&group_name);

            info!("Processing network group {} ({} proxies) with concurrency {}",
                 group_name, group_proxies.len(), optimal_concurrency);

            // For large groups, use a two-phase approach for efficiency
            let (fast_check, detailed_check) = if group_proxies.len() > 100 {
                (true, false)
            } else {
                (false, true)
            };

            // Process proxies in this group concurrently
            let valid_proxies = self.validate_proxy_group(
                group_proxies,
                optimal_concurrency,
                initial_timeout,
                full_timeout,
                fast_check,
                detailed_check
            ).await;

            // Add validated proxies to the collection
            if !valid_proxies.is_empty() {
                info!("Found {} working proxies in group {}", valid_proxies.len(), group_name);
                let mut proxies = validated_proxies.lock().await;
                proxies.extend(valid_proxies);
            }

            // Adjust delay between groups based on position to avoid rate limiting
            let delay_ms = if group_idx < 3 {
                // Process first few groups quickly
                100
            } else {
                // Add increasing delays for later groups
                200 + (group_idx * 50).min(1000)
            };

            sleep(Duration::from_millis(delay_ms as u64)).await;
        }

        // Extract and sort the results
        let mut result = Arc::try_unwrap(validated_proxies)
            .unwrap_or_else(|_| panic!("Failed to unwrap Arc"))
            .into_inner();

        // Sort by response time (ascending)
        result.sort_by(|a, b| a.response_time.partial_cmp(&b.response_time).unwrap_or(Ordering::Equal));

        Ok(result)
    }

    /// Validate a group of proxies with optimal concurrency
    async fn validate_proxy_group(
        &self,
        proxies: Vec<ProxyInfo>,
        concurrency: usize,
        initial_timeout: Duration,
        full_timeout: Duration,
        fast_check: bool,
        detailed_check: bool
    ) -> Vec<ProxyInfo> {
        // Thread-safe collection for validated proxies
        let valid_proxies = Arc::new(Mutex::new(Vec::new()));

        // Process proxies concurrently
        stream::iter(proxies)
            .map(|proxy| {
                let valid_proxies = Arc::clone(&valid_proxies);

                async move {
                    // Phase 1: Fast initial check
                    let initial_valid = if fast_check {
                        match self.fast_validate_proxy(&proxy, initial_timeout).await {
                            Ok(valid) => valid,
                            Err(_) => false,
                        }
                    } else {
                        true // Skip fast check
                    };

                    if initial_valid {
                        // Phase 2: Full validation
                        if detailed_check {
                            if let Ok(is_valid) = self.validate_proxy(&proxy, full_timeout).await {
                                if is_valid {
                                    // Phase 3: Get detailed info for working proxies
                                    if let Ok((response_time, country, anonymity)) =
                                        self.measure_proxy_performance(&proxy, full_timeout).await
                                    {
                                        let mut validated_proxy = proxy.clone();
                                        validated_proxy.response_time = response_time;
                                        validated_proxy.country = country;
                                        validated_proxy.anonymity = anonymity;
                                        validated_proxy.last_checked = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(); // Corrected timestamp
                                        validated_proxy.success_rate = 1.0; // Initial success rate
                                        validated_proxy.stability_score = 1.0; // Initial stability

                                        let mut valid_proxies = valid_proxies.lock().await;
                                        valid_proxies.push(validated_proxy);
                                    } else {
                                         debug!("Failed to get detailed info for proxy {}:{}", proxy.ip, proxy.port);
                                    }
                                } else {
                                    debug!("Proxy {}:{} failed full validation", proxy.ip, proxy.port);
                                }
                            } else {
                                debug!("Error during full validation for proxy {}:{}", proxy.ip, proxy.port);
                            }
                        } else {
                            // If only fast check, add with minimal info
                            let mut validated_proxy = proxy.clone();
                            validated_proxy.last_checked = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(); // Corrected timestamp
                            validated_proxy.success_rate = 0.5; // Lower initial success rate
                            validated_proxy.stability_score = 0.5; // Lower initial stability
                            let mut valid_proxies = valid_proxies.lock().await;
                            valid_proxies.push(validated_proxy);
                            debug!("Proxy {}:{} passed fast check, skipping detailed validation", proxy.ip, proxy.port);
                        }
                    } else {
                        debug!("Proxy {}:{} failed fast validation", proxy.ip, proxy.port);
                    }
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<()>>()
            .await;

        // Extract and return validated proxies
        let mut valid_proxies_locked = valid_proxies.lock().await;
        std::mem::take(&mut *valid_proxies_locked) // Efficiently empty and return the vector
    }

    /// Validate a single proxy with a shorter timeout
    async fn fast_validate_proxy(&self, proxy: &ProxyInfo, timeout_duration: Duration) -> Result<bool, Box<dyn Error>> {
        let proxy_url = format!("{}://{}:{}", proxy.protocol, proxy.ip, proxy.port);

        // Use a single fast test URL first (adaptive based on region)
        let test_url = self.select_optimal_test_url(&proxy.ip);

        // Create a client with optimized settings
        let proxy_client = match Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url)?)
            .timeout(timeout_duration)  // Use provided timeout
            .tcp_nodelay(true)  // Disable Nagle's algorithm for faster connection
            .build() {
            Ok(client) => client,
            Err(e) => {
                debug!("Failed to build proxy client for {}:{}: {}", proxy.ip, proxy.port, e);
                return Ok(false);
            },
        };

        // Fast initial check
        match timeout(
            timeout_duration,
            proxy_client.get(test_url).send()
        ).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    debug!("Proxy {}:{} passed fast validation", proxy.ip, proxy.port);
                    return Ok(true);
                } else {
                    debug!("Proxy {}:{} failed fast validation with status: {}", proxy.ip, proxy.port, response.status());
                }
            },
            Ok(Err(e)) => {
                debug!("Error sending fast validation request for {}:{}: {}", proxy.ip, proxy.port, e);
            },
            Err(e) => {
                debug!("Fast validation request timed out for {}:{}: {}", proxy.ip, proxy.port, e);
            }
        }

        Ok(false)
    }

    /// Validate a single proxy with multiple rounds and full timeout
    async fn validate_proxy(&self, proxy: &ProxyInfo, timeout_duration: Duration) -> Result<bool, Box<dyn Error>> {
        let proxy_url = format!("{}://{}:{}", proxy.protocol, proxy.ip, proxy.port);

        // Try multiple validation rounds
        let mut successful_rounds = 0;
        let total_rounds = self.validation_rounds;

        for round in 0..total_rounds {
            // Select a random test URL
            let test_url = self.get_next_test_url();

            // Create a client with proxy
            let proxy_client = match Client::builder()
                .proxy(reqwest::Proxy::all(&proxy_url)?)
                .timeout(timeout_duration) // Use provided timeout
                .build() {
                Ok(client) => client,
                Err(e) => {
                    debug!("Failed to build proxy client for {}:{} in round {}: {}", proxy.ip, proxy.port, round, e);
                    continue;
                },
            };

            // Test the proxy
            match timeout(
                timeout_duration,
                proxy_client.get(test_url).send()
            ).await {
                Ok(Ok(response)) => {
                    if response.status().is_success() {
                        successful_rounds += 1;
                        debug!("Proxy {}:{} passed validation round {}", proxy.ip, proxy.port, round);
                    } else {
                        debug!("Proxy {}:{} failed validation round {} with status: {}", proxy.ip, proxy.port, round, response.status());
                    }
                },
                Ok(Err(e)) => {
                    debug!("Error sending validation request for {}:{} in round {}: {}", proxy.ip, proxy.port, round, e);
                },
                Err(e) => {
                    debug!("Validation request timed out for {}:{} in round {}: {}", proxy.ip, proxy.port, round, e);
                }
            }

            // Add small delay between rounds to avoid overwhelming the proxy or test sites
            if round < total_rounds - 1 {
                 sleep(Duration::from_millis(200)).await;
            }
        }

        // Determine if proxy is valid based on successful rounds
        let required_successful_rounds = match total_rounds {
            0 => 0, // No rounds, consider valid if reached here (shouldn't happen with current logic)
            1 => 1, // Need 1 successful round
            2 => 1, // Need at least 1 successful round
            _ => (total_rounds as f32 * 0.5).ceil() as usize, // Need at least 50% successful rounds
        };

        Ok(successful_rounds >= required_successful_rounds && successful_rounds > 0) // Must have at least one success
    }


    /// Measure proxy performance (response time, country, anonymity)
    async fn measure_proxy_performance(&self, proxy: &ProxyInfo, timeout_duration: Duration) -> Result<(f64, String, String), Box<dyn Error>> {
        let proxy_url = format!("{}://{}:{}", proxy.protocol, proxy.ip, proxy.port);

        // Create a client with proxy
        let proxy_client = Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url)?)
            .timeout(timeout_duration)
            .build()?;

        // Use a reliable IP info service to measure response time and get country
        let test_url = "http://ip-api.com/json/";

        let start = Instant::now();
        let response = match timeout(timeout_duration, proxy_client.get(test_url).send()).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(format!("Error fetching IP info for {}:{}: {}", proxy.ip, proxy.port, e).into()),
            Err(e) => return Err(format!("Timeout fetching IP info for {}:{}: {}", proxy.ip, proxy.port, e).into()),
        };

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
                    anonymity = self.determine_anonymity(&proxy_client, timeout_duration).await?;
                }
            } else {
                debug!("Failed to parse IP info JSON for {}:{}", proxy.ip, proxy.port);
            }
        } else {
             debug!("Failed to fetch IP info for {}:{} with status: {}", proxy.ip, proxy.port, response.status());
             return Err(format!("Failed to fetch IP info with status: {}", response.status()).into());
        }


        Ok((response_time, country, anonymity))
    }

    /// Determine the anonymity level of a proxy
    async fn determine_anonymity(&self, proxy_client: &Client, timeout_duration: Duration) -> Result<String, Box<dyn Error>> {
        // Fetch anonymity test URL
        let response = match timeout(timeout_duration, proxy_client.get("https://httpbin.org/headers").send()).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                debug!("Error fetching headers for anonymity check: {}", e);
                return Ok("unknown".to_string());
            },
            Err(e) => {
                 debug!("Timeout fetching headers for anonymity check: {}", e);
                 return Ok("unknown".to_string());
            }
        };

        if !response.status().is_success() {
            debug!("Anonymity check failed with status: {}", response.status());
            return Ok("unknown".to_string());
        }

        // Parse headers
        let headers = match response.json::<serde_json::Value>().await {
            Ok(json) => json.get("headers").and_then(|h| h.as_object()).map(|h| h.clone()),
            Err(e) => {
                debug!("Failed to parse headers JSON for anonymity check: {}", e);
                None
            },
        };

        if let Some(headers) = headers {
            // Check for proxy-related headers (case-insensitive)
            let has_via = headers.keys().any(|k| k.to_lowercase() == "via");
            let has_forwarded = headers.keys().any(|k| k.to_lowercase() == "x-forwarded-for" || k.to_lowercase() == "forwarded");
            let has_proxy_headers = headers.keys().any(|k| k.to_lowercase().contains("proxy"));

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
        info!("Running speed test on {} proxies...", proxies.len());

        let mut results = Vec::new();
        let results_mutex = Arc::new(Mutex::new(&mut results));

        // Test proxies concurrently with limited concurrency
        stream::iter(proxies.iter().cloned()) // Clone to move into async blocks
            .map(|proxy| {
                let results = Arc::clone(&results_mutex);
                let timeout_duration = Duration::from_secs_f64(self.timeout_duration);

                async move {
                    // Measure response time
                    if let Ok(speed) = self.measure_proxy_speed(&proxy, timeout_duration).await {
                        let mut results_lock = results.lock().await;
                        results_lock.push((proxy.clone(), speed));
                    }
                }
            })
            .buffer_unordered(self.connection_limit.min(100)) // Limit concurrency for speed tests
            .collect::<Vec<()>>()
            .await;

        // Sort results by speed (ascending response time)
        results.sort_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        Ok(results)
    }

    /// Measure the speed of a single proxy
    async fn measure_proxy_speed(&self, proxy: &ProxyInfo, timeout_duration: Duration) -> Result<f64, Box<dyn Error>> {
        let proxy_url = format!("{}://{}:{}", proxy.protocol, proxy.ip, proxy.port);

        // Create a client with proxy
        let proxy_client = Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url)?)
            .timeout(timeout_duration)
            .build()?;

        // Use a relatively small but consistent resource to test download speed
        // Using a known small test file or API endpoint is better than a full webpage
        let test_url = "https://speed.cloudflare.com/__down?bytes=100000"; // Example test URL for 100KB

        // Measure download time
        let start = Instant::now();
        let response = match timeout(timeout_duration, proxy_client.get(test_url).send()).await {
             Ok(Ok(resp)) => resp,
             Ok(Err(e)) => return Err(format!("Error fetching speed test URL for {}:{}: {}", proxy.ip, proxy.port, e).into()),
             Err(e) => return Err(format!("Timeout fetching speed test URL for {}:{}: {}", proxy.ip, proxy.port, e).into()),
        };

        if response.status().is_success() {
            // Read the full response body to measure the time to download
            let _body = response.bytes().await?;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0; // Convert to ms
            debug!("Speed test for {}:{} took {:.2}ms", proxy.ip, proxy.port, elapsed);
            return Ok(elapsed);
        } else {
            let status = response.status();
            debug!("Speed test for {}:{} failed with status: {}", proxy.ip, proxy.port, status);
            return Err(format!("Proxy test failed with status: {}", status).into());
        }
    }

    // Helper functions for parsing proxy lists (basic implementations)

    fn parse_plaintext_proxies(content: &str, reliability: f32) -> Vec<ProxyInfo> {
        let mut proxies = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                if let Ok(port) = parts[1].parse::<u16>() {
                    proxies.push(ProxyInfo {
                        ip: parts[0].to_string(),
                        port,
                        protocol: "http".to_string(), // Assume http for plaintext
                        anonymity: "unknown".to_string(),
                        response_time: 0.0,
                        country: "Unknown".to_string(),
                        last_checked: 0,
                        success_rate: reliability, // Use source reliability as initial success rate
                        stability_score: reliability, // Use source reliability as initial stability
                        region: None,
                        asn: None,
                    });
                }
            }
        }
        proxies
    }

    fn parse_html_proxies(content: &str, strategy: &ParseStrategy, reliability: f32) -> Vec<ProxyInfo> {
        let mut proxies = Vec::new();
        let document = Html::parse_document(content);

        if let ParseStrategy::TableRows { selector: selector_str } = strategy {
            if let Ok(selector) = Selector::parse(selector_str) {
                 for row in document.select(&selector) {
                    // Basic attempt to find IP and Port in table cells
                    let cells: Vec<_> = row.select(&Selector::parse("td").unwrap()).collect(); // Safe to unwrap
                    if cells.len() >= 2 {
                        let ip = cells[0].text().collect::<String>().trim().to_string();
                        if let Ok(port) = cells[1].text().collect::<String>().trim().parse::<u16>() {
                             if !ip.is_empty() && port > 0 {
                                 // Attempt to extract protocol, anonymity, country from other columns if available
                                 let protocol = cells.get(3).map(|c| c.text().collect::<String>().trim().to_string()).unwrap_or_else(|| "http".to_string());
                                 let anonymity = cells.get(4).map(|c| c.text().collect::<String>().trim().to_string()).unwrap_or_else(|| "unknown".to_string());
                                 let country = cells.get(2).map(|c| c.text().collect::<String>().trim().to_string()).unwrap_or_else(|| "Unknown".to_string());


                                proxies.push(ProxyInfo {
                                    ip,
                                    port,
                                    protocol: protocol.to_lowercase(),
                                    anonymity: anonymity.to_lowercase(),
                                    response_time: 0.0,
                                    country,
                                    last_checked: 0,
                                    success_rate: reliability,
                                    stability_score: reliability,
                                    region: None, // Need more sophisticated parsing for region/asn
                                    asn: None,
                                });
                            }
                        }
                    }
                 }
            } else {
                warn!("Failed to parse HTML selector: {}", selector_str);
            }
        } else {
             warn!("Unsupported HTML parse strategy");
        }

        proxies
    }

    fn parse_json_proxies(_content: &str, _strategy: &ParseStrategy, _reliability: f32) -> Vec<ProxyInfo> {
        // TODO: Implement JSON parsing based on strategy
        warn!("JSON proxy parsing not implemented");
        Vec::new()
    }

    fn parse_xml_proxies(_content: &str, _strategy: &ParseStrategy, _reliability: f32) -> Vec<ProxyInfo> {
        // TODO: Implement XML parsing based on strategy
        warn!("XML proxy parsing not implemented");
        Vec::new()
    }

    // Helper functions for adaptive validation (basic implementations)

    fn determine_optimal_concurrency(&self, _group_name: &str, group_size: usize) -> usize {
        // Simple heuristic: use higher concurrency for larger groups, capped by connection limit
        (group_size / 10).max(1).min(self.connection_limit / 2).max(1) // Ensure at least 1
    }

    fn determine_optimal_timeouts(&self, _group_name: &str) -> (Duration, Duration) {
        // Simple: use half timeout for fast check, full timeout for detailed check
        let initial = Duration::from_secs_f64(self.timeout_duration * 0.5);
        let full = Duration::from_secs_f64(self.timeout_duration);
        (initial, full)
    }

    fn select_optimal_test_url(&self, _ip: &str) -> &str {
        // Basic: just pick a random test URL. More advanced would use IP geo-location.
        let test_urls_slice: &[String] = &self.test_urls;
        let random_index = rand::thread_rng().gen_range(0..test_urls_slice.len());
        &test_urls_slice[random_index]
    }

    fn get_next_test_url(&self) -> &str {
         // Basic: just pick a random test URL. More advanced would cycle or adapt.
        let test_urls_slice: &[String] = &self.test_urls;
        let random_index = rand::thread_rng().gen_range(0..test_urls_slice.len());
        &test_urls_slice[random_index]
    }
}