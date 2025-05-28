// src/main.rs
use reqwest::Client;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Write, Read, BufReader, BufRead};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::sync::mpsc;
use tokio::time;
use url::Url;
use num_complex::Complex;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
use flate2::Compression;
use rand::Rng;
use scraper::{Html, Selector};
use futures::stream::{self, StreamExt};
use nalgebra::DMatrix;
use log::{info, warn, error}; // Added logging

mod tokenizer;
mod entropy;
mod prime_hilbert;
mod engine; // Now using the optimized engine
mod crawler;
mod quantum_types;
mod dork_engine;
mod bug_bounty;
mod vulnerability_matcher;
mod proxy_scanner; // Now using the completed proxy scanner

use engine::ResonantEngine;
use crawler::{Crawler, CrawledDocument};
use quantum_types::{MatrixComplex, trace};
use dork_engine::{DorkEngine, DorkResult};
use bug_bounty::BugBountyManager;
use vulnerability_matcher::{VulnerabilityMatcher, VulnerabilityMatch}; // Added VulnerabilityMatch
use proxy_scanner::ProxyScanner;
use lib::{Finding, BountyMatch}; // Import Finding and BountyMatch from lib

// Define the complete scan report structure that combines results from various modules
#[derive(Debug, Serialize, Deserialize)]
struct ScanReport {
    target: String,
    timestamp: u64,
    findings: Vec<Finding>,
    subdomains: Vec<String>,
    vulnerabilities: Vec<ReportVulnerability>, // Use ReportVulnerability for report structure
    endpoints: Vec<ApiEndpoint>,
    proxies: Vec<ProxyInfo>,
    bounty_matches: Vec<BountyMatch>,
    visualizations: Vec<Visualization>,
}

// Adjusted Vulnerability struct for reporting (based on VulnerabilityMatch)
#[derive(Debug, Serialize, Deserialize)]
struct ReportVulnerability {
    id: String, // Added ID for uniqueness
    name: String,
    description: String,
    severity: String,
    url: String,
    pattern_matched: String,
    discovery_timestamp: u664,
    context: String, // Added context
    cwe_id: Option<String>, // Added CWE ID
    remediation: Option<String>, // Added remediation
}


#[derive(Debug, Serialize, Deserialize)]
struct ApiEndpoint {
    url: String,
    method: String,
    parameters: Vec<String>,
    response_code: u16,
    discovery_timestamp: u64,
}

// Re-using ProxyInfo from proxy_scanner
use proxy_scanner::ProxyInfo;

// Re-using BountyMatch from lib

#[derive(Debug, Serialize, Deserialize)]
struct Visualization {
    title: String,
    description: String,
    file_path: String,
    visualization_type: String, // "graph", "timeline", "heatmap"
}

/// Apply a quantum jump event to a document state matrix
pub fn quantum_jump_event(doc_state: &mut MatrixComplex<f64>, jump_operator: MatrixComplex<f64>) {
    // Apply the jump operator to both sides of the density matrix
    let result = &jump_operator * &(*doc_state) * &jump_operator.adjoint();
    *doc_state = result;

    // Normalize the density matrix by its trace
    let tr = trace(doc_state).re;
    if tr > 0.0 {
        // Apply scaling manually
        for i in 0..doc_state.nrows() {
            for j in 0..doc_state.ncols() {
                doc_state[(i, j)] = doc_state[(i, j)] / Complex::new(tr, 0.0); // Corrected scaling
            }
        }
    }
}

/// Helper function to load seed URLs from a file
fn load_urls_from_file(file_path: &str) -> io::Result<Vec<String>> {
    let content = fs::read_to_string(file_path)?;
    let urls = content.lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && (line.starts_with("http") || !line.contains("://")))
        .collect();

    Ok(urls)
}

/// Helper function to ensure data directories exist
fn ensure_data_dirs() -> io::Result<()> {
    let data_dir = Path::new("data");
    if !data_dir.exists() {
        fs::create_dir_all(data_dir)?;
        info!("Created data directory");
    }

    let checkpoints_dir = Path::new("data/checkpoints");
    if !checkpoints_dir.exists() {
        fs::create_dir_all(checkpoints_dir)?;
        info!("Created checkpoints directory");
    }

    let findings_dir = Path::new("data/findings");
    if !findings_dir.exists() {
        fs::create_dir_all(findings_dir)?;
        info!("Created findings directory");
    }

    let proxies_dir = Path::new("data/proxies");
    if !proxies_dir.exists() {
        fs::create_dir_all(proxies_dir)?;
        info!("Created proxies directory");
    }

    let visualizations_dir = Path::new("data/visualizations");
    if !visualizations_dir.exists() {
        fs::create_dir_all(visualizations_dir)?;
        info!("Created visualizations directory");
    }

    Ok(())
}

/// Function to scan for open redirects in a list of URLs
async fn scan_for_open_redirects(urls: &[String], payload: &str) -> Vec<String> {
    let client = Client::new();
    let mut vulnerable_urls = Vec::new();
    let mut tested_urls = HashSet::new();

    println!("Scanning {} URLs for open redirect vulnerabilities...", urls.len());

    for url in urls {
        let modified_url = replace_http_parameters(url, payload);

        if tested_urls.contains(&modified_url) {
            continue;
        }

        if !is_valid_url(&modified_url) {
            println!("Skipping unsupported URL scheme for: {}", modified_url);
            continue;
        }

        match client.get(&modified_url).send().await {
            Ok(response) => {
                let status = response.status();

                if status.is_redirection() {
                    if let Some(location) = response.headers().get("Location") {
                        let location_str = location.to_str().unwrap_or("");
                        if location_str == payload {
                            println!("Open Redirect Found: {}", modified_url);
                            vulnerable_urls.push(modified_url.clone());
                        } else {
                            println!("Redirect to different location for {}: {}", modified_url, location_str);
                        }
                    } else {
                        println!("Redirection status but no Location header for: {}", modified_url);
                    }
                } else {
                    let body = response.text().await.unwrap_or_else(|_| String::from(""));
                    if body.contains("The fake ones are the ones that scream the most") {
                        println!("Open Redirect Found in response body: {}", modified_url);
                        vulnerable_urls.push(modified_url.clone());
                    } else {
                        println!("No redirect for {}: Status {}", modified_url, status);
                    }
                }
            }
            Err(e) => eprintln!("Failed to send request to {}: {}", modified_url, e),
        }

        tested_urls.insert(modified_url);
    }

    vulnerable_urls
}

/// Helper function to replace HTTP parameters in a URL
fn replace_http_parameters(url: &str, payload: &str) -> String {
    if let Ok(mut parsed_url) = Url::parse(url) {
        let modified_query: Vec<(String, String)> = parsed_url
            .query_pairs()
            .map(|(key, value)| {
                if value.starts_with("http") {
                    (key.to_string(), payload.to_string())
                } else {
                    (key.to_string(), value.to_string())
                }
            })
            .collect();
        parsed_url.query_pairs_mut().clear().extend_pairs(modified_query);
        return parsed_url.to_string();
    }
    url.to_string()
}

/// Helper function to check if a URL is valid
fn is_valid_url(url: &str) -> bool {
    match Url::parse(url) {
        Ok(parsed_url) => parsed_url.scheme() == "http" || parsed_url.scheme() == "https",
        Err(_) => false,
    }
}

/// Run the complete OSINT and vulnerability scan
async fn run_complete_scan(target: &str) -> Result<ScanReport, Box<dyn Error>> {
    info!("Starting complete scan for target: {}", target);

    // 1. Domain reconnaissance
    println!("\n[1/9] Performing domain reconnaissance...");
    let dork_engine = DorkEngine::new().await?;
    let subdomains = dork_engine.discover_subdomains(target).await?;
    info!("Found {} subdomains", subdomains.len());
    println!("Found {} subdomains", subdomains.len());


    // 2. Execute all dorks against target
    println!("\n[2/9] Executing dorks against target and subdomains...");
    let dork_results = dork_engine.execute_all_dorks(target, &subdomains).await?;
    info!("Got {} results from dork queries", dork_results.len());
    println!("Got {} results from dork queries", dork_results.len());

    // 3. Query specialized services
    println!("\n[3/9] Querying specialized security services...");
    let shodan_results = dork_engine.query_shodan(target, &subdomains).await?;
    let urlscan_results = dork_engine.query_urlscan(target, &subdomains).await?;
    let dns_information = dork_engine.gather_dns_info(target, &subdomains).await?;
    info!("Retrieved data from specialized services");
    println!("Retrieved data from specialized services");


    // 4. Process JavaScript files
    println!("\n[4/9] Extracting and analyzing JavaScript files...");
    let js_files = dork_engine.extract_javascript_files(&dork_results).await?;
    let js_analysis = dork_engine.analyze_javascript_files(&js_files).await?;
    info!("Analyzed {} JavaScript files", js_files.len());
    println!("Analyzed {} JavaScript files", js_files.len());


    // 5. Check cloud storage
    println!("\n[5/9] Checking for cloud storage resources...");
    let cloud_storage = dork_engine.check_cloud_storage(target).await?;
    info!("Found {} cloud storage resources", cloud_storage.len());
    println!("Found {} cloud storage resources", cloud_storage.len());


    // 6. Analyze all findings
    println!("\n[6/9] Analyzing findings...");
    let vulnerability_matcher = VulnerabilityMatcher::new(); // Create a new instance
    let analyzed_results = vulnerability_matcher.analyze_findings(
        target,
        &dork_results,
        &shodan_results,
        &urlscan_results,
        &dns_information,
        &js_analysis,
        &cloud_storage,
    ).await?;
    info!("Analysis complete with {} findings", analyzed_results.len());
    println!("Analysis complete with {} findings", analyzed_results.len());


    // 7. Scan for active proxies
    println!("\n[7/9] Scanning for usable proxies...");
    let mut proxy_scanner = ProxyScanner::new(); // Create a new mutable instance
    let proxies = proxy_scanner.scan_proxies().await?;
    info!("Found {} working proxies", proxies.len());
    println!("Found {} working proxies", proxies.len());


    // 8. Generate visualizations
    println!("\n[8/9] Generating visualizations...");
    let visualizations = generate_visualizations(&analyzed_results).await?;
    info!("Generated {} visualizations", visualizations.len());
    println!("Generated {} visualizations", visualizations.len());


    // 9. Match to bug bounty programs
    println!("\n[9/9] Matching findings to bug bounty programs...");
    let bug_bounty_manager = BugBountyManager::new(); // Create a new instance
    let bounty_matches = bug_bounty_manager.match_to_bug_bounty_programs(&analyzed_results).await?;
    info!("Found {} potential bug bounty matches", bounty_matches.len());
    println!("Found {} potential bug bounty matches", bounty_matches.len());

    // Create the comprehensive report
    let report = ScanReport {
        target: target.to_string(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        findings: analyzed_results,
        subdomains,
        vulnerabilities: collect_report_vulnerabilities(&dork_results, &shodan_results, &js_analysis, &urlscan_results, &cloud_storage), // Collect vulnerabilities from various sources
        endpoints: collect_endpoints(&dork_results, &js_analysis),
        proxies,
        bounty_matches,
        visualizations,
    };

    // Save the report
    let report_path = format!("data/findings/{}_full_report.json", target.replace(".", "_"));
    let report_json = serde_json::to_string_pretty(&report)?;
    fs::write(&report_path, report_json)?;

    info!("Scan complete! Report saved to {}", report_path);
    println!("\nScan complete! Report saved to {}", report_path);

    Ok(report)
}

/// Generate visualizations for the findings
async fn generate_visualizations(findings: &[Finding]) -> Result<Vec<Visualization>, Box<dyn Error>> {
    let mut visualizations = Vec::new();

    // Timeline visualization
    let timeline_path = "data/visualizations/findings_timeline.svg";

    // Create a simple timeline visualization (in a real implementation, this would generate actual SVG)
    let timeline_content = r#"<svg width="800" height="400" xmlns="http://www.w3.org/2000/svg">
        <rect width="800" height="400" fill="#f0f0f0" />
        <text x="400" y="50" font-family="Arial" font-size="24" text-anchor="middle">Findings Timeline</text>
    </svg>"#;

    fs::write(timeline_path, timeline_content)?;

    visualizations.push(Visualization {
        title: "Findings Timeline".to_string(),
        description: "Timeline of all discovered vulnerabilities".to_string(),
        file_path: timeline_path.to_string(),
        visualization_type: "timeline".to_string(),
    });

    // Network graph visualization
    let graph_path = "data/visualizations/network_graph.svg";

    // Create a simple network graph visualization
    let graph_content = r#"<svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
        <rect width="800" height="600" fill="#f0f0f0" />
        <text x="400" y="50" font-family="Arial" font-size="24" text-anchor="middle">Network Graph</text>
    </svg>"#;

    fs::write(graph_path, graph_content)?;

    visualizations.push(Visualization {
        title: "Network Graph".to_string(),
        description: "Graph showing relationships between findings".to_string(),
        file_path: graph_path.to_string(),
        visualization_type: "graph".to_string(),
    });

    // Severity heatmap visualization
    let heatmap_path = "data/visualizations/severity_heatmap.svg";

    // Create a simple heatmap visualization
    let heatmap_content = r#"<svg width="600" height="400" xmlns="http://www.w3.org/2000/svg">
        <rect width="600" height="400" fill="#f0f0f0" />
        <text x="300" y="50" font-family="Arial" font-size="24" text-anchor="middle">Severity Heatmap</text>
    </svg>"#;

    fs::write(heatmap_path, heatmap_content)?;

    visualizations.push(Visualization {
        title: "Severity Heatmap".to_string(),
        description: "Heatmap showing concentration of vulnerabilities by severity".to_string(),
        file_path: heatmap_path.to_string(),
        visualization_type: "heatmap".to_string(),
    });

    Ok(visualizations)
}

/// Collect vulnerabilities from various sources and format for the report
fn collect_report_vulnerabilities(
    dork_results: &[DorkResult],
    shodan_results: &[serde_json::Value],
    js_analysis: &[serde_json::Value],
    urlscan_results: &[serde_json::Value],
    cloud_storage: &[serde_json::Value],
) -> Vec<ReportVulnerability> {
    let mut vulnerabilities = Vec::new();
    let matcher = VulnerabilityMatcher::new(); // Need a matcher to analyze content

    // Analyze dork results content
    for result in dork_results {
        let matches = matcher.analyze_content(&result.url, &result.snippet);
        for m in matches {
            vulnerabilities.push(ReportVulnerability {
                id: m.pattern_id.clone(), // Use pattern ID as part of vulnerability ID
                name: m.pattern_name,
                description: format!("Matched pattern '{}' in search result snippet. Matched content: '{}'", m.pattern_id, m.matched_content),
                severity: m.severity,
                url: m.url,
                pattern_matched: m.matched_content,
                discovery_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                context: m.context,
                cwe_id: m.cwe_id,
                remediation: m.remediation,
            });
        }
         // Also check URL for simple patterns like exposed admin
         if result.url.contains("admin") ||
            result.url.contains("login") ||
            result.url.contains("dashboard") ||
            result.url.contains("wp-admin") {
             vulnerabilities.push(ReportVulnerability {
                 id: "EXPOSED-ADMIN-URL".to_string(),
                 name: "Exposed Admin Interface URL".to_string(),
                 description: format!("Potential administrative interface URL found in search results: {}", result.url),
                 severity: "Medium".to_string(),
                 url: result.url.clone(),
                 pattern_matched: "URL contains admin/login pattern".to_string(),
                 discovery_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                 context: result.url.clone(),
                 cwe_id: Some("CWE-200".to_string()), // Information Exposure
                 remediation: Some("Restrict access to administrative interfaces with proper authentication and IP restrictions.".to_string()),
             });
         }
    }

    // Extract vulnerabilities from Shodan results
    for shodan_result in shodan_results {
        if let Some(vulns) = shodan_result.get("vulns").and_then(|v| v.as_object()) {
            for (vuln_id, vuln_details) in vulns {
                 vulnerabilities.push(ReportVulnerability {
                    id: vuln_id.clone(), // Use Shodan vuln ID
                    name: vuln_id.clone(),
                    description: vuln_details.get("summary").and_then(|s| s.as_str()).unwrap_or("No description").to_string(),
                    severity: vuln_details.get("severity").and_then(|s| s.as_str()).unwrap_or("Unknown").to_string(),
                    url: shodan_result.get("ip_str").and_then(|ip| ip.as_str()).unwrap_or("unknown").to_string(),
                    pattern_matched: "Shodan vulnerability scan".to_string(),
                    discovery_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                    context: format!("Shodan data: {:?}", shodan_result),
                    cwe_id: None, // Shodan data might not have CWE ID
                    remediation: None, // Shodan data might not have remediation
                 });
            }
        }
    }

     // Extract vulnerabilities from JavaScript analysis
     for js_result in js_analysis {
         if let Some(api_keys) = js_result.get("api_keys").and_then(|k| k.as_array()) {
             if !api_keys.is_empty() {
                 vulnerabilities.push(ReportVulnerability {
                     id: "JS-API-KEY-EXPOSURE".to_string(),
                     name: "API Key Exposure in JavaScript".to_string(),
                     description: format!("API keys found in JavaScript file that could be used to access protected APIs: {:?}", api_keys),
                     severity: "High".to_string(),
                     url: js_result.get("url").and_then(|u| u.as_str()).unwrap_or("unknown").to_string(),
                     pattern_matched: "API key pattern in JS".to_string(),
                     discovery_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                     context: js_result.to_string(), // Full JS analysis result as context
                     cwe_id: Some("CWE-312".to_string()),
                     remediation: Some("Never store sensitive credentials in client-side code. Use environment variables or secure credential storage.".to_string()),
                 });
             }
         }
          if let Some(true) = js_result.get("has_credentials").and_then(|c| c.as_bool()) {
             vulnerabilities.push(ReportVulnerability {
                 id: "JS-HARDCODED-CREDENTIALS".to_string(),
                 name: "Hard-coded Credentials in JavaScript".to_string(),
                 description: "Hard-coded credentials found in JavaScript code. These credentials can be extracted and used to gain unauthorized access to systems.".to_string(),
                 severity: "Critical".to_string(),
                 url: js_result.get("url").and_then(|u| u.as_str()).unwrap_or("unknown").to_string(),
                 pattern_matched: "Hard-coded credential pattern in JS".to_string(),
                 discovery_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                 context: js_result.to_string(), // Full JS analysis result as context
                 cwe_id: Some("CWE-798".to_string()), // Use of Hard-coded Credentials
                 remediation: Some("Remove all hard-coded credentials from client-side code and use secure authentication mechanisms.".to_string()),
             });
         }
     }

     // Extract vulnerabilities from URLScan results
     for urlscan_result in urlscan_results {
         if let Some(page) = urlscan_result.get("page") {
             let missing_security_headers = vec![
                "Content-Security-Policy",
                "X-XSS-Protection",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Strict-Transport-Security",
                "Referrer-Policy",
                "Permissions-Policy",
             ];

             let mut missing_headers = Vec::new();

             for header in &missing_security_headers {
                 if !page.get(header).is_some() {
                     missing_headers.push(header.to_string());
                 }
             }

             if !missing_headers.is_empty() {
                 vulnerabilities.push(ReportVulnerability {
                     id: "MISSING-SECURITY-HEADERS".to_string(),
                     name: "Missing Security Headers".to_string(),
                     description: format!("Security headers are missing that could help protect against common web vulnerabilities: {:?}. Implementing these headers adds important defense-in-depth protections.", missing_headers),
                     severity: "Low".to_string(),
                     url: page.get("url").and_then(|u| u.as_str()).unwrap_or("unknown").to_string(),
                     pattern_matched: "Absence of security headers".to_string(),
                     discovery_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                     context: urlscan_result.to_string(), // Full URLScan result as context
                     cwe_id: Some("CWE-16".to_string()), // Configuration
                     remediation: Some("Implement proper security headers on all web pages.".to_string()),
                 });
             }

             if let Some(true) = page.get("hasInsecureContent").and_then(|v| v.as_bool()) {
                 vulnerabilities.push(ReportVulnerability {
                     id: "MIXED-CONTENT".to_string(),
                     name: "Mixed Content".to_string(),
                     description: "The page loads resources over insecure HTTP connections, which can lead to man-in-the-middle attacks. All resources should be loaded over HTTPS.".to_string(),
                     severity: "Medium".to_string(),
                     url: page.get("url").and_then(|u| u.as_str()).unwrap_or("unknown").to_string(),
                     pattern_matched: "Insecure content detected".to_string(),
                     discovery_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                     context: urlscan_result.to_string(), // Full URLScan result as context
                     cwe_id: Some("CWE-311".to_string()), // Missing Encryption of Sensitive Data
                     remediation: Some("Update all resource links to use HTTPS.".to_string()),
                 });
             }
         }
     }

      // Extract vulnerabilities from cloud storage findings
     for storage_result in cloud_storage {
         vulnerabilities.push(ReportVulnerability {
             id: "CLOUD-STORAGE-EXPOSURE".to_string(),
             name: "Cloud Storage Exposure".to_string(),
             description: format!(
                 "Exposed cloud storage found: {} ({}). Publicly accessible cloud storage can lead to data leaks if it contains sensitive information.",
                 storage_result.get("title").and_then(|t| t.as_str()).unwrap_or("Unknown"),
                 storage_result.get("storage_type").and_then(|t| t.as_str()).unwrap_or("Unknown")
             ),
             severity: "Medium".to_string(), // Assuming medium severity for exposure
             url: storage_result.get("url").and_then(|u| u.as_str()).unwrap_or("unknown").to_string(),
             pattern_matched: "Public cloud storage detected".to_string(),
             discovery_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
             context: storage_result.to_string(), // Full cloud storage result as context
             cwe_id: Some("CWE-922".to_string()), // Insecure Storage of Sensitive Data
             remediation: Some("Review access controls for the cloud storage resource and restrict public access.".to_string()),
         });
     }


    vulnerabilities
}

/// Collect API endpoints from dork results and JavaScript analysis
fn collect_endpoints(dork_results: &[DorkResult], js_analysis: &[serde_json::Value]) -> Vec<ApiEndpoint> {
    let mut endpoints = Vec::new();

    // Extract endpoints from dork results
    for result in dork_results {
        if result.url.contains("/api/") || result.url.contains("api.") {
            endpoints.push(ApiEndpoint {
                url: result.url.clone(),
                method: "GET".to_string(), // Assuming GET as default
                parameters: Vec::new(),    // No parameters extracted
                response_code: 0,        // Default to 0, actual code not available from dork
                discovery_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
        }
    }

    // Extract endpoints from JavaScript analysis
    for js_file in js_analysis {
        if let Some(endpoints_list) = js_file.get("endpoints").and_then(|e| e.as_array()) {
            for endpoint in endpoints_list {
                if let Some(url) = endpoint.get("url").and_then(|u| u.as_str()) {
                    let method = endpoint.get("method").and_then(|m| m.as_str()).unwrap_or("GET").to_string();

                    let parameters = if let Some(params) = endpoint.get("parameters").and_then(|p| p.as_array()) {
                        params.iter()
                            .filter_map(|param| param.as_str().map(|s| s.to_string()))
                            .collect()
                    } else {
                        Vec::new()
                    };

                    endpoints.push(ApiEndpoint {
                        url: url.to_string(),
                        method,
                        parameters,
                        response_code: 0, // Default to 0, actual code not available from analysis
                        discovery_timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    });
                }
            }
        }
    }

    endpoints
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Initialize logging
    env_logger::init();


    // Ensure data directories exist
    ensure_data_dirs()?;

    println!("===============================================================");
    println!("                   OmniDork v1.0");
    println!("===============================================================");
    println!("Integrated OSINT, Quantum Resonant Search, and Proxy Scanner");
    println!("===============================================================\n");

    // Check for existing checkpoint
    let checkpoint_path = "data/checkpoints/latest.checkpoint";
    let resume_from_checkpoint = Path::new(checkpoint_path).exists();

    let mut engine = ResonantEngine::new();

    if resume_from_checkpoint {
        println!("\nFound existing checkpoint. Would you like to resume? (y/n)");
        print!("> ");
        io::stdout().flush()?;

        let mut resume_choice = String::new();
        io::stdin().read_line(&mut resume_choice)?;

        if resume_choice.trim().to_lowercase().starts_with('y') {
            match engine.load_checkpoint(checkpoint_path) {
                Ok(_) => println!("Resumed from checkpoint with {} documents", engine.len()),
                Err(e) => {
                    eprintln!("Failed to load checkpoint: {}", e);
                    println!("Starting fresh index");
                }
            }
        } else {
            println!("Starting fresh index");
        }
    }

    println!("\nChoose operation mode:");
    println!("1. OSINT and Vulnerability Scanning");
    println!("2. Quantum Resonant Search");
    println!("3. Proxy Scanning");
    println!("4. Open Redirect Vulnerability Scan");
    println!("5. Full Integrated Scan");
    print!("> ");
    io::stdout().flush()?;

    let mut mode_choice = String::new();
    io::stdin().read_line(&mut mode_choice)?;

    match mode_choice.trim() {
        "1" => {
            println!("\nEnter the target domain (e.g., example.com):");
            print!("> ");
            io::stdout().flush()?;

            let mut target = String::new();
            io::stdin().read_line(&mut target)?;
            let target = target.trim();

            match run_complete_scan(target).await {
                Ok(report) => {
                    println!("\nScan completed successfully!");
                    println!("Found {} vulnerabilities, {} endpoints, and {} bug bounty matches",
                             report.vulnerabilities.len(),
                             report.endpoints.len(),
                             report.bounty_matches.len());
                },
                Err(e) => {
                    eprintln!("Error during scan: {}", e);
                }
            }
        },
        "2" => {
            // --- Feature Selection ---
            println!("\nEnable quantum-inspired scoring? (y/n)");
            print!("> ");
            io::stdout().flush()?;

            let mut quantum_choice = String::new();
            io::stdin().read_line(&mut quantum_choice)?;
            let use_quantum = quantum_choice.trim().to_lowercase().starts_with('y');

            println!("\nEnable persistence theory scoring? (y/n)");
            print!("> ");
            io::stdout().flush()?;

            let mut persistence_choice = String::new();
            io::stdin().read_line(&mut persistence_choice)?;
            let use_persistence = persistence_choice.trim().to_lowercase().starts_with('y');

            // Set engine features
            engine.set_use_quantum_score(use_quantum);
            engine.set_use_persistence_score(use_persistence);

            if use_quantum {
                println!("Quantum-inspired scoring enabled");
            }

            if use_persistence {
                println!("Persistence theory scoring enabled");

                // Configure persistence parameters
                println!("\nSet fragility parameter (0.0-1.0, default: 0.2):"); // Corrected range
                print!("> ");
                io::stdout().flush()?;

                let mut fragility_input = String::new();
                io::stdin().read_line(&mut fragility_input)?;
                if let Ok(fragility) = fragility_input.trim().parse::<f64>() {
                    if fragility >= 0.0 && fragility <= 1.0 { // Corrected range check
                        engine.set_fragility(fragility);
                        println!("Fragility set to {}", fragility);
                    } else {
                         println!("Invalid fragility value. Using default: 0.2");
                    }
                } else {
                     println!("Invalid input. Using default fragility: 0.2");
                }


                println!("\nSet entropy weight (0.0-1.0, default: 0.1):"); // Corrected range
                print!("> ");
                io::stdout().flush()?;

                let mut weight_input = String::new();
                io::stdin().read_line(&mut weight_input)?;
                if let Ok(weight) = weight_input.trim().parse::<f64>() {
                    if weight >= 0.0 && weight <= 1.0 { // Corrected range check
                        engine.set_entropy_weight(weight);
                        println!("Entropy weight set to {}", weight);
                    } else {
                         println!("Invalid entropy weight value. Using default: 0.1");
                    }
                } else {
                     println!("Invalid input. Using default entropy weight: 0.1");
                }
            }

            // --- Crawler Setup ---
            // Only do crawling if we're not starting with enough documents or user explicitly chooses to crawl
            let mut perform_crawling = false;
            if engine.len() < 10 {
                 println!("\nIndex contains fewer than 10 documents. Crawling is recommended.");
                 perform_crawling = true;
            }

            if !perform_crawling {
                println!("\nDo you want to:\n1. Use existing index\n2. Load URLs from a file\n3. Specify a single domain to crawl");
                print!("> ");
                io::stdout().flush()?;

                let mut choice = String::new();
                io::stdin().read_line(&mut choice)?;
                let choice = choice.trim();

                match choice {
                    "2" | "3" => perform_crawling = true,
                    _ => println!("Using existing index only."),
                }
            } else {
                 println!("\nDo you want to:\n1. Use default seed URLs\n2. Load URLs from a file\n3. Specify a single domain to crawl");
                 print!("> ");
                 io::stdout().flush()?;

                 let mut choice = String::new();
                 io::stdin().read_line(&mut choice)?;
                 let choice = choice.trim();

                 let seed_urls = match choice {
                     "1" => {
                         println!("Using default seed URLs based on predefined topics...");

                         // Create multiple starting points relevant to your interests
                         let mut urls = Vec::new();

                         // Add domain-specific authoritative sites
                         urls.push("https://facebook.com/".to_string());
                         urls.push("https://wikipedia.org/".to_string());
                         urls.push("https://yahoo.com/".to_string());
                         urls.push("https://bloomberg.com/".to_string());
                         urls.push("https://yandex.ru/".to_string());
                         urls.push("https://youtube.com/".to_string());

                         urls
                     },
                     "2" => {
                         println!("Enter the path to your URL list file:");
                         print!("> ");
                         io::stdout().flush()?;

                         let mut file_path = String::new();
                         io::stdin().read_line(&mut file_path)?;
                         let file_path = file_path.trim();

                         println!("Loading URLs from: {}", file_path);
                         match load_urls_from_file(file_path) {
                             Ok(urls) => urls,
                             Err(e) => {
                                 eprintln!("Error loading URLs from file: {}", e);
                                 println!("Using default seed URLs instead.");
                                 vec!["https://facebook.com/".to_string()] // Fallback
                             }
                         }
                     },
                     "3" => {
                         println!("Enter the domain to crawl (e.g., example.com):");
                         print!("> ");
                         io::stdout().flush()?;

                         let mut domain = String::new();
                         io::stdin().read_line(&mut domain)?;
                         let domain = domain.trim();

                         println!("Stay within this domain only? (y/n)");
                         print!("> ");
                         io::stdout().flush()?;

                         let mut stay_choice = String::new();
                         io::stdin().read_line(&mut stay_choice)?;
                         let stay_in_domain = stay_choice.trim().to_lowercase().starts_with('y');

                         if stay_in_domain {
                             // Crawler instance not available here, will configure later
                             println!("Will stay within the specified domain");
                         }

                         // Convert to proper URL format
                         let base_url = if domain.starts_with("http") {
                             domain.to_string()
                         } else {
                             format!("https://{}", domain)
                         };

                         match Url::parse(&base_url) {
                             Ok(_) => vec![base_url],
                             Err(_) => {
                                 eprintln!("Invalid URL: {}.", base_url);
                                 println!("Using default seed URLs instead.");
                                 vec!["https://facebook.com/".to_string()] // Fallback
                             }
                         }
                     },
                     _ => {
                         println!("Invalid choice. Using default seed URLs.");
                         vec!["https://facebook.com/".to_string()]
                     }
                 };


                 if !seed_urls.is_empty() {
                     println!("Starting with {} seed URLs", seed_urls.len());
                     for url in &seed_urls {
                         println!("  - {}", url);
                     }

                     // Configure crawling parameters
                     println!("\nHow many pages would you like to crawl? (default: 1000, max: 25000)");
                     print!("> ");
                     io::stdout().flush()?;

                     let mut page_limit_input = String::new();
                     io::stdin().read_line(&mut page_limit_input)?;
                     let page_limit: usize = page_limit_input.trim().parse().unwrap_or(1000);
                     let page_limit = page_limit.min(25000);

                     println!("Maximum crawl depth? (default: 3, higher values follow more links)");
                     print!("> ");
                     io::stdout().flush()?;
                     let mut depth_input = String::new();
                     io::stdin().read_line(&mut depth_input)?;
                     let max_depth: u32 = depth_input.trim().parse().unwrap_or(3);

                     println!("How many concurrent workers? (default: 10, max recommended: 20)");
                     print!("> ");
                     io::stdout().flush()?;

                     let mut workers_input = String::new();
                     io::stdin().read_line(&mut workers_input)?;
                     let num_crawler_workers: usize = workers_input.trim().parse().unwrap_or(10);
                     let num_crawler_workers = num_crawler_workers.min(20).max(1); // Ensure between 1-20

                     println!("Starting web crawling with {} workers, targeting {} pages with max depth {}...",
                              num_crawler_workers, page_limit, max_depth);

                     // Channel for crawled documents
                     let (doc_sender, mut doc_receiver) = mpsc::channel::<CrawledDocument>(500);

                     // Create the crawler instance and set options
                     let mut crawler = Crawler::new(doc_sender.clone());
                     crawler.set_max_pages(page_limit);
                     crawler.set_max_depth(max_depth);
                     // Check the stay_in_domain flag set earlier if choice was 3
                     if choice.trim() == "3" && stay_choice.trim().to_lowercase().starts_with('y') {
                        crawler.set_stay_in_domain(true);
                        println!("Staying within the specified domain during crawl.");
                     }


                     // Spawn the crawler task
                     let crawl_handle = tokio::spawn(async move {
                         crawler.crawl(seed_urls, num_crawler_workers).await;
                         // Drop the sender when the crawler finishes to signal the indexing loop
                         drop(doc_sender);
                     });

                     // --- Indexing Process ---
                     // Process crawled documents as they arrive from the crawler
                     let mut indexed_count = 0;
                     let start_time = SystemTime::now()
                         .duration_since(UNIX_EPOCH)
                         .unwrap_or_default()
                         .as_secs();

                     // This loop will run until the doc_sender is dropped in the crawler task
                     while let Some(doc) = doc_receiver.recv().await {
                         engine.add_crawled_document(doc);
                         indexed_count += 1;

                         // Print progress periodically
                         if indexed_count % 10 == 0 {
                              println!("Indexed document. Total indexed: {}", engine.len());
                         }

                         // Save checkpoints periodically
                         if indexed_count % 100 == 0 {
                             if let Err(e) = engine.save_checkpoint(checkpoint_path) {
                                 eprintln!("Failed to save checkpoint: {}", e);
                             }

                             // Also compress documents to save memory
                             engine.compress_all_documents();
                         }

                         // Keep the limit if you only want a max index size and stop early
                          if engine.len() >= page_limit {
                              println!("Reached target index size of {}. Stopping crawler.", page_limit);
                              break;
                          }
                     }
                     println!("Indexing of crawled documents finished. Total indexed: {}", engine.len());

                     // Calculate crawling stats
                     let end_time = SystemTime::now()
                         .duration_since(UNIX_EPOCH)
                         .unwrap_or_default()
                         .as_secs();
                     let elapsed_seconds = end_time - start_time;
                     println!("Crawling took {} seconds ({:.2} minutes)",
                         elapsed_seconds, elapsed_seconds as f64 / 60.0);
                     println!("Average speed: {:.2} pages per second",
                         indexed_count as f64 / elapsed_seconds.max(1) as f64);

                     // Save final checkpoint
                     println!("Saving final checkpoint...");
                     if let Err(e) = engine.save_checkpoint(checkpoint_path) {
                         eprintln!("Failed to save final checkpoint: {}", e);
                     }

                     // Export index to CSV for external analysis
                     if let Err(e) = engine.export_index("data/index_export.csv") {
                         eprintln!("Failed to export index: {}", e);
                     }

                     // Wait for the crawler task to complete
                     let _ = crawl_handle.await;
                 }
            }


            // --- Search Loop ---
            println!("\nResonant Search Engine is ready. Total documents indexed: {}", engine.len());

            // Only enter the search loop after crawling and indexing are complete
            loop {
                println!("\nEnter your resonant query (or type 'quit' to exit):");
                print!("> ");
                io::stdout().flush()?;

                let mut query = String::new();
                io::stdin().read_line(&mut query)?;
                let query = query.trim();

                if query.eq_ignore_ascii_case("quit") {
                    println!("Exiting.");
                    break;
                }

                if query.eq_ignore_ascii_case("export") {
                    println!("Exporting index to CSV...");
                    if let Err(e) = engine.export_index("data/index_export.csv") {
                        eprintln!("Failed to export index: {}", e);
                    }
                    continue;
                }

                if query.eq_ignore_ascii_case("checkpoint") {
                    println!("Saving checkpoint...");
                    if let Err(e) = engine.save_checkpoint(checkpoint_path) {
                        eprintln!("Failed to save checkpoint: {}", e);
                    }
                    continue;
                }

                if query.eq_ignore_ascii_case("compress") {
                    println!("Compressing all documents...");
                    engine.compress_all_documents();
                    continue;
                }

                if query.is_empty() {
                    println!("Query is empty. Please enter a query.");
                    continue;
                }

                println!("\nSearching for resonant matches...");
                let results = engine.search(query, 5); // Display top 5 results

                // Apply quantum jump for feedback mechanism
                engine.apply_quantum_jump(query, 0.2);

                println!("\nTop Resonant Matches:");
                if results.is_empty() {
                    println!("No results found.");
                } else {
                    for (idx, r) in results.iter().enumerate() {
                        println!("[{}] {}", idx + 1, r.title);
                        println!("    URL:            {}", r.path); // Display URL

                        // Show standard scores
                        println!("    Resonance:      {:.4}", r.resonance);
                        println!("    Δ Entropy:      {:.4}", r.delta_entropy);
                        println!("    Standard Score: {:.4}", r.score);

                        // Show extended scores if enabled
                        if use_quantum {
                            println!("    Quantum Score:  {:.4}", r.quantum_score);
                        }

                        if use_persistence {
                            println!("    Persist. Score: {:.4}", r.persistence_score);
                        }

                        // Compute combined score based on what's enabled
                        let combined_score = if use_quantum && use_persistence {
                            r.score * 0.5 + r.quantum_score * 0.25 + r.persistence_score * 0.25
                        } else if use_quantum {
                            r.score * 0.7 + r.quantum_score * 0.3
                        } else if use_persistence {
                            r.score * 0.7 + r.persistence_score * 0.3
                        } else {
                            r.score
                        };

                        println!("    Combined Score: {:.4}", combined_score);
                        println!("    Preview:        {}", r.snippet);
                        println!();
                    }
                }

                // Save checkpoint after each successful search to preserve learning
                if let Err(e) = engine.save_checkpoint(checkpoint_path) {
                    eprintln!("Failed to save search checkpoint: {}", e);
                }
            }
        },
        "3" => {
            // Proxy Scanner Mode
            println!("\nStarting proxy scanner...");

            // Proxy scanner settings
            println!("\nConfigure proxy scanner settings:");

            println!("Maximum concurrent connections (default: 150, max recommended: 1250):");
            print!("> ");
            io::stdout().flush()?;

            let mut conn_limit_input = String::new();
            io::stdin().read_line(&mut conn_limit_input)?;
            let connection_limit: usize = conn_limit_input.trim().parse().unwrap_or(150);
            let connection_limit = connection_limit.min(1250).max(10);

            println!("Number of validation rounds per proxy (default: 3):");
            print!("> ");
            io::stdout().flush()?;

            let mut validation_input = String::new();
            io::stdin().read_line(&mut validation_input)?;
            let validation_rounds: usize = validation_input.trim().parse().unwrap_or(3);

            println!("Connection timeout in seconds (default: 5.0):");
            print!("> ");
            io::stdout().flush()?;

            let mut timeout_input = String::new();
            io::stdin().read_line(&mut timeout_input)?;
            let timeout: f64 = timeout_input.trim().parse().unwrap_or(5.0);

            println!("Check proxy anonymity level? (y/n, default: y)");
            print!("> ");
            io::stdout().flush()?;

            let mut anonymity_input = String::new();
            io::stdin().read_line(&mut anonymity_input)?;
            let check_anonymity = !anonymity_input.trim().to_lowercase().starts_with('n');

            println!("\nStarting proxy scan with {} connections, {} validation rounds, {}s timeout...",
                     connection_limit, validation_rounds, timeout);

            let mut proxy_scanner = ProxyScanner::new_with_config( // Made mutable
                connection_limit,
                validation_rounds,
                timeout,
                check_anonymity
            );

            match proxy_scanner.scan_proxies().await {
                Ok(proxies) => {
                    println!("\nProxy scan completed!");
                    println!("Found {} working proxies", proxies.len());

                    // Save proxies to file
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let proxy_path = format!("data/proxies/working_proxies_{}.txt", timestamp);
                    let mut proxy_file = fs::File::create(&proxy_path)?;

                    for proxy in &proxies {
                        writeln!(proxy_file, "{}:{}", proxy.ip, proxy.port)?;
                    }

                    println!("Saved working proxies to {}", proxy_path);

                    // Offer to run speed tests
                    println!("\nWould you like to run speed tests on these proxies? (y/n)");
                    print!("> ");
                    io::stdout().flush()?;

                    let mut speed_test_input = String::new();
                    io::stdin().read_line(&mut speed_test_input)?;

                    if speed_test_input.trim().to_lowercase().starts_with('y') {
                        println!("Running speed tests (this may take a while)...");

                        match proxy_scanner.run_speed_test(&proxies).await {
                            Ok(results) => {
                                println!("\nSpeed test results:");
                                println!("Fastest 5 proxies:");

                                for (i, (proxy, speed)) in results.iter().take(5).enumerate() {
                                    println!("{}. {}:{} - {:.2}ms", i+1, proxy.ip, proxy.port, speed);
                                }

                                // Save speed test results to file
                                let speed_path = format!("data/proxies/speed_test_{}.csv", timestamp);
                                let mut speed_file = fs::File::create(&speed_path)?;

                                writeln!(speed_file, "IP,Port,Protocol,ResponseTime,Country")?;
                                for (proxy, speed) in &results {
                                    writeln!(speed_file, "{},{},{},{:.2},{}",
                                             proxy.ip, proxy.port, proxy.protocol, speed, proxy.country)?;
                                }

                                println!("Saved speed test results to {}", speed_path);
                            },
                            Err(e) => {
                                eprintln!("Error during speed test: {}", e);
                            }
                        }
                    }
                },
                Err(e) => {
                    eprintln!("Error during proxy scan: {}", e);
                }
            }
        },
        "4" => {
            // Open Redirect Vulnerability Scanner
            println!("\nOpen Redirect Vulnerability Scanner");
            println!("Enter the file containing URLs to scan:");
            print!("> ");
            io::stdout().flush()?;

            let mut filename = String::new();
            io::stdin().read_line(&mut filename)?;
            let filename = filename.trim();

            // Read URLs from file
            let file = match fs::File::open(filename) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Error opening file: {}", e);
                    return Ok(());
                }
            };

            let reader = BufReader::new(file);
            let urls: Vec<String> = reader.lines()
                .filter_map(|line| line.ok())
                .collect();

            println!("Loaded {} URLs from {}", urls.len(), filename);

            println!("Enter payload for redirect testing (default: http://evil.com):");
            print!("> ");
            io::stdout().flush()?;

            let mut payload = String::new();
            io::stdin().read_line(&mut payload)?;
            let payload = if payload.trim().is_empty() {
                "http://evil.com".to_string()
            } else {
                payload.trim().to_string()
            };

            println!("Starting open redirect scan with payload: {}", payload);

            // Run the open redirect scan
            let vulnerable_urls = scan_for_open_redirects(&urls, &payload).await; // No need for match

            println!("\nScan complete!");
            println!("Found {} vulnerable URLs", vulnerable_urls.len());

            if !vulnerable_urls.is_empty() {
                // Save vulnerable URLs to file
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let vuln_path = format!("data/findings/open_redirect_vulns_{}.txt", timestamp);
                let mut vuln_file = fs::File::create(&vuln_path)?;

                for url in &vulnerable_urls {
                    writeln!(vuln_file, "{}", url)?;
                }

                println!("Saved vulnerable URLs to {}", vuln_path);
            }
        },
        "5" => {
            // Full Integrated Scan Mode
            println!("\nFull Integrated Scan");
            println!("This mode combines OSINT scanning, quantum search, and proxy scanning.");

            println!("\nEnter the target domain for OSINT scanning:");
            print!("> ");
            io::stdout().flush()?;

            let mut target = String::new();
            io::stdin().read_line(&mut target)?;
            let target = target.trim();

            // 1. First run the OSINT scan
            println!("\n[Phase 1/3] Starting OSINT and vulnerability scan...");
            let osint_result = match run_complete_scan(target).await {
                Ok(report) => {
                    println!("OSINT scan complete!");
                    println!("Found {} vulnerabilities, {} endpoints, and {} bug bounty matches",
                             report.vulnerabilities.len(),
                             report.endpoints.len(),
                             report.bounty_matches.len());
                    Some(report)
                },
                Err(e) => {
                    eprintln!("Error during OSINT scan: {}", e);
                    None
                }
            };

            // 2. Then run the quantum resonant search
            println!("\n[Phase 2/3] Starting quantum resonant search...");

            // Enable quantum-inspired scoring
            engine.set_use_quantum_score(true);
            println!("Quantum-inspired scoring enabled");

            // Enable persistence theory scoring
            engine.set_use_persistence_score(true);
            println!("Persistence theory scoring enabled");

            // Set default parameters
            engine.set_fragility(0.2);
            engine.set_entropy_weight(0.1);

            // Channel for crawled documents
            let (doc_sender, mut doc_receiver) = mpsc::channel::<CrawledDocument>(500);

            // Create the crawler instance
            let mut crawler = Crawler::new(doc_sender.clone());

            // Get seed URLs from the OSINT scan if available
            let seed_urls = if let Some(ref report) = osint_result {
                // Convert subdomains to URLs
                let mut urls: Vec<String> = report.subdomains.iter()
                    .filter_map(|subdomain| {
                         // Attempt to parse as URL, fallback to https
                         if Url::parse(subdomain).is_ok() {
                             Some(subdomain.clone())
                         } else {
                             Some(format!("https://{}", subdomain))
                         }
                    })
                    .collect();
                // Add the main target domain
                if Url::parse(target).is_ok() {
                     urls.push(target.to_string());
                } else {
                     urls.push(format!("https://{}", target));
                }
                urls
            } else {
                // Fallback to default seed URLs if OSINT scan failed
                vec![
                    format!("https://{}", target),
                    format!("https://www.{}", target)
                ]
            };

            println!("Using {} seed URLs for crawling", seed_urls.len());

            // Configure crawler
            crawler.set_max_pages(500);
            crawler.set_max_depth(3);
            crawler.set_stay_in_domain(true); // Stay within the target domain

            // Spawn the crawler task
            let crawl_handle = tokio::spawn(async move {
                crawler.crawl(seed_urls, 10).await;
                drop(doc_sender);
            });

            // Process crawled documents
            let mut indexed_count = 0;

            while let Some(doc) = doc_receiver.recv().await {
                engine.add_crawled_document(doc);
                indexed_count += 1;

                // Print progress periodically
                if indexed_count % 10 == 0 {
                     println!("Indexed document. Total indexed: {}", engine.len());
                }

                // Save checkpoints periodically
                if indexed_count % 100 == 0 {
                    if let Err(e) = engine.save_checkpoint(checkpoint_path) {
                        eprintln!("Failed to save checkpoint: {}", e);
                    }

                    // Also compress documents to save memory
                    engine.compress_all_documents();
                }
            }

            println!("Quantum resonant indexing complete. Total indexed: {}", engine.len());

            // Save final checkpoint
            if let Err(e) = engine.save_checkpoint(checkpoint_path) {
                eprintln!("Failed to save final checkpoint: {}", e);
            }

            // Wait for the crawler task to complete
            let _ = crawl_handle.await;

            // 3. Run proxy scanner
            println!("\n[Phase 3/3] Starting proxy scanner...");

            let mut proxy_scanner = ProxyScanner::new(); // Made mutable

            match proxy_scanner.scan_proxies().await {
                Ok(proxies) => {
                    println!("Proxy scan complete!");
                    println!("Found {} working proxies", proxies.len());

                    // Save proxies to file
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let proxy_path = format!("data/proxies/working_proxies_{}.txt", timestamp);
                    let mut proxy_file = fs::File::create(&proxy_path)?;

                    for proxy in &proxies {
                        writeln!(proxy_file, "{}:{}", proxy.ip, proxy.port)?;
                    }

                    println!("Saved working proxies to {}", proxy_path);
                },
                Err(e) => {
                    eprintln!("Error during proxy scan: {}", e);
                }
            }

            // Generate integrated report
            println!("\nGenerating integrated report...");

            let integrated_report_path = format!("data/findings/integrated_report_{}.md",
                                              SystemTime::now()
                                                  .duration_since(UNIX_EPOCH)
                                                  .unwrap_or_default()
                                                  .as_secs());

            let mut report_file = fs::File::create(&integrated_report_path)?;

            writeln!(report_file, "# Integrated Scan Report for {}\n", target)?;
            writeln!(report_file, "Generated on: {}\n",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))?;

            // OSINT section
            writeln!(report_file, "## 1. OSINT and Vulnerability Findings\n")?;

            if let Some(report) = osint_result {
                writeln!(report_file, "* Found {} subdomains", report.subdomains.len())?;
                writeln!(report_file, "* Discovered {} vulnerabilities", report.vulnerabilities.len())?;
                writeln!(report_file, "* Identified {} API endpoints", report.endpoints.len())?;
                writeln!(report_file, "* Matched {} potential bug bounties\n", report.bounty_matches.len())?;

                // List vulnerabilities
                if !report.vulnerabilities.is_empty() {
                    writeln!(report_file, "### Key Vulnerabilities\n")?;
                    // Use the ReportVulnerability structure for the table
                    writeln!(report_file, "| Severity | Name | URL | CWE ID | Remediation | Context |")?;
                    writeln!(report_file, "|----------|------|-----|--------|-------------|---------|")?;

                    for vuln in report.vulnerabilities.iter().take(10) {
                        // Escape markdown special characters in context and description
                        let escaped_context = vuln.context.replace("|", "\\|").replace("\n", "<br/>");
                        let escaped_description = vuln.description.replace("|", "\\|").replace("\n", "<br/>");

                        writeln!(report_file, "| {} | {} | {} | {} | {} | {} |",
                                 vuln.severity,
                                 vuln.name,
                                 vuln.url,
                                 vuln.cwe_id.as_deref().unwrap_or("N/A"),
                                 vuln.remediation.as_deref().unwrap_or("No specific remediation provided."),
                                 escaped_context
                                 )?;
                    }

                    if report.vulnerabilities.len() > 10 {
                        writeln!(report_file, "\n... and {} more vulnerabilities. See full report for details.\n",
                                report.vulnerabilities.len() - 10)?;
                    }

                    writeln!(report_file, "\n")?;
                }
                 // List Findings (the more detailed ones from analyze_findings)
                 if !report.findings.is_empty() {
                     writeln!(report_file, "### Detailed Findings\n")?;
                      writeln!(report_file, "| Severity | Type | URL | Description | Dork Used | Sensitive Data |")?;
                     writeln!(report_file, "|----------|------|-----|-------------|-----------|----------------|")?;

                     for finding in report.findings.iter().take(10) {
                         let escaped_desc = finding.description.replace("|", "\\|").replace("\n", "<br/>");
                          writeln!(report_file, "| {} | {} | {} | {} | {} | {} |",
                                 finding.severity,
                                 finding.finding_type,
                                 finding.url.as_deref().unwrap_or("N/A"),
                                 escaped_desc,
                                 finding.dork_used.as_deref().unwrap_or("N/A"),
                                 finding.has_sensitive_data
                                 )?;
                     }
                      if report.findings.len() > 10 {
                         writeln!(report_file, "\n... and {} more findings. See full report for details.\n",
                                report.findings.len() - 10)?;
                     }
                     writeln!(report_file, "\n")?;
                 }

            } else {
                writeln!(report_file, "OSINT scan did not complete successfully.\n")?;
            }

            // Quantum search section
            writeln!(report_file, "## 2. Quantum Resonant Search Results\n")?;
            writeln!(report_file, "* Indexed {} documents", engine.len())?;

            // List top documents by resonance
            let top_docs = engine.get_top_documents(5);

            if !top_docs.is_empty() {
                writeln!(report_file, "\n### Top Resonant Documents\n")?;

                for (i, doc) in top_docs.iter().enumerate() {
                    writeln!(report_file, "{}. **{}**", i+1, doc.title)?;
                    writeln!(report_file, "   - URL: {}", doc.path)?;
                    writeln!(report_file, "   - Score: {:.4}", doc.score)?; // Use standard score for simplicity in summary
                    writeln!(report_file, "   - Preview: {}\n", doc.snippet)?;
                }
            } else {
                 writeln!(report_file, "No documents indexed or no results found in quantum search.\n")?;
            }


            // Proxy scanner section
            writeln!(report_file, "## 3. Proxy Scanner Results\n")?;

            let proxy_files = fs::read_dir("data/proxies")?
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry.file_name().to_string_lossy().starts_with("working_proxies_")
                })
                .collect::<Vec<_>>();

            if let Some(latest_proxy_file) = proxy_files.into_iter().max_by_key(|entry| {
                entry.metadata().ok()
                    .and_then(|meta| meta.modified().ok())
                    .unwrap_or_else(|| std::time::SystemTime::UNIX_EPOCH)
            }) {
                let proxy_count = BufReader::new(fs::File::open(latest_proxy_file.path())?)
                    .lines()
                    .count();

                writeln!(report_file, "* Found {} working proxies", proxy_count)?;
                writeln!(report_file, "* Proxy list saved to {}",
                        latest_proxy_file.path().display())?;

                // Check for speed test results
                let speed_test_files = fs::read_dir("data/proxies")?
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| {
                        entry.file_name().to_string_lossy().starts_with("speed_test_")
                    })
                    .collect::<Vec<_>>();

                if let Some(latest_speed_file) = speed_test_files.into_iter().max_by_key(|entry| {
                    entry.metadata().ok()
                        .and_then(|meta| meta.modified().ok())
                        .unwrap_or_else(|| std::time::SystemTime::UNIX_EPOCH)
                }) {
                     writeln!(report_file, "* Latest speed test results saved to {}",
                             latest_speed_file.path().display())?;
                }

            } else {
                writeln!(report_file, "No proxy scan results found.")?;
            }

            println!("Integrated report saved to {}", integrated_report_path);
            println!("\nFull integrated scan complete!");
        },
        _ => {
            println!("Invalid choice. Exiting.");
        }
    }

    Ok(())
}