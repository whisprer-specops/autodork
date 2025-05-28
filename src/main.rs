use omnidork::crawler::Crawler;
use omnidork::dork_engine::DorkEngine;
use omnidork::proxy_scanner::ProxyScanner;
use omnidork::quantum_osint::QuantumScorer;
use omnidork::vulnerability_matcher::VulnerabilityMatcher;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{info, error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    info!("Starting Omnidork Quantum OSINT Engine");

    // Initialize components
    let quantum_scorer = Arc::new(QuantumScorer::new(1000));
    let proxy_scanner = Arc::new(ProxyScanner::new_with_config(150, 3, 5.0, true));
    let proxies = Arc::new(Mutex::new(Vec::new()));
    let vulnerability_matcher = Arc::new(VulnerabilityMatcher::new());
    let dork_engine = Arc::new(DorkEngine::new(Arc::clone(&proxies)));
    let crawler = Arc::new(Crawler::new(Arc::clone(&proxy_scanner), 50, 2));

    // Update proxies
    info!("Scanning for proxies...");
    {
        let mut proxies_lock = proxies.lock().await;
        *proxies_lock = proxy_scanner.scan_proxies().await?;
    }

    // Define target and dorks
    let target = "example.com";
    let dorks = vec![
        "inurl:admin",
        "intext:password",
        "filetype:pdf confidential",
    ];

    // Run dork searches
    info!("Running dork searches for {}", target);
    let mut dork_results = Vec::new();
    for dork in dorks {
        let results = dork_engine.search(dork, target, 10).await?;
        dork_results.extend(results);
    }

    // Crawl target
    info!("Crawling target {}", target);
    let crawl_results = crawler.crawl(&format!("https://{}", target), 2).await?;

    // Analyze findings
    info!("Analyzing findings...");
    let findings = vulnerability_matcher
        .analyze_findings(
            target,
            &dork_results,
            &[], // Shodan results
            &[], // URLScan results
            &[], // DNS info
            &[], // JS analysis
            &[], // Cloud storage
        )
        .await?;

    // Process crawl results
    for result in crawl_results {
        let matches = vulnerability_matcher.analyze_content(&result.url, &result.content);
        for m in matches {
            println!(
                "Found vulnerability: {} at {} (Quantum Score: {:.2})",
                m.pattern_name, m.url, m.quantum_score
            );
        }
    }

    // Output findings
    for finding in findings {
        println!(
            "[{}] {} - {} (Severity: {}, Quantum Score: {:.2})",
            finding.id, finding.finding_type, finding.description, finding.severity, 
            quantum_scorer.score_finding(&finding)
        );
    }

    info!("Omnidork scan complete");
    Ok(())
}