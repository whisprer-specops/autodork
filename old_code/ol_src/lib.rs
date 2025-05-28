// src/lib.rs - Main library file exporting all modules

// Re-export all core modules
pub mod tokenizer;
pub mod engine;
pub mod prime_hilbert;
pub mod entropy;
pub mod crawler;
pub mod quantum_types;
pub mod dork_engine;
pub mod vulnerability_matcher;
pub mod proxy_scanner;
pub mod bug_bounty;

// Main data structures
use serde::{Deserialize, Serialize};

/// Represents a security finding discovered during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for the finding
    pub id: String,
    
    /// Reference to the target this finding belongs to
    pub target_id: String,
    
    /// Optional reference to specific subdomain (if applicable)
    pub subdomain_id: Option<String>,
    
    /// Type of finding (e.g., "XSS", "SQLi", "Open Redirect")
    pub finding_type: String,
    
    /// Severity level ("Critical", "High", "Medium", "Low", "Info")
    pub severity: String,
    
    /// URL where the issue was found (if applicable)
    pub url: Option<String>,
    
    /// Description of the finding
    pub description: String,
    
    /// Timestamp when the finding was discovered
    pub discovery_timestamp: u64,
    
    /// Google dork used to discover this finding (if applicable)
    pub dork_used: Option<String>,
    
    /// Path to screenshot evidence (if available)
    pub screenshot_path: Option<String>,
    
    /// Whether the finding contains sensitive data
    pub has_sensitive_data: bool,
}

/// Represents a target domain being scanned
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// Unique identifier for the target
    pub id: String,
    
    /// Domain name of the target
    pub domain: String,
    
    /// When the target was first scanned
    pub first_scan_timestamp: u64,
    
    /// When the target was last scanned
    pub last_scan_timestamp: u64,
}

/// Represents a subdomain discovered during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subdomain {
    /// Unique identifier for the subdomain
    pub id: String,
    
    /// Reference to the parent target
    pub target_id: String,
    
    /// Full subdomain name
    pub subdomain: String,
    
    /// When the subdomain was first discovered
    pub first_discovered: u64,
    
    /// When the subdomain was last seen
    pub last_seen: u64,
    
    /// IP address of the subdomain (if resolved)
    pub ip_address: Option<String>,
    
    /// HTTP status code (if checked)
    pub http_status: Option<u16>,
    
    /// Whether HTTPS is enabled
    pub https_enabled: Option<bool>,
}

/// Represents a bug bounty match for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BountyMatch {
    /// Unique identifier for the match
    pub id: String,
    
    /// Reference to the associated finding
    pub finding_id: String,
    
    /// Bug bounty platform name
    pub platform: String,
    
    /// Bug bounty program name
    pub program_name: String,
    
    /// Estimated reward amount (if applicable)
    pub estimated_reward: Option<f64>,
    
    /// URL for submission
    pub submission_url: Option<String>,
}

/// Represents a dork execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkExecution {
    /// Unique identifier for the execution
    pub id: String,
    
    /// Reference to the target 
    pub target_id: String,
    
    /// The dork that was executed
    pub dork: String,
    
    /// When the dork was executed
    pub timestamp: u64,
    
    /// Number of results found
    pub result_count: usize,
}

// Re-export key types and functions for convenient external use
pub use engine::ResonantEngine;
pub use engine::SearchResult;
pub use crawler::CrawledDocument;
pub use prime_hilbert::{PrimeVector, BiorthogonalVector};
pub use quantum_types::{MatrixComplex, VectorComplex};
pub use dork_engine::DorkEngine;
pub use vulnerability_matcher::VulnerabilityMatcher;
pub use proxy_scanner::ProxyScanner;
pub use bug_bounty::BugBountyManager;

// Export key persistence theory functions
pub use entropy::{
    shannon_entropy,
    calculate_reversibility,
    entropy_pressure,
    buffering_capacity,
    persistence_score,
    apply_non_hermitian_decay,
    apply_fragility,
    resonant_persistence_score
};

// Important quantum functions
pub use quantum_types::{
    trace,
    density_matrix,
    mutual_information,
    calculate_redundancy,
    calculate_symmetry,
    create_hamiltonian,
    create_dissipator,
    lindblad_evolution
};

/// Utility function to apply a quantum jump event to a document state matrix
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
                doc_state[(i, j)] = doc_state[(i, j)] * Complex::new(1.0/tr, 0.0);
            }
        }
    }
}

/// Run a complete OSINT and vulnerability scan on a target domain
pub async fn run_complete_scan(target: &str) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    println!("Starting complete scan for target: {}", target);
    
    // Create instances of all necessary engines
    let dork_engine = DorkEngine::new().await?;
    let vulnerability_matcher = VulnerabilityMatcher::new();
    let bug_bounty_manager = BugBountyManager::new();
    
    // 1. Domain reconnaissance
    println!("\n[1/7] Performing domain reconnaissance...");
    let subdomains = dork_engine.discover_subdomains(target).await?;
    println!("Found {} subdomains", subdomains.len());
    
    // 2. Execute all dorks against target
    println!("\n[2/7] Executing dorks against target and subdomains...");
    let dork_results = dork_engine.execute_all_dorks(target, &subdomains).await?;
    println!("Got {} results from dork queries", dork_results.len());
    
    // 3. Query specialized services
    println!("\n[3/7] Querying specialized security services...");
    let shodan_results = dork_engine.query_shodan(target, &subdomains).await?;
    let urlscan_results = dork_engine.query_urlscan(target, &subdomains).await?;
    let dns_information = dork_engine.gather_dns_info(target, &subdomains).await?;
    
    // 4. Process JavaScript files
    println!("\n[4/7] Extracting and analyzing JavaScript files...");
    let js_files = dork_engine.extract_javascript_files(&dork_results).await?;
    let js_analysis = dork_engine.analyze_javascript_files(&js_files).await?;
    
    // 5. Check cloud storage
    println!("\n[5/7] Checking for cloud storage resources...");
    let cloud_storage = dork_engine.check_cloud_storage(target).await?;
    
    // 6. Analyze all findings
    println!("\n[6/7] Analyzing findings...");
    let findings = vulnerability_matcher.analyze_findings(
        target,
        &dork_results,
        &shodan_results,
        &urlscan_results,
        &dns_information,
        &js_analysis,
        &cloud_storage,
    ).await?;
    
    // 7. Match to bug bounty programs
    println!("\n[7/7] Matching findings to bug bounty programs...");
    let _bounty_matches = bug_bounty_manager.match_to_bug_bounty_programs(&findings).await?;
    
    Ok(findings)
}
