#[derive(Debug, Serialize, Deserialize)]
struct BugBountyProgram {
    platform: String,
    name: String,
    url: String,
    in_scope_domains: Vec<String>,
    out_of_scope_domains: Vec<String>,
    vulnerability_types: HashMap<String, bool>,
    known_rewards: HashMap<String, f64>,
}

struct BugBountyManager {
    programs: Vec<BugBountyProgram>,
}

impl BugBountyManager {
    fn find_matching_programs(&self, domain: &str, vulnerability_type: &str) -> Vec<&BugBountyProgram> {
        self.programs.iter()
            .filter(|p| p.in_scope_domains.iter().any(|d| domain.ends_with(d)))
            .filter(|p| p.vulnerability_types.get(vulnerability_type).copied().unwrap_or(false))
            .collect()
    }
    
    fn estimate_reward(&self, program: &BugBountyProgram, vulnerability_type: &str, severity: &str) -> Option<f64> {
        // Estimate potential reward based on historical data
        // ...
        None
    }
    
    fn generate_submission_template(&self, program: &BugBountyProgram, finding: &Finding) -> String {
        // Create platform-specific submission format
        // ...
        String::new()
    }
    
    async fn update_programs(&mut self) -> Result<(), reqwest::Error> {
        // Scrape latest program information from public sources
        // Update program database
        // ...
        Ok(())
    }
}