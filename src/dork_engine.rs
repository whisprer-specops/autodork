use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use urlencoding::encode;
use crate::proxy_scanner::ProxyInfo;
use log::{info, warn};
use rand::seq::SliceRandom;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkResult {
    pub url: String,
    pub title: String,
    pub snippet: String,
    pub content_type: Option<String>,
    pub found_dork: String,
}

pub struct DorkEngine {
    client: Client,
    proxies: Arc<Mutex<Vec<ProxyInfo>>>,
    user_agents: Vec<String>,
    search_engines: Vec<String>,
}

impl DorkEngine {
    pub fn new(proxies: Arc<Mutex<Vec<ProxyInfo>>>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/14.1.1".to_string(),
        ];
        let search_engines = vec![
            "https://www.google.com/search?q={}".to_string(),
            "https://www.bing.com/search?q={}".to_string(),
        ];
        DorkEngine {
            client,
            proxies,
            user_agents,
            search_engines,
        }
    }

    pub async fn search(&self, dork: &str, target: &str, max_results: usize) -> Result<Vec<DorkResult>, Box<dyn Error>> {
        let query = format!("site:{} {}", target, dork);
        let encoded_query = encode(&query);
        let mut results = Vec::new();

        for engine in &self.search_engines {
            let url = engine.replace("{}", &encoded_query);
            let proxy = {
                let proxies_lock = self.proxies.lock().await;
                proxies_lock
                    .iter()
                    .filter(|p| p.quantum_score > 2.5 && p.success_rate > 0.8)
                    .collect::<Vec<_>>()
                    .choose(&mut rand::thread_rng())
                    .cloned()
            };

            let client = match proxy {
                Some(p) => {
                    let proxy_url = format!("{}://{}:{}", p.protocol, p.ip, p.port);
                    Client::builder()
                        .proxy(Proxy::all(&proxy_url)?)
                        .timeout(Duration::from_secs(10))
                        .user_agent(self.user_agents.choose(&mut rand::thread_rng()).unwrap())
                        .build()?
                }
                None => {
                    warn!("No suitable proxies, using direct connection");
                    self.client.clone()
                }
            };

            let response = match client.get(&url).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("Failed to query {}: {}", url, e);
                    continue;
                }
            };

            let body = response.text().await.unwrap_or_default();
            let document = scraper::Html::parse_document(&body);
            let result_selector = scraper::Selector::parse(".g, .tF2Cxc").unwrap();
            let title_selector = scraper::Selector::parse("h3").unwrap();
            let url_selector = scraper::Selector::parse("a").unwrap();
            let snippet_selector = scraper::Selector::parse(".VwiC3b, .s3v9rd").unwrap();

            for result in document.select(&result_selector) {
                let title = result
                    .select_first(&title_selector)
                    .and_then(|t| Some(t.text().collect::<String>()))
                    .unwrap_or_default();
                let url = result
                    .select_first(&url_selector)
                    .and_then(|a| a.value().attr("href"))
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let snippet = result
                    .select_first(&snippet_selector)
                    .and_then(|s| Some(s.text().collect::<String>()))
                    .unwrap_or_default();

                if !url.is_empty() && results.len() < max_results {
                    results.push(DorkResult {
                        url,
                        title,
                        snippet,
                        content_type: None,
                        found_dork: dork.to_string(),
                    });
                }
            }
        }

        Ok(results)
    }
}