use reqwest::{Client, Proxy};
use scraper::{Html, Selector};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use url::Url;
use crate::proxy_scanner::{ProxyInfo, ProxyScanner};
use log::{info, warn, debug};
use rand::seq::SliceRandom;

#[derive(Debug, Clone)]
pub struct Crawler {
    client: Client,
    proxy_scanner: Arc<ProxyScanner>,
    proxies: Arc<Mutex<Vec<ProxyInfo>>>,
    user_agents: Vec<String>,
    max_depth: usize,
    concurrent_requests: usize,
}

#[derive(Debug, Clone)]
pub struct CrawlResult {
    pub url: String,
    pub content: String,
    pub links: Vec<String>,
    pub status: u16,
}

impl Crawler {
    pub fn new(proxy_scanner: Arc<ProxyScanner>, concurrent_requests: usize, max_depth: usize) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .pool_max_idle_per_host(concurrent_requests)
            .tcp_keepalive(Some(Duration::from_secs(10)))
            .build()
            .unwrap_or_else(|_| Client::new());

        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0".to_string(),
        ];

        Crawler {
            client,
            proxy_scanner,
            proxies: Arc::new(Mutex::new(Vec::new())),
            user_agents,
            max_depth,
            concurrent_requests,
        }
    }

    pub async fn update_proxies(&self) -> Result<(), Box<dyn Error>> {
        let proxies = self.proxy_scanner.scan_proxies().await?;
        let mut proxy_lock = self.proxies.lock().await;
        *proxy_lock = proxies
            .into_iter()
            .filter(|p| p.quantum_score > 2.0 && p.success_rate > 0.7)
            .collect();
        info!("Updated {} high-quality proxies for crawling", proxy_lock.len());
        Ok(())
    }

    pub async fn crawl(&self, start_url: &str, depth: usize) -> Result<Vec<CrawlResult>, Box<dyn Error>> {
        if depth > self.max_depth {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let mut to_crawl = vec![start_url.to_string()];
        let visited = Arc::new(Mutex::new(std::collections::HashSet::new()));

        for current_depth in 0..=depth {
            let mut tasks = Vec::new();
            let urls = to_crawl;
            to_crawl = Vec::new();

            for url in urls {
                let visited = Arc::clone(&visited);
                let proxies = Arc::clone(&self.proxies);
                let user_agents = self.user_agents.clone();
                tasks.push(tokio::spawn(async move {
                    if visited.lock().await.insert(url.clone()) {
                        Self::crawl_single(&url, proxies, &user_agents).await
                    } else {
                        Ok(None)
                    }
                }));
            }

            let task_results = futures::future::join_all(tasks).await;
            for result in task_results {
                if let Ok(Ok(Some(crawl_result))) = result {
                    to_crawl.extend(crawl_result.links.iter().filter(|link| {
                        Url::parse(link).map_or(false, |u| u.host_str() == Url::parse(&crawl_result.url).map_or(None, |u| u.host_str()))
                    }).cloned());
                    results.push(crawl_result);
                }
            }

            if to_crawl.is_empty() || current_depth == depth {
                break;
            }
        }

        Ok(results)
    }

    async fn crawl_single(url: &str, proxies: Arc<Mutex<Vec<ProxyInfo>>>, user_agents: &[String]) -> Result<Option<CrawlResult>, Box<dyn Error>> {
        let proxy = {
            let proxies_lock = proxies.lock().await;
            proxies_lock.choose(&mut rand::thread_rng()).cloned()
        };

        let client = match proxy {
            Some(ref p) => {
                let proxy_url = format!("{}://{}:{}", p.protocol, p.ip, p.port);
                Client::builder()
                    .proxy(Proxy::all(&proxy_url)?)
                    .timeout(Duration::from_secs(15))
                    .user_agent(user_agents.choose(&mut rand::thread_rng()).unwrap())
                    .build()?
            }
            None => {
                warn!("No proxies available, using direct connection");
                Client::builder()
                    .timeout(Duration::from_secs(15))
                    .user_agent(user_agents.choose(&mut rand::thread_rng()).unwrap())
                    .build()?
            }
        };

        let response = match client.get(url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Failed to crawl {}: {}", url, e);
                return Ok(None);
            }
        };

        let status = response.status().as_u16();
        if !response.status().is_success() {
            debug!("Non-success status {} for {}", status, url);
            return Ok(None);
        }

        let content = response.text().await.unwrap_or_default();
        let document = Html::parse_document(&content);
        let selector = Selector::parse("a[href]").unwrap();
        let links: Vec<String> = document
            .select(&selector)
            .filter_map(|element| element.value().attr("href"))
            .filter_map(|href| Url::parse(href).ok().or_else(|| Url::parse(url).ok().and_then(|base| base.join(href).ok())))
            .map(|u| u.to_string())
            .collect();

        Ok(Some(CrawlResult {
            url: url.to_string(),
            content,
            links,
            status,
        }))
    }
}