# OmniDork: Integration Overview

This document provides a summary of how all components in OmniDork work together to create a cohesive and powerful tool for security reconnaissance, vulnerability discovery, and quantum-enhanced search.

## Module Integration Map

```
┌───────────────────────────────────────────────────────────────────┐
│                           Main Program                            │
│                            (main.rs)                              │
└─────────────────┬─────────────────────────────────┬───────────────┘
                  │                                 │
                  ▼                                 ▼
┌───────────────────────────────┐    ┌───────────────────────────────┐
│     OSINT & Vulnerability     │    │    Quantum Search Engine      │
│        (dork_engine.rs)       │    │        (engine.rs)            │
└────────────┬─────────┬────────┘    └────────────┬────────┬─────────┘
             │         │                          │        │
             ▼         ▼                          ▼        ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│ Vulnerability  │ │ Bug Bounty     │ │ Tokenizer      │ │ Entropy &      │
│ Matcher        │ │ Matcher        │ │ (tokenizer.rs) │ │ Persistence    │
│                │ │                │ │                │ │ (entropy.rs)    │
└────────────────┘ └────────────────┘ └────────────────┘ └────────────────┘
             ▲                                  ▲
             │                                  │
             │         ┌────────────────┐       │
             └────────►│  Web Crawler   │◄──────┘
                       │  (crawler.rs)  │
                       └────────┬───────┘
                                │
                                ▼
                       ┌────────────────┐
                       │ Proxy Scanner  │
                       │                │
                       └────────────────┘
```

## Data Flow Through the System

### 1. Initialization and Target Selection

- User selects a target domain/URL and operation mode
- `main.rs` coordinates the initialization of required modules
- PostgreSQL database is accessed to check for existing data

### 2. OSINT Phase

- `dork_engine.rs` starts by discovering subdomains
- Google dorks are executed against the target and subdomains
- External services (Shodan, URLScan) are queried for additional info
- JavaScript files are extracted and analyzed
- Cloud storage resources are identified

### 3. Crawling and Indexing Phase

- `crawler.rs` fetches content from discovered URLs
- Raw HTML is processed to extract text and metadata
- Links are followed to discover additional content
- `proxy_scanner.rs` can provide proxies for anonymous crawling

### 4. Quantum Indexing Phase

- `tokenizer.rs` creates prime-based token representations
- `prime_hilbert.rs` builds biorthogonal vectors
- `entropy.rs` calculates information-theoretic metrics
- `engine.rs` manages the indexing and retrieval operations

### 5. Analysis Phase

- `vulnerability_matcher.rs` analyzes all collected content for security issues
- Regex patterns detect potential vulnerabilities
- Content from JavaScript, HTTP responses, and crawled pages is correlated
- Findings are categorized by severity and type

### 6. Matching and Reporting

- `bug_bounty.rs` matches findings to bug bounty programs
- Potential rewards are estimated
- Submission templates are generated
- Comprehensive report is created with all findings

## Key Data Structures

The following data structures allow information to flow through the system:

### 1. DorkResult

This structure represents a single result from a Google dork query:

```rust
struct DorkResult {
    url: String,
    title: String,
    snippet: String,
    content_type: Option<String>,
    found_dork: String,
}
```

### 2. CrawledDocument

This represents a document fetched by the crawler:

```rust
struct CrawledDocument {
    url: String,
    title: String,
    text: String,
}
```

### 3. ProxyInfo

This contains details about a discovered proxy:

```rust
struct ProxyInfo {
    ip: String,
    port: u16,
    protocol: String,
    anonymity: String,
    response_time: f64,
    country: String,
    last_checked: u64,
}
```

### 4. Finding

This represents a security finding:

```rust
struct Finding {
    id: String,
    target_id: String,
    subdomain_id: Option<String>,
    finding_type: String,
    severity: String,
    url: Option<String>,
    description: String,
    discovery_timestamp: u64,
    dork_used: Option<String>,
    screenshot_path: Option<String>,
    has_sensitive_data: bool,
}
```

### 5. PrimeVector and BiorthogonalVector

These quantum-inspired structures represent documents in the search engine:

```rust
type PrimeVector = HashMap<u64, f64>;

struct BiorthogonalVector {
    left: PrimeVector,
    right: PrimeVector,
}
```

## Integration of Quantum Concepts

The quantum aspects of OmniDork are incorporated in these ways:

1. **Document Representation**: Documents are encoded as sparse vectors with prime number keys
2. **Biorthogonal Vectors**: Non-Hermitian quantum mechanics inspires the left/right vector representation
3. **Complex Resonance**: Similarity scores include both amplitude and phase components
4. **Quantum Jumps**: Feedback mechanism updates document states based on search queries
5. **Persistence Theory**: Thermodynamic principles model information stability and relevance

## Integration of Security Features

Security functionality is integrated through:

1. **Comprehensive Dorking**: Specialized dorks for different vulnerability types
2. **Pattern Matching**: Regular expressions identify security issues in HTML, JavaScript, and other content
3. **Service Integration**: Shodan, URLScan, and DNS data provide additional attack surface information
4. **JavaScript Analysis**: Extracted scripts are analyzed for sensitive information like API keys
5. **Cloud Storage Detection**: Specialized dorks identify exposed cloud storage resources

## Integration of Proxy Capabilities

Proxy functionality is integrated by:

1. **Multi-Source Fetching**: Proxies are retrieved from multiple public sources
2. **Concurrent Validation**: Asynchronous testing validates proxies efficiently
3. **Anonymity Classification**: Proxies are categorized as elite, anonymous, or transparent
4. **Speed Testing**: Performance metrics help select the fastest proxies
5. **Crawler Integration**: Validated proxies can be used for anonymous crawling

## Database Integration

All components save their results to a PostgreSQL database with the following schema:

```sql
CREATE TABLE targets (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL,
    first_scan_timestamp TIMESTAMP NOT NULL,
    last_scan_timestamp TIMESTAMP NOT NULL
);

CREATE TABLE subdomains (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    subdomain TEXT NOT NULL,
    first_discovered TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    ip_address TEXT,
    http_status INTEGER,
    https_enabled BOOLEAN
);

CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    subdomain_id INTEGER REFERENCES subdomains(id),
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    url TEXT,
    description TEXT,
    discovery_timestamp TIMESTAMP NOT NULL,
    dork_used TEXT,
    screenshot_path TEXT,
    has_sensitive_data BOOLEAN
);
```

## Visualization Integration

OmniDork generates several types of visualizations:

1. **Network Graph**: Shows relationships between domains, subdomains, and discovered assets
2. **Vulnerability Timeline**: Displays the discovery of vulnerabilities over time
3. **Attack Surface Heatmap**: Shows concentration of potential vulnerabilities
4. **Proxy Distribution Map**: Illustrates geographic distribution of discovered proxies

## Full Integrated Workflow

A complete integrated scan performs these steps in sequence:

1. **Target Selection**: User enters a domain to analyze
2. **Subdomain Discovery**: Finding related subdomains through various techniques
3. **Dork Execution**: Running specialized Google dorks against all discovered domains
4. **External Services**: Querying Shodan, URLScan, and DNS services
5. **JavaScript Analysis**: Extracting and examining JavaScript files
6. **Cloud Storage Check**: Looking for exposed cloud storage buckets
7. **Proxy Discovery**: Finding and validating anonymous proxies
8. **Quantum Crawling**: Using the crawler to index content with quantum representations
9. **Vulnerability Analysis**: Analyzing all gathered data for security issues
10. **Bug Bounty Matching**: Finding relevant bug bounty programs
11. **Reporting**: Generating comprehensive reports in multiple formats

## Extension and Customization

The integrated architecture allows for easy extension:

1. **New Dork Categories**: Add specialized dorks for new vulnerability types
2. **Custom Regexes**: Define new patterns for vulnerability detection
3. **Additional APIs**: Integrate with more security services
4. **Quantum Enhancements**: Experiment with different quantum-inspired algorithms
5. **Custom Proxies**: Add new proxy sources or validation techniques

## Resource Management

The system efficiently manages resources:

1. **Document Compression**: Compressed storage of crawled content
2. **Checkpoint System**: Ability to pause and resume operations
3. **Concurrent Processing**: Parallel execution of tasks when possible
4. **Rate Limiting**: Polite behavior towards search engines and APIs
5. **Memory Management**: Dynamic compression of rarely-accessed data

## Conclusion

OmniDork's power comes from the tight integration of quantum-inspired search techniques with traditional security reconnaissance tools and proxy discovery mechanisms. This unique combination allows for more intelligent and efficient discovery of vulnerabilities, while the quantum aspects of the system provide superior search capabilities that improve with use.

The modular design makes it easy to extend and customize the system, while the shared data structures ensure that information flows smoothly between all components for a unified and coherent user experience.
