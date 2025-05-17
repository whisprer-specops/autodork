// Optimized implementation for the quantum engine core
// src/engine.rs

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Write, Read, BufWriter, BufReader};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;

use tokio::sync::Mutex;
use num_complex::Complex;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
use flate2::Compression;

use crate::tokenizer::{tokenize, extract_keywords};
use crate::prime_hilbert::{PrimeVector, BiorthogonalVector, build_vector, 
                          dot_product, build_biorthogonal_vector, resonance_complex, 
                          biorthogonal_score};
use crate::entropy::{shannon_entropy, calculate_reversibility, entropy_pressure, 
                   buffering_capacity, persistence_score};
use crate::crawler::CrawledDocument;
use crate::quantum_types::{MatrixComplex, trace, create_hamiltonian, create_dissipator};

// Maximum cache size for recently accessed docs
const MAX_DECOMPRESSED_CACHE: usize = 100;

/// Search result with scoring information
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub title: String,
    pub path: String,
    pub resonance: f64,
    pub delta_entropy: f64,
    pub score: f64,
    pub quantum_score: f64,
    pub persistence_score: f64,
    pub snippet: String,
}

/// Document representation optimized for memory usage
struct Document {
    id: usize,
    title: String,
    path: String,
    // Raw text is either stored directly or compressed
    text: String,
    compressed_text: Option<Vec<u8>>,
    // Token information
    token_stream: Vec<u64>,
    prime_vector: PrimeVector,
    biorthogonal_vector: Option<BiorthogonalVector>,
    // Entropy metrics
    base_entropy: f64,
    current_entropy: f64,
    // Quantum state information
    quantum_state: Option<MatrixComplex<f64>>,
    // Persistence metrics
    reversibility: f64,
    buffering: f64,
    // Metadata
    last_accessed: u64,  // For LRU cache
    modified: bool,      // Track when document needs saving
}

impl Document {
    /// Create a new document from raw text
    fn new(id: usize, title: String, path: String, text: String) -> Self {
        // Extract token stream
        let token_stream = tokenize(&text);
        
        // Calculate base entropy
        let base_entropy = shannon_entropy(&token_stream);
        
        // Create prime vector representation
        let prime_vector = build_vector(&token_stream);
        
        Document {
            id,
            title,
            path,
            text,
            compressed_text: None,
            token_stream,
            prime_vector,
            biorthogonal_vector: None,
            base_entropy,
            current_entropy: base_entropy,
            quantum_state: None,
            reversibility: 1.0,   // Start with perfect reversibility
            buffering: 0.5,       // Default buffering capacity
            last_accessed: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            modified: false,
        }
    }
    
    /// Compress the document text to save memory
    fn compress(&mut self) {
        if !self.text.is_empty() && self.compressed_text.is_none() {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            if encoder.write_all(self.text.as_bytes()).is_ok() {
                if let Ok(compressed) = encoder.finish() {
                    self.compressed_text = Some(compressed);
                    // Only clear text if compression succeeds
                    self.text.clear();
                    self.modified = true;
                }
            }
        }
    }
    
    /// Decompress the document text when needed
    fn decompress(&mut self) {
        if self.text.is_empty() && self.compressed_text.is_some() {
            if let Some(compressed) = &self.compressed_text {
                let mut decoder = GzDecoder::new(&compressed[..]);
                let mut text = String::new();
                
                if decoder.read_to_string(&mut text).is_ok() {
                    self.text = text;
                    // Don't remove compressed text to avoid recompressing
                }
            }
        }
        
        // Update last accessed time for LRU caching
        self.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
    
    /// Initialize quantum state for the document
    fn init_quantum_state(&mut self) {
        if self.quantum_state.is_none() {
            // Create a density matrix from the document's token frequencies
            let dim = 10; // Use a fixed dimensionality for all documents
            let mut state = MatrixComplex::<f64>::zeros(dim, dim);
            
            // Initialize with a mixture based on token frequencies
            for (i, &prime) in self.token_stream.iter().take(dim).enumerate() {
                let weight = *self.prime_vector.get(&prime).unwrap_or(&0.0);
                state[(i, i)] = Complex::new(weight, 0.0);
            }
            
            // Normalize the state
            let tr = trace(&state).re;
            if tr > 0.0 {
                for i in 0..dim {
                    for j in 0..dim {
                        state[(i, j)] = state[(i, j)] / Complex::new(tr, 0.0);
                    }
                }
            }
            
            self.quantum_state = Some(state);
            self.modified = true;
        }
    }
    
    /// Create or update biorthogonal representation
    fn ensure_biorthogonal(&mut self) {
        if self.biorthogonal_vector.is_none() {
            self.biorthogonal_vector = Some(build_biorthogonal_vector(&self.token_stream));
            self.modified = true;
        }
    }
    
    /// Generate a snippet for search results
    fn generate_snippet(&mut self, query_terms: &[&str], max_length: usize) -> String {
        self.decompress();
        
        // Start with a simple algorithm that looks for sentences containing query terms
        let sentences: Vec<&str> = self.text.split(['.', '!', '?']).collect();
        
        // Score sentences by how many query terms they contain
        let mut scored_sentences: Vec<(usize, &str)> = sentences
            .iter()
            .map(|&sentence| {
                let score = query_terms.iter()
                    .filter(|&term| sentence.to_lowercase().contains(&term.to_lowercase()))
                    .count();
                (score, sentence)
            })
            .filter(|&(score, _)| score > 0)
            .collect();
        
        // Sort by score descending
        scored_sentences.sort_by(|a, b| b.0.cmp(&a.0));
        
        // Take best sentence(s) up to max_length
        let mut snippet = String::new();
        for (_, sentence) in scored_sentences.iter().take(3) {
            let trimmed = sentence.trim();
            if !trimmed.is_empty() {
                if !snippet.is_empty() {
                    snippet.push_str(" ");
                }
                snippet.push_str(trimmed);
                snippet.push_str(".");
                
                if snippet.len() > max_length {
                    break;
                }
            }
        }
        
        // If we couldn't find a good sentence, just take the beginning
        if snippet.is_empty() {
            snippet = self.text.chars().take(max_length).collect();
            if snippet.len() < self.text.len() {
                snippet.push_str("...");
            }
        }
        
        // For efficiency, we should compress the text if possible
        if !self.text.is_empty() && self.compressed_text.is_some() {
            self.text.clear();
        }
        
        snippet
    }
    
    /// Apply a quantum jump to update document state
    fn apply_quantum_jump(&mut self, query_vector: &PrimeVector, importance: f64) {
        if let Some(state) = &mut self.quantum_state {
            // Create a jump operator based on the query
            let jump_operator = create_hamiltonian(query_vector, importance);
            
            // Apply the jump
            let new_state = &jump_operator * state * &jump_operator.adjoint();
            
            // Normalize
            let tr = trace(&new_state).re;
            if tr > 0.0 {
                for i in 0..new_state.nrows() {
                    for j in 0..new_state.ncols() {
                        new_state[(i, j)] = new_state[(i, j)] / Complex::new(tr, 0.0);
                    }
                }
            }
            
            *state = new_state;
            
            // Update entropy and reversibility
            self.current_entropy = shannon_entropy(&self.token_stream);
            self.reversibility *= 0.95 + 0.05 * dot_product(query_vector, &self.prime_vector);
            self.modified = true;
        }
    }
}

/// The main resonant search engine
pub struct ResonantEngine {
    docs: Vec<Document>,
    decompressed_count: usize,
    next_id: usize,
    use_quantum_score: bool,
    use_persistence_score: bool,
    entropy_weight: f64,
    fragility: f64,
}

impl ResonantEngine {
    /// Create a new resonant search engine
    pub fn new() -> Self {
        ResonantEngine {
            docs: Vec::new(),
            decompressed_count: 0,
            next_id: 0,
            use_quantum_score: false,
            use_persistence_score: false,
            entropy_weight: 0.1,
            fragility: 0.2,
        }
    }
    
    /// Enable or disable quantum scoring
    pub fn set_use_quantum_score(&mut self, enable: bool) {
        self.use_quantum_score = enable;
        
        // Initialize quantum states if enabled
        if enable {
            for doc in &mut self.docs {
                doc.init_quantum_state();
            }
        }
    }
    
    /// Enable or disable persistence scoring
    pub fn set_use_persistence_score(&mut self, enable: bool) {
        self.use_persistence_score = enable;
    }
    
    /// Set the entropy weight parameter
    pub fn set_entropy_weight(&mut self, weight: f64) {
        self.entropy_weight = weight.max(0.0).min(1.0);
    }
    
    /// Set the fragility parameter for persistence theory
    pub fn set_fragility(&mut self, fragility: f64) {
        self.fragility = fragility.max(0.0).min(1.0);
    }
    
    /// Get the number of documents in the index
    pub fn len(&self) -> usize {
        self.docs.len()
    }
    
    /// Check if the index is empty
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }
    
    /// Add a document from text
    pub fn add_document(&mut self, title: String, path: String, text: String) {
        let id = self.next_id;
        self.next_id += 1;
        
        let mut doc = Document::new(id, title, path, text);
        
        // Initialize quantum state if needed
        if self.use_quantum_score {
            doc.init_quantum_state();
        }
        
        // Initialize biorthogonal representation if needed
        if self.use_quantum_score {
            doc.ensure_biorthogonal();
        }
        
        self.docs.push(doc);
        self.decompressed_count += 1;
        
        // Manage memory by compressing older documents
        self.manage_memory();
    }
    
    /// Add a document from a crawler
    pub fn add_crawled_document(&mut self, crawled: CrawledDocument) {
        self.add_document(crawled.title, crawled.url, crawled.text);
    }
    
    /// Manage memory by compressing documents
    fn manage_memory(&mut self) {
        // If we have too many decompressed documents, compress older ones
        if self.decompressed_count > MAX_DECOMPRESSED_CACHE {
            // Sort docs by last accessed time
            self.docs.sort_by(|a, b| a.last_accessed.cmp(&b.last_accessed));
            
            // Compress older documents
            let to_compress = self.decompressed_count - MAX_DECOMPRESSED_CACHE;
            for i in 0..to_compress {
                if !self.docs[i].text.is_empty() {
                    self.docs[i].compress();
                    self.decompressed_count -= 1;
                }
            }
            
            // Resort by ID to maintain stable order
            self.docs.sort_by(|a, b| a.id.cmp(&b.id));
        }
    }
    
    /// Compress all documents to save memory
    pub fn compress_all_documents(&mut self) {
        for doc in &mut self.docs {
            if !doc.text.is_empty() {
                doc.compress();
            }
        }
        self.decompressed_count = 0;
    }
    
    /// Search for documents that match a query
    pub fn search(&mut self, query: &str, max_results: usize) -> Vec<SearchResult> {
        // Extract query tokens and create vector
        let query_terms: Vec<&str> = extract_keywords(query);
        let query_tokens = tokenize(query);
        let query_vector = build_vector(&query_tokens);
        
        // For quantum scoring, create biorthogonal representation
        let query_biorthogonal = if self.use_quantum_score {
            Some(build_biorthogonal_vector(&query_tokens))
        } else {
            None
        };
        
        // Create a thread-safe results collector
        let results_mutex = Arc::new(Mutex::new(Vec::new()));
        
        // Process documents in parallel
        let handles: Vec<_> = self.docs.iter_mut().map(|doc| {
            let query_vector = query_vector.clone();
            let query_biorthogonal = query_biorthogonal.clone();
            let query_terms = query_terms.clone();
            let entropy_weight = self.entropy_weight;
            let fragility = self.fragility;
            let use_quantum = self.use_quantum_score;
            let use_persistence = self.use_persistence_score;
            let results = Arc::clone(&results_mutex);
            
            tokio::spawn(async move {
                // Calculate resonance (similarity)
                let resonance = dot_product(&query_vector, &doc.prime_vector);
                
                // Calculate entropy delta
                let delta_entropy = doc.current_entropy - doc.base_entropy;
                
                // Calculate standard score (resonance - entropy_penalty)
                let score = resonance - entropy_weight * delta_entropy;
                
                // Calculate quantum score if enabled
                let quantum_score = if use_quantum {
                    // Ensure biorthogonal representation
                    doc.ensure_biorthogonal();
                    
                    if let (Some(doc_bio), Some(query_bio)) = (&doc.biorthogonal_vector, &query_biorthogonal) {
                        // Use biorthogonal scoring
                        let bio_score = biorthogonal_score(query_bio, doc_bio);
                        
                        // Add complex resonance
                        let complex_res = resonance_complex(&query_vector, &doc.prime_vector, delta_entropy);
                        let complex_score = complex_res.norm();
                        
                        // Combine scores
                        0.7 * bio_score + 0.3 * complex_score
                    } else {
                        0.0
                    }
                } else {
                    0.0
                };
                
                // Calculate persistence score if enabled
                let persistence_score = if use_persistence {
                    // Calculate entropy pressure
                    let pressure = entropy_pressure(0.1, 0.05, delta_entropy.abs());
                    
                    // Calculate persistence score
                    persistence_score(doc.reversibility, pressure, doc.buffering, fragility)
                } else {
                    0.0
                };
                
                // Generate snippet
                let snippet = doc.generate_snippet(&query_terms, 150);
                
                // Create the result
                let result = SearchResult {
                    title: doc.title.clone(),
                    path: doc.path.clone(),
                    resonance,
                    delta_entropy,
                    score,
                    quantum_score,
                    persistence_score,
                    snippet,
                };
                
                // Add to results
                let mut results = results.lock().await;
                results.push(result);
            })
        }).collect();
        
        // Wait for all document processing to complete
        futures::executor::block_on(async {
            for handle in handles {
                let _ = handle.await;
            }
        });
        
        // Sort results by combined score
        let mut results = Arc::try_unwrap(results_mutex)
            .unwrap_or_else(|_| panic!("Failed to unwrap Arc"))
            .into_inner();
        
        results.sort_by(|a, b| {
            // Calculate combined score based on what's enabled
            let a_combined = if self.use_quantum_score && self.use_persistence_score {
                a.score * 0.5 + a.quantum_score * 0.25 + a.persistence_score * 0.25
            } else if self.use_quantum_score {
                a.score * 0.7 + a.quantum_score * 0.3
            } else if self.use_persistence_score {
                a.score * 0.7 + a.persistence_score * 0.3
            } else {
                a.score
            };
            
            let b_combined = if self.use_quantum_score && self.use_persistence_score {
                b.score * 0.5 + b.quantum_score * 0.25 + b.persistence_score * 0.25
            } else if self.use_quantum_score {
                b.score * 0.7 + b.quantum_score * 0.3
            } else if self.use_persistence_score {
                b.score * 0.7 + b.persistence_score * 0.3
            } else {
                b.score
            };
            
            // Sort descending
            b_combined.partial_cmp(&a_combined).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Return top results
        results.truncate(max_results);
        results
    }
    
    /// Apply a quantum jump to update document states based on a query
    pub fn apply_quantum_jump(&mut self, query: &str, importance: f64) {
        if self.use_quantum_score {
            // Create query vector
            let query_tokens = tokenize(query);
            let query_vector = build_vector(&query_tokens);
            
            // Apply jump to all documents
            for doc in &mut self.docs {
                doc.apply_quantum_jump(&query_vector, importance);
            }
        }
    }
    
    /// Get the top documents by score
    pub fn get_top_documents(&self, count: usize) -> Vec<SearchResult> {
        let mut results = Vec::new();
        
        for doc in &self.docs {
            // Use standard score
            results.push(SearchResult {
                title: doc.title.clone(),
                path: doc.path.clone(),
                resonance: 1.0,  // Just use 1.0 as default since we're not comparing to a query
                delta_entropy: doc.current_entropy - doc.base_entropy,
                score: 1.0 - self.entropy_weight * (doc.current_entropy - doc.base_entropy),
                quantum_score: 0.0,
                persistence_score: 0.0,
                snippet: String::new(), // Empty snippet since we're not comparing to query
            });
        }
        
        // Sort by score
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        
        // Return top results
        results.truncate(count);
        
        // Generate snippets for these results
        for (i, result) in results.iter_mut().enumerate() {
            if i < self.docs.len() {
                let doc = &mut self.docs[i];
                let snippet = doc.generate_snippet(&["the", "a", "an"], 150); // Generic terms
                result.snippet = snippet;
            }
        }
        
        results
    }
    
    /// Save the current state to a checkpoint file
    pub fn save_checkpoint(&mut self, path: &str) -> io::Result<()> {
        // Create directories if they don't exist
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        
        // Write header with metadata
        writeln!(writer, "# OmniDork Checkpoint")?;
        writeln!(writer, "# Version: 1.0")?;
        writeln!(writer, "# Documents: {}", self.docs.len())?;
        writeln!(writer, "# NextID: {}", self.next_id)?;
        writeln!(writer, "# UseQuantum: {}", self.use_quantum_score)?;
        writeln!(writer, "# UsePersistence: {}", self.use_persistence_score)?;
        writeln!(writer, "# EntropyWeight: {}", self.entropy_weight)?;
        writeln!(writer, "# Fragility: {}", self.fragility)?;
        
        // Write documents
        for doc in &mut self.docs {
            // Ensure document is compressed
            if !doc.text.is_empty() {
                doc.compress();
            }
            
            // Write document header
            writeln!(writer, "DOC\t{}\t{}\t{}", doc.id, doc.title, doc.path)?;
            
            // Write base entropy and current entropy
            writeln!(writer, "ENTROPY\t{}\t{}", doc.base_entropy, doc.current_entropy)?;
            
            // Write reversibility and buffering
            writeln!(writer, "PERSISTENCE\t{}\t{}", doc.reversibility, doc.buffering)?;
            
            // Write token stream (compressed with run-length encoding for efficiency)
            write!(writer, "TOKENS")?;
            let mut current_token = 0;
            let mut count = 0;
            
            for &token in &doc.token_stream {
                if token == current_token && count > 0 {
                    count += 1;
                } else {
                    if count > 0 {
                        write!(writer, "\t{}:{}", current_token, count)?;
                    }
                    current_token = token;
                    count = 1;
                }
            }
            
            if count > 0 {
                write!(writer, "\t{}:{}", current_token, count)?;
            }
            writeln!(writer)?;
            
            // Write compressed text if available
            if let Some(compressed) = &doc.compressed_text {
                let encoded = base64::encode(compressed);
                writeln!(writer, "COMPRESSED\t{}", encoded)?;
            }
            
            // Write end of document marker
            writeln!(writer, "ENDDOC")?;
        }
        
        Ok(())
    }
    
    /// Load state from a checkpoint file
    pub fn load_checkpoint(&mut self, path: &str) -> io::Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        self.docs.clear();
        self.decompressed_count = 0;
        
        let mut current_doc: Option<Document> = None;
        
        for line in reader.lines() {
            let line = line?;
            
            if line.starts_with('#') {
                // Parse metadata
                if line.starts_with("# NextID:") {
                    if let Some(id_str) = line.strip_prefix("# NextID:") {
                        if let Ok(id) = id_str.trim().parse::<usize>() {
                            self.next_id = id;
                        }
                    }
                } else if line.starts_with("# UseQuantum:") {
                    if let Some(use_quantum) = line.strip_prefix("# UseQuantum:") {
                        self.use_quantum_score = use_quantum.trim() == "true";
                    }
                } else if line.starts_with("# UsePersistence:") {
                    if let Some(use_persistence) = line.strip_prefix("# UsePersistence:") {
                        self.use_persistence_score = use_persistence.trim() == "true";
                    }
                } else if line.starts_with("# EntropyWeight:") {
                    if let Some(weight_str) = line.strip_prefix("# EntropyWeight:") {
                        if let Ok(weight) = weight_str.trim().parse::<f64>() {
                            self.entropy_weight = weight;
                        }
                    }
                } else if line.starts_with("# Fragility:") {
                    if let Some(fragility_str) = line.strip_prefix("# Fragility:") {
                        if let Ok(fragility) = fragility_str.trim().parse::<f64>() {
                            self.fragility = fragility;
                        }
                    }
                }
            } else if line.starts_with("DOC\t") {
                // Finalize previous document if any
                if let Some(doc) = current_doc.take() {
                    self.docs.push(doc);
                }
                
                // Parse new document header
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 4 {
                    if let Ok(id) = parts[1].parse::<usize>() {
                        let title = parts[2].to_string();
                        let path = parts[3].to_string();
                        
                        // Create new document with placeholder values
                        current_doc = Some(Document {
                            id,
                            title,
                            path,
                            text: String::new(),
                            compressed_text: None,
                            token_stream: Vec::new(),
                            prime_vector: HashMap::new(),
                            biorthogonal_vector: None,
                            base_entropy: 0.0,
                            current_entropy: 0.0,
                            quantum_state: None,
                            reversibility: 1.0,
                            buffering: 0.5,
                            last_accessed: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            modified: false,
                        });
                    }
                }
            } else if line.starts_with("ENTROPY\t") && current_doc.is_some() {
                // Parse entropy values
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 3 {
                    if let (Ok(base), Ok(current)) = (parts[1].parse::<f64>(), parts[2].parse::<f64>()) {
                        if let Some(doc) = &mut current_doc {
                            doc.base_entropy = base;
                            doc.current_entropy = current;
                        }
                    }
                }
            } else if line.starts_with("PERSISTENCE\t") && current_doc.is_some() {
                // Parse persistence values
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 3 {
                    if let (Ok(rev), Ok(buf)) = (parts[1].parse::<f64>(), parts[2].parse::<f64>()) {
                        if let Some(doc) = &mut current_doc {
                            doc.reversibility = rev;
                            doc.buffering = buf;
                        }
                    }
                }
            } else if line.starts_with("TOKENS") && current_doc.is_some() {
                // Parse token stream (run-length decoded)
                let parts: Vec<&str> = line.split('\t').collect();
                let mut tokens = Vec::new();
                
                for i in 1..parts.len() {
                    let token_part = parts[i];
                    if let Some(colon_pos) = token_part.find(':') {
                        if let (Ok(token), Ok(count)) = (
                            token_part[..colon_pos].parse::<u64>(),
                            token_part[colon_pos+1..].parse::<usize>()
                        ) {
                            tokens.extend(std::iter::repeat(token).take(count));
                        }
                    }
                }
                
                if let Some(doc) = &mut current_doc {
                    doc.token_stream = tokens;
                    doc.prime_vector = build_vector(&doc.token_stream);
                }
            } else if line.starts_with("COMPRESSED\t") && current_doc.is_some() {
                // Parse compressed text
                if let Some(encoded) = line.strip_prefix("COMPRESSED\t") {
                    if let Ok(compressed) = base64::decode(encoded) {
                        if let Some(doc) = &mut current_doc {
                            doc.compressed_text = Some(compressed);
                        }
                    }
                }
            } else if line == "ENDDOC" && current_doc.is_some() {
                // Finalize document
                if let Some(doc) = current_doc.take() {
                    self.docs.push(doc);
                }
            }
        }
        
        // Add the last document if any
        if let Some(doc) = current_doc {
            self.docs.push(doc);
        }
        
        // Initialize quantum states if needed
        if self.use_quantum_score {
            for doc in &mut self.docs {
                if doc.quantum_state.is_none() {
                    doc.init_quantum_state();
                }
            }
        }
        
        println!("Loaded {} documents from checkpoint", self.docs.len());
        
        Ok(())
    }
    
    /// Export the index to a CSV file for external analysis
    pub fn export_index(&self, path: &str) -> io::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        
        // Write CSV header
        writeln!(writer, "id,title,path,base_entropy,current_entropy,token_count,reversibility,buffering")?;
        
        // Write document data
        for doc in &self.docs {
            writeln!(writer, "{},{},{},{},{},{},{},{}",
                    doc.id,
                    csv_escape(&doc.title),
                    csv_escape(&doc.path),
                    doc.base_entropy,
                    doc.current_entropy,
                    doc.token_stream.len(),
                    doc.reversibility,
                    doc.buffering)?;
        }
        
        Ok(())
    }
}

/// Helper function to escape strings for CSV
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_document_compression() {
        let mut doc = Document::new(
            1,
            "Test Document".to_string(),
            "http://example.com".to_string(),
            "This is a test document with some content to compress".to_string()
        );
        
        // Verify initial state
        assert!(!doc.text.is_empty());
        assert!(doc.compressed_text.is_none());
        
        // Compress the document
        doc.compress();
        
        // Verify compressed state
        assert!(doc.text.is_empty());
        assert!(doc.compressed_text.is_some());
        
        // Decompress the document
        doc.decompress();
        
        // Verify decompressed state
        assert!(!doc.text.is_empty());
        assert_eq!(doc.text, "This is a test document with some content to compress");
    }
    
    #[test]
    fn test_search_relevance() {
        let mut engine = ResonantEngine::new();
        
        // Add some test documents
        engine.add_document(
            "Document about quantum physics".to_string(),
            "http://example.com/quantum".to_string(),
            "Quantum physics is a fundamental theory in physics that describes nature at the smallest scales of energy levels of atoms and subatomic particles.".to_string()
        );
        
        engine.add_document(
            "Document about classical physics".to_string(),
            "http://example.com/classical".to_string(),
            "Classical physics refers to theories of physics that predate modern, more complete, or more widely applicable theories.".to_string()
        );
        
        // Search for quantum-related documents
        let results = engine.search("quantum particles theory", 10);
        
        // Verify that the quantum document is ranked higher
        assert!(!results.is_empty());
        assert_eq!(results[0].title, "Document about quantum physics");
    }
    
    #[test]
    fn test_quantum_jumps() {
        let mut engine = ResonantEngine::new();
        engine.set_use_quantum_score(true);
        
        // Add test documents
        engine.add_document(
            "Document about cats".to_string(),
            "http://example.com/cats".to_string(),
            "Cats are small carnivorous mammals that are domesticated and kept as pets.".to_string()
        );
        
        engine.add_document(
            "Document about dogs".to_string(),
            "http://example.com/dogs".to_string(),
            "Dogs are domesticated mammals, not natural wild animals. They were originally bred from wolves.".to_string()
        );
        
        // Apply a quantum jump related to cats
        engine.apply_quantum_jump("cats pets feline", 0.5);
        
        // Search for pets
        let results = engine.search("pets", 10);
        
        // Verify that the cats document is ranked higher due to the quantum jump
        assert!(!results.is_empty());
        assert_eq!(results[0].title, "Document about cats");
    }
}
