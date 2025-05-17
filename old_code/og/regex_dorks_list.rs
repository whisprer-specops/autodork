Complete Dork Library (Regex-Optimized)
Domain Discovery Dorks
rustlet domain_discovery_dorks = vec![
    // Subdomain discovery
    r"site:*.(?P<domain>.*) -www",
    r"site:(?P<domain>.*) inurl:subdomain",
    r"site:(?P<domain>.*) inurl:dev",
    r"site:(?P<domain>.*) inurl:test",
    r"site:(?P<domain>.*) inurl:staging",
    
    // Virtual host discovery
    r"ip:(?P<ip>.*) -site:(?P<domain>.*)",
    
    // Non-standard ports
    r"site:(?P<domain>.*) port:(8080|8443|3000|8000|8081|8888)",
];
Sensitive Content Dorks
rustlet sensitive_content_dorks = vec![
    // Confidential documents
    r"site:(?P<domain>.*) (filetype:pdf|filetype:doc|filetype:docx|filetype:xls|filetype:xlsx) (confidential|internal|private|secret)",
    r"site:(?P<domain>.*) inurl:(internal|private|confidential|secret) ext:(pdf|doc|docx|xls|xlsx)",
    
    // Configuration files
    r"site:(?P<domain>.*) ext:(conf|cfg|config|env|ini|json|xml|yml|yaml)",
    r"site:(?P<domain>.*) (inurl:config|inurl:configuration) ext:(php|txt|xml|json)",
    
    // Backup files
    r"site:(?P<domain>.*) ext:(bak|backup|old|save|swp|temp|tmp)",
    r"site:(?P<domain>.*) inurl:(backup|bak|old|save|archive)",
    
    // Log files
    r"site:(?P<domain>.*) ext:log",
    r"site:(?P<domain>.*) inurl:(log|logs) ext:(txt|log)",
];
Vulnerability Detection Dorks
rustlet vulnerability_dorks = vec![
    // Error pages
    r"site:(?P<domain>.*) (intext:\"sql syntax near\"|intext:\"syntax error has occurred\"|intext:\"incorrect syntax near\"|intext:\"unexpected end of SQL command\"|intext:\"Warning: mysql_fetch_array()\"|intext:\"Error Executing Database Query\"|intext:\"Microsoft OLE DB Provider for ODBC Drivers error\")",
    r"site:(?P<domain>.*) \"Whitelabel Error Page\"",
    r"site:(?P<domain>.*) \"PHP Error\"",
    
    // Admin interfaces
    r"site:(?P<domain>.*) inurl:(admin|cp|dashboard|portal|manage) (intext:username|intext:password|intext:login)",
    r"site:(?P<domain>.*) intitle:(admin|administration|login|backend|cp)",
    
    // Cloud storage
    r"site:s3.amazonaws.com (?P<domain>.*)",
    r"site:(?P<domain>.*) inurl:s3.amazonaws.com",
    r"site:(?P<domain>.*) inurl:r2.dev",
    
    // Framework vulnerabilities
    r"site:(?P<domain>.*) inurl:actuator",
    r"site:(?P<domain>.*) inurl:wp-content",
    r"site:(?P<domain>.*) inurl:phpinfo",
    r"site:(?P<domain>.*) \"Call to undefined function\"",
];
API and Endpoint Dorks
rustlet api_dorks = vec![
    // API endpoints
    r"site:(?P<domain>.*) inurl:api",
    r"site:(?P<domain>.*) (inurl:api/v1|inurl:api/v2|inurl:api/v3)",
    r"site:(?P<domain>.*) inurl:graphql",
    r"site:(?P<domain>.*) inurl:swagger",
    r"site:(?P<domain>.*) inurl:redoc",
    
    // JavaScript endpoints
    r"site:(?P<domain>.*) ext:js (api|endpoint|token|key|secret|password|credentials)",
    r"site:(?P<domain>.*) ext:js (fetch|axios|xhr|ajax)",
    
    // Authentication endpoints
    r"site:(?P<domain>.*) inurl:(oauth|auth|login|signin)",
    r"site:(?P<domain>.*) inurl:(token|jwt|bearer)",
];
