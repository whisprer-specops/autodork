-- Core tables
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

-- Support tables
CREATE TABLE dork_executions (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    dork TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    result_count INTEGER NOT NULL
);

CREATE TABLE bug_bounty_matches (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id),
    platform TEXT NOT NULL,
    program_name TEXT NOT NULL,
    estimated_reward NUMERIC,
    submission_url TEXT
);