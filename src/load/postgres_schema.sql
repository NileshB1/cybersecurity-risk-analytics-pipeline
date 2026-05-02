
-- run this file once before the pipeline starts
-- psql -U postgres -d cybersecurity_db -f load/postgres_schema.sql

--if above command not working, try:

-- psql -h localhost -U postgres -d cybersecurity_db -f load/postgres_schema.sql

--
-- make sure the database exists first, if not run this manually:
-- CREATE DATABASE cybersecurity_db;


-- TABLE 1 : vulnerabilities
-- cleaned CVE records from NVD after transformer runs


CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id  VARCHAR(30)   UNIQUE NOT NULL, -- e.g. CVE-2023-44487
    severity NUMERIC(4,1), -- CVSS score, 0.0 to 10.0
    vendor  VARCHAR(255),
    publish_date DATE,
    modified_date DATE,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- TABLE 2 : exploited_vulnerabilities
-- only CVEs that are confirmed exploited in real attacks

CREATE TABLE IF NOT EXISTS exploited_vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30)  UNIQUE NOT NULL,
    vendor VARCHAR(255),
    product VARCHAR(255),
    vulnerability_name TEXT,
    exploitation_date DATE,
    required_action TEXT,  -- what orgs should do to fix
    created_at TIMESTAMP DEFAULT NOW()
);

-- TABLE 3 : breaches
-- breach incidents scraped from privacyrights.org

CREATE TABLE IF NOT EXISTS breaches (
    id SERIAL PRIMARY KEY,
    organisation VARCHAR(500)  NOT NULL,
    industry VARCHAR(255),
    breach_type VARCHAR(100),
    breach_date   DATE,
    records_exposed BIGINT,       -- yahoo had 3 billion, so needs BIGINT not INT
    state  VARCHAR(100),
    created_at    TIMESTAMP DEFAULT NOW()
);


-- TABLE 4 : industry_summary
-- pre-aggregated - refreshed on every pipeline run


CREATE TABLE IF NOT EXISTS industry_summary (
    industry VARCHAR(255) PRIMARY KEY,
    breach_count INT DEFAULT 0,
    total_records BIGINT DEFAULT 0,
    avg_severity  NUMERIC(4,1),
    updated_at TIMESTAMP DEFAULT NOW()
);



-- INDEXES
-- without indexes the GROUP BY queries on 200k+ rows are too slow

CREATE INDEX IF NOT EXISTS idx_vuln_vendor ON vulnerabilities(vendor);
CREATE INDEX IF NOT EXISTS idx_vuln_publish_date ON vulnerabilities(publish_date);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);

CREATE INDEX IF NOT EXISTS idx_kev_vendor ON exploited_vulnerabilities(vendor);
CREATE INDEX IF NOT EXISTS idx_kev_exploit_date ON exploited_vulnerabilities(exploitation_date);

CREATE INDEX IF NOT EXISTS idx_breach_date ON breaches(breach_date);
CREATE INDEX IF NOT EXISTS idx_breach_industry ON breaches(industry);
CREATE INDEX IF NOT EXISTS idx_breach_org ON breaches(organisation);

-- composite index
CREATE INDEX IF NOT EXISTS idx_breach_industry_date ON breaches(industry, breach_date);

-- to verify everything created run:
-- SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';