# Cybersecurity Risk Analytics Pipeline

This repository contains a semester project pipeline for collecting, integrating, and analyzing cybersecurity risk data from multiple public sources.

## Project Scope

- Extract CVE records from the NVD API
- Extract CISA KEV feed data
- Validate breach source reachability
- Integrate and transform extracted data
- Load curated datasets into MongoDB, PostgreSQL, and graph structures
- Support analytics and dashboard workflows

## Current Progress

- Connection validation suite implemented for:
  - NVD API
  - CISA KEV feed
  - Privacy Rights Clearinghouse reachability
  - MongoDB
  - PostgreSQL
- MongoDB connection handling improved to use environment configuration and explicit ping checks
- PostgreSQL environment validated and project database prepared (`cybersecurity_db`)
- Logging output cleaned for readability in connection test runs

## Repository Structure

- `src/extract/`: data extractors for NVD, KEV, and breach source
- `src/integration/`: merge and integration logic
- `src/transform/`: transformation layer
- `src/load/`: loaders for MongoDB and PostgreSQL
- `src/graph/`: graph loading utilities
- `src/dashboard/`: dashboard application
- `src/test/`: connectivity validation and test utilities

## Run Connection Validation

From `src/`:

```bash
python test/test_connections
```

## Notes

Environment-specific secrets and local virtual environments are intentionally excluded from version control.
