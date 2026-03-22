# Changelog

## v1.0.0 (2026-03-21)

Initial release.

- 6 scanner modules: pattern engine, obfuscation detector, network intel, integrity checker, file walker, main orchestrator
- 128 detection signatures across 6 categories (PHP backdoors, webshells, crypto miners, SEO spam, obfuscation, file anomalies)
- Shannon entropy analysis for obfuscation detection
- Threaded parallel file scanning
- HTML report (dark theme, severity badges)
- JSON report (CI/CD compatible)
- CLI with severity filtering and exit codes
