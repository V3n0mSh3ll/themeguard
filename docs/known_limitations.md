# ThemeGuard Known Limitations

## Detection Limitations

### ML Classifier
- Uses statistical heuristics, not a trained neural network
- No labeled training/validation dataset exists yet
- Precision/recall/F1 metrics not yet published
- Best described as "intelligent risk scoring" rather than "AI/ML detection"
- May underperform on novel, previously unseen obfuscation techniques

### Static Analysis Only
- No dynamic execution or sandboxing of PHP code
- Cannot detect runtime-only behaviors (e.g., time-delayed payloads)
- Cannot follow external includes (`include('http://...')`)
- Cannot evaluate variable-dependent control flow

### PHP Analysis
- Regex-based, not full AST parsing
- May produce false positives inside string literals and comments
- Complex multi-file taint flows may be missed
- Does not handle PHP namespaces, traits, or closures deeply

### Cloud Intelligence
- URLhaus and WPScan are the only integrated providers
- No VirusTotal, AbuseIPDB, or OTX integration yet
- API rate limits apply (especially WPScan without API key)
- Offline mode returns no intelligence, does not fail scan

## False Positive Sources

| Source | Mitigation |
|--------|------------|
| Minified JS (long lines, high entropy) | Suppressed if .min.js extension |
| Vendor libraries (eval in legitimate code) | Vendor path suppression |
| WordPress core files (complex patterns) | Known-safe path list |
| Base64 in legitimate plugins (API keys, fonts) | Confidence scoring reduces severity |
| Composer autoloader (dynamic includes) | Vendor directory skip |

## Performance Limitations

- Single-machine, single-process design
- No distributed scanning support
- Scan cache uses file mtime+size (not content hash) — renamed files without content change may re-scan
- SQLite evidence store not tested beyond 100K findings
- Memory-mapped reading limited to 2MB files (larger files skipped)

## Real-time Protection

- Polling-based, not kernel event-driven (no watchdog/inotify)
- Minimum effective poll interval: 2 seconds
- Event storm throttling may delay detection during bulk operations
- Auto-block sets read-only permissions only, does not quarantine
- No OS-level agent/daemon hardening (not a rootkit-resistant EDR)

## Quarantine

- SHA-256 verification on restore, but no cryptographic signing of manifest
- Audit trail is append-only JSON (not tamper-evident chain)
- No encryption of quarantined files
- Restore requires same filesystem permissions as quarantine

## Scale

- Tested up to ~10K files
- 50K-100K file benchmarks not yet documented
- No 24-hour soak test results published
- Watch mode not validated for extended runs (>6 hours)

## Integration

- CLI-only, no web dashboard
- No webhook/SIEM output (JSON export available)
- No scheduled scan built-in (use OS cron/task scheduler)
- No central management for multi-site deployments

## Reporting

- Triage report is text-only, not HTML
- SARIF output available but may not cover all finding types
- No visual timeline or graph output
- Correlation labels are auto-generated, not curated
