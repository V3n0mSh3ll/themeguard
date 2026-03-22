# ThemeGuard Architecture

## Overview

ThemeGuard is a WordPress-focused static and behavioral malware scanner with recursive payload decoding, confidence scoring, cross-file correlation, optional cloud reputation checks, and real-time watch mode.

## Scan Pipeline (5 Phases)

```
Phase A: Prefilter
  file_walker → prefilter_files → file_classifier
  ↓ skip binaries, prioritize high-risk files

Phase B: Per-File Analysis (parallel, threadpool)
  pattern_engine (Aho-Corasick + regex)
  obfuscation analyzer
  network intel
  integrity checker
  payload decoder
  PHP analyzer + deep scan
  deobfuscator
  threat engine (.tgr rules)
  behavioral scan
  WP deep scan
  WP hardening checks
  C2 + malware family detection
  ML classifier
  recursive decoder (8-depth)
  cloud intel (optional)

Phase C: Directory-Level Scans
  .htaccess analysis
  wp-config.php audit
  polyglot file detection
  infection timeline
  WP core integrity (deep mode)
  auto-rule generation

Phase D: Post-Processing
  deduplication → correlation → confidence scoring → suppression → FP filtering

Phase E: Output
  evidence store (SQLite)
  triage report
  summary
  HTML/JSON/SARIF export
```

## Module Map (30 modules)

| Module | Purpose |
|--------|---------|
| `file_walker.py` | Directory traversal, file enumeration |
| `pattern_engine.py` | Aho-Corasick + regex signature matching |
| `obfuscation.py` | Entropy, encoding chain, chr() detection |
| `network_intel.py` | URL, domain, TLD, IP analysis |
| `integrity.py` | Tampering, core file detection |
| `payload_decoder.py` | Base64, hex, chr chain decode |
| `forensics.py` | File hash, timestamp analysis |
| `php_analyzer.py` | Dangerous function, dropper detection |
| `deobfuscator.py` | Multi-layer deobfuscation |
| `threat_engine.py` | Custom .tgr rule engine |
| `wp_deep_scan.py` | WP hook, cron, nonce, REST API analysis |
| `php_deep_scan.py` | Taint flow, call graph, dead code |
| `wp_hardening.py` | .htaccess, wp-config, session, core integrity |
| `advanced_detect.py` | Polyglot, timeline, C2, malware family |
| `ml_classifier.py` | 26-feature statistical classifier |
| `cloud_intel.py` | URLhaus, WPScan API integration |
| `decoder_recursive.py` | 8-depth recursive payload decoder |
| `file_classifier.py` | Text/binary, vendor, minified classification |
| `deduper.py` | Finding dedup with stable IDs |
| `scorer.py` | Confidence scoring with signal weights |
| `correlation.py` | Cross-file campaign detection |
| `suppression.py` | Path/rule/hash suppression engine |
| `fp_tuner.py` | False positive whitelist and tuning |
| `evidence_store.py` | SQLite scan history and findings DB |
| `triage_report.py` | Actionable triage report generator |
| `perf_optimizer.py` | Scan cache, mmap, prefilter |
| `safe_io.py` | Robust I/O, regex DoS, path safety |
| `quarantine.py` | SHA-256 verified quarantine/restore |
| `watcher.py` | Watch mode with debounce + storm guard |
| `realtime_guard.py` | Daemon with auto-block |

## Data Flow

```
Scan Start
  ├─ Load: signatures, rules, cache, suppressions
  ├─ Classify files (skip binary, prioritize config)
  ├─ Parallel scan (ThreadPoolExecutor)
  │   ├─ Cache check (skip unchanged)
  │   ├─ Read file (mmap for 64KB+, multi-encoding)
  │   ├─ Run 18+ per-file analyzers
  │   └─ Mark cache entry
  ├─ Directory-level scans
  ├─ Dedup → Correlate → Score → Suppress → Filter
  ├─ Store in SQLite
  └─ Generate triage report
```

## Security Properties

- No `eval()` in analysis pipeline
- Regex length limited (2000 chars max)
- Regex search limited (500K chars max)
- Decompression output capped (64KB)
- Recursive decode depth limited (8 levels)
- Symlink escape protection
- Path traversal detection
- Quarantine hash verification on restore
- Tamper detection in quarantine manifest
- Atomic JSON writes (tmp + rename)
