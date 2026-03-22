---
description: Strict professional code standards - NO AI-generated patterns allowed
---

# Code Standards - MANDATORY FOR ALL CODE

Every line of code MUST look like it was written by a senior software engineer with 10+ years of experience. No reviewer should ever suspect AI wrote this code. Follow these rules STRICTLY:

## NO AI Fingerprints

- **ZERO inline comments** like `# Check if X`, `# Loop through Y`, `# Handle Z`
- **ZERO section separators** like `# ---- Section ----` or `# === Block ===`
- **ZERO obvious docstrings** on simple/clear functions. Only add docstrings when the function behavior is genuinely non-obvious
- **ZERO AI-style variable names** like `result_list`, `output_data`, `is_valid_check`
- **ZERO redundant comments** that just repeat what the code does
- **ZERO `"""Description of what this does."""`** on every single function

## Professional Style

- Use **underscore-prefixed names** for module-private constants: `_KNOWN_HASHES`, `_SCAN_LABELS`
- **Pre-compile regex** at module level: `_URL_RE = re.compile(r"...")`
- **Extract helpers** into small private functions: `_check_dropper()`, `_decode_hex_blocks()`
- **PEP8 spacing**: 2 blank lines between top-level functions/classes, 1 blank line between methods
- Keep functions **under 40 lines** - split large logic into helpers
- Use **dict lookups** instead of long if/elif chains
- Use **tuple/set literals** for constant collections

## Code Structure

- Imports at top, grouped: stdlib > third-party > local
- Module-level constants immediately after imports
- Class definitions with proper blank line separation
- Private helpers at bottom of file
- No trailing whitespace, no extra blank lines at end of file

## What Professional Code Looks Like

```python
import re
from collections import Counter

_RISK_WEIGHTS = {
    "code_execution": 10,
    "command_execution": 15,
    "encoding_decoding": 5,
}

_FUNC_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(f) for f in _CATEGORY_MAP) + r")\s*\(",
    re.IGNORECASE,
)


def analyze(content, filename):
    findings = []
    calls, locations = _collect_calls(content)
    if not calls:
        return findings
    _check_combinations(calls, filename, findings)
    _check_risk_score(calls, filename, findings)
    return findings


def _collect_calls(content):
    calls = Counter()
    for match in _FUNC_REGEX.finditer(content):
        calls[match.group(1).lower()] += 1
    return calls
```

## What AI Code Looks Like (NEVER DO THIS)

```python
# Define risk weights for different categories
RISK_WEIGHTS = {
    "code_execution": 10,  # High risk
    "command_execution": 15,  # Very high risk
    "encoding_decoding": 5,  # Medium risk
}

def analyze_php_functions(content, filename):
    """Analyze PHP functions in the content and return findings."""
    findings = []

    # Collect all function calls
    func_calls = Counter()

    # Build regex pattern for matching
    func_pattern = re.compile(r'\b(...)\s*\(', re.IGNORECASE)

    # Iterate through each line
    for i, line in enumerate(lines, 1):
        # Skip comments
        if line.strip().startswith("//"):
            continue
        # Check for matches
        for match in func_pattern.finditer(line):
            fname = match.group(1).lower()
            func_calls[fname] += 1

    # Check for dangerous combinations
    ...
```

## ASCII Only for Terminal Output

- Use `#` and `-` for progress bars (not Unicode block chars)
- Use `=` for separators (not Unicode box drawing)
- Use `[OK]` and `[!]` for status (not Unicode checkmarks/warnings)
- This ensures Windows cmd/PowerShell compatibility

## Apply EVERY TIME

These rules apply to ALL code: Python, JavaScript, PHP, anything. No exceptions. If you catch yourself writing a comment that explains obvious code, DELETE IT.
