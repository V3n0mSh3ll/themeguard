# ThemeGuard Rule Format (.tgr)

## Overview

ThemeGuard uses its own custom rule format (`.tgr` files) instead of YARA. Rules are stored in `rules/` directory.

## Rule Structure

```
rule rule_name : tag1 tag2
{
    meta:
        description = "What this rule detects"
        severity = "critical|high|medium|low"
        author = "author name"
        family = "malware family name"

    strings:
        $text1 = "plain text pattern"
        $regex1 = /regex pattern/i
        $hex1 = { 48 65 6C 6C 6F }
        $wide1 = "text" wide
        $b64 = "text" base64

    condition:
        any of them
        // or: all of them
        // or: $text1 and ($regex1 or $hex1)
        // or: 2 of ($text*)
        // or: #text1 > 3
        // or: filesize < 100KB
}
```

## String Modifiers

| Modifier | Effect |
|----------|--------|
| `wide` | Match UTF-16 encoded strings |
| `fullword` | Match whole word only |
| `nocase` | Case-insensitive match |
| `base64` | Match base64-encoded form |
| `xor` | Match XOR-encoded variants |
| `private` | Don't report this string in output |

## Condition Operators

| Operator | Example |
|----------|---------|
| `and`, `or`, `not` | `$a and $b` |
| `any of them` | Any string matches |
| `all of them` | All strings match |
| `N of them` | At least N strings match |
| `#string > N` | String appears more than N times |
| `@string` | Offset of string |
| `filesize` | File size condition |
| `for..of` | Iterate over string set |

## Rule Directories

- `rules/builtin/` — Default rules shipped with ThemeGuard
- `rules/auto_generated.tgr` — Rules auto-created from scan findings
- `rules/wordpress_deep.tgr` — WordPress-specific threat rules

## Severity Levels

| Level | Meaning |
|-------|---------|
| `critical` | Active backdoor, webshell, confirmed malware |
| `high` | Strong indicators of compromise |
| `medium` | Suspicious patterns requiring review |
| `low` | Informational, possible false positive |
