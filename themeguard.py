#!/usr/bin/env python3
import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.banner import print_banner
from utils.colors import red, green, yellow, cyan, bold, info, magenta
from utils.rc_config import load_config, create_default_config
from core.scanner import Scanner
from core.history import save_scan, compare_scans, list_scans
from core.quarantine import quarantine_files, restore_files, list_quarantined
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.sarif_report import generate_sarif_report

_SEV_ORDER = ["critical", "high", "medium", "low"]
_OUTPUT_DIR = "reports"
_QUARANTINE_DIR = "quarantine"


def interactive_menu():
    print_banner()
    config = load_config()
    while True:
        _show_menu()
        choice = input(f"  {bold('Select option [0-9]:')} ").strip()
        _handle_choice(choice, config)


def _handle_choice(choice, config):
    dispatch = {
        "0": _exit,
        "1": lambda: _run_scan("theme", False, None, config),
        "2": lambda: _run_scan("theme", True, None, config),
        "3": lambda: _run_scan("theme", True, "both", config),
        "4": lambda: _run_scan("plugin", False, None, config),
        "5": lambda: _run_scan("plugin", True, None, config),
        "6": lambda: _run_scan("plugin", True, "both", config),
        "7": lambda: _run_scan("full", True, None, config),
        "8": lambda: _run_scan("theme", True, None, config, severity="critical"),
        "9": lambda: _run_scan("theme", False, None, config, network=True),
        "10": _watch_mode,
        "11": _quarantine_menu,
        "12": _history_menu,
        "13": _wp_diff_scan,
        "14": lambda: _init_config(config),
        "15": _show_help,
    }

    if choice in dispatch:
        dispatch[choice]()
    else:
        print(red("\n  Invalid option. Try again.\n"))


def _show_menu():
    print(bold("  +-----------------------------------------------+"))
    print(bold("  |           THEMEGUARD SCANNER MENU              |"))
    print(bold("  +-----------------------------------------------+"))
    print()
    print(f"  {bold(cyan('--- THEME SCANNING ---'))}")
    print(f"  {cyan('[1]')}  Quick Theme Scan       {magenta('(fast, common threats)')}")
    print(f"  {cyan('[2]')}  Full Theme Scan        {magenta('(all signatures + threat rules)')}")
    print(f"  {cyan('[3]')}  Theme Scan + Report    {magenta('(HTML + JSON + SARIF)')}")
    print()
    print(f"  {bold(cyan('--- PLUGIN SCANNING ---'))}")
    print(f"  {cyan('[4]')}  Quick Plugin Scan      {magenta('(fast, common threats)')}")
    print(f"  {cyan('[5]')}  Full Plugin Scan       {magenta('(all signatures + threat rules)')}")
    print(f"  {cyan('[6]')}  Plugin Scan + Report   {magenta('(HTML + JSON + SARIF)')}")
    print()
    print(f"  {bold(cyan('--- ADVANCED ---'))}")
    print(f"  {cyan('[7]')}  Full wp-content Scan   {magenta('(themes + plugins at once)')}")
    print(f"  {cyan('[8]')}  Critical Only          {magenta('(show only critical findings)')}")
    print(f"  {cyan('[9]')}  Network Sandbox Scan   {magenta('(URL probing + DNS checks)')}")
    print(f"  {cyan('[10]')} Watch Mode             {magenta('(real-time file monitoring)')}")
    print(f"  {cyan('[11]')} Quarantine Manager     {magenta('(isolate/restore files)')}")
    print(f"  {cyan('[12]')} Scan History           {magenta('(compare past scans)')}")
    print(f"  {cyan('[13]')} WP Diff Check          {magenta('(compare vs official repo)')}")
    print(f"  {cyan('[14]')} Generate Config        {magenta('(create .themeguardrc)')}")
    print(f"  {cyan('[15]')} Help                   {magenta('(CLI usage and examples)')}")
    print(f"  {cyan('[0]')}  Exit")
    print()


def _exit():
    print(green("\n  Goodbye.\n"))
    sys.exit(0)


def _ask_path(label):
    path = input(f"\n  {bold(f'{label} path:')} ").strip().strip("'\"")
    if not path:
        print(red("\n  No path provided.\n"))
        return None
    if not os.path.exists(path):
        print(red(f"\n  Path not found: {path}\n"))
        return None
    return path


def _run_scan(scan_type, deep, report, config, severity=None, network=False):
    label = {"theme": "Theme", "plugin": "Plugin", "full": "wp-content"}.get(scan_type, "Target")
    path = _ask_path(label)
    if not path:
        return

    print()
    scanner = Scanner(path=path, deep=deep, verbosity=1, scan_type=scan_type, network=network)
    scanner.run()
    results = scanner.get_results()

    if severity:
        idx = _SEV_ORDER.index(severity)
        results["findings"] = [f for f in results["findings"] if _SEV_ORDER.index(f.get("severity", "low")) <= idx]
        results["total_findings"] = len(results["findings"])

    comparison = compare_scans(results, path)
    if comparison:
        print(bold("  Scan Comparison vs Previous:"))
        print(green(f"    +{comparison['new_threats']} new   ") +
              red(f"-{comparison['resolved']} resolved   ") +
              cyan(f"={comparison['unchanged']} unchanged"))
        print()

    save_scan(results, path)

    if report in ("html", "both"):
        rpath = generate_html_report(results, _OUTPUT_DIR)
        print(info(f"HTML report:  {bold(rpath)}"))
    if report in ("json", "both"):
        rpath = generate_json_report(results, _OUTPUT_DIR)
        print(info(f"JSON report:  {bold(rpath)}"))
    if report == "both":
        rpath = generate_sarif_report(results, _OUTPUT_DIR)
        print(info(f"SARIF report: {bold(rpath)}"))

    _post_scan_menu(results, path, config)
    print(cyan("\n  Returning to main menu...\n"))


def _post_scan_menu(results, scan_path, config):
    total = results.get("total_findings", 0)
    if total == 0:
        return

    print()
    print(bold("  +-----------------------------------------------+"))
    print(bold("  |             POST-SCAN OPTIONS                  |"))
    print(bold("  +-----------------------------------------------+"))
    print()
    print(f"  {cyan('[1]')} Generate HTML report")
    print(f"  {cyan('[2]')} Generate JSON report")
    print(f"  {cyan('[3]')} Generate SARIF report")
    print(f"  {cyan('[4]')} Generate all reports")
    print(f"  {cyan('[5]')} Quarantine threats (critical + high)")
    print(f"  {cyan('[0]')} Skip")
    print()
    choice = input(f"  {bold('Select [0-5]:')} ").strip()

    if choice == "1":
        rpath = generate_html_report(results, _OUTPUT_DIR)
        print(info(f"HTML report: {bold(rpath)}"))
    elif choice == "2":
        rpath = generate_json_report(results, _OUTPUT_DIR)
        print(info(f"JSON report: {bold(rpath)}"))
    elif choice == "3":
        rpath = generate_sarif_report(results, _OUTPUT_DIR)
        print(info(f"SARIF report: {bold(rpath)}"))
    elif choice == "4":
        for gen, label in [(generate_html_report, "HTML"), (generate_json_report, "JSON"), (generate_sarif_report, "SARIF")]:
            rpath = gen(results, _OUTPUT_DIR)
            print(info(f"{label} report: {bold(rpath)}"))
    elif choice == "5":
        q_dir = os.path.join(scan_path, _QUARANTINE_DIR)
        moved = quarantine_files(results.get("findings", []), scan_path, q_dir)
        print(info(f"Quarantined {bold(str(len(moved)))} file(s) to {q_dir}"))


def _watch_mode():
    path = _ask_path("Watch target")
    if not path:
        return

    print()
    scan_type = input(f"  {bold('Scan type [theme/plugin/full]:')} ").strip() or "theme"
    interval = input(f"  {bold('Poll interval in seconds [5]:')} ").strip()
    interval = int(interval) if interval.isdigit() else 5

    from core.watcher import watch
    watch(path, interval=interval, scan_type=scan_type)


def _quarantine_menu():
    print()
    print(f"  {cyan('[1]')} View quarantined files")
    print(f"  {cyan('[2]')} Restore a file")
    print(f"  {cyan('[0]')} Back")
    print()
    choice = input(f"  {bold('Select [0-2]:')} ").strip()

    if choice == "1":
        path = _ask_path("Quarantine directory")
        if not path:
            return
        q_dir = os.path.join(path, _QUARANTINE_DIR)
        items = list_quarantined(q_dir)
        if not items:
            print(green("\n  No quarantined files.\n"))
            return
        for i, item in enumerate(items, 1):
            print(f"  {cyan(f'[{i}]')} {item.get('relative_path', '')} ({item.get('timestamp', '')})")
        print()

    elif choice == "2":
        path = _ask_path("Original scan directory")
        if not path:
            return
        q_dir = os.path.join(path, _QUARANTINE_DIR)
        rel = input(f"  {bold('Relative path to restore (or blank for all):')} ").strip()
        restored = restore_files(q_dir, rel or None)
        print(info(f"Restored {bold(str(len(restored)))} file(s)"))


def _history_menu():
    path = _ask_path("Scan target")
    if not path:
        return

    scans = list_scans(path)
    if not scans:
        print(yellow("\n  No scan history found.\n"))
        return

    print(bold("\n  Scan History:"))
    for s in scans[:10]:
        print(f"    {cyan(s['timestamp'])} - {s['findings']} finding(s)")
    print()


def _wp_diff_scan():
    path = _ask_path("Theme/Plugin")
    if not path:
        return

    scan_type = input(f"  {bold('Type [theme/plugin]:')} ").strip() or "theme"
    print(info("\n  Downloading official source from WordPress.org..."))

    from core.wp_diff import diff_against_official
    findings = diff_against_official(path, scan_type)

    if not findings:
        print(green("\n  [OK] All files match official release.\n"))
    else:
        print(yellow(f"\n  Found {len(findings)} difference(s):\n"))
        for f in findings:
            color = red if f["severity"] == "high" else yellow
            print(f"    {color(f['message'])}")
    print()


def _init_config(config):
    path = _ask_path("Project directory")
    if not path:
        return

    fpath = create_default_config(path)
    print(info(f"Config created: {bold(fpath)}"))
    print(info("Edit .themeguardrc to customize scan behavior."))
    print()


def _show_help():
    print()
    print(bold("  CLI Usage:"))
    print()
    print(f"  {bold('Basic scanning:')}")
    print(f"  {cyan('python themeguard.py --path ./theme/')}")
    print(f"  {cyan('python themeguard.py --path ./plugin/ --type plugin')}")
    print(f"  {cyan('python themeguard.py --path ./wp-content/ --type full')}")
    print()
    print(f"  {bold('Reports:')}")
    print(f"  {cyan('python themeguard.py --path ./theme/ --report both')}")
    print(f"  {cyan('python themeguard.py --path ./theme/ --report sarif')}")
    print()
    print(f"  {bold('Advanced:')}")
    print(f"  {cyan('python themeguard.py --path ./theme/ --network')}")
    print(f"  {cyan('python themeguard.py --path ./theme/ --watch')}")
    print(f"  {cyan('python themeguard.py --path ./theme/ --quarantine')}")
    print(f"  {cyan('python themeguard.py --path ./theme/ --diff')}")
    print(f"  {cyan('python themeguard.py --path ./theme/ --compare')}")
    print()
    print(f"  {bold('Options:')}")
    print(f"    --path        Target directory (required)")
    print(f"    --type        theme, plugin, or full (default: theme)")
    print(f"    --report      html, json, sarif, or both")
    print(f"    --severity    critical, high, medium, low")
    print(f"    --deep        Deep scan mode")
    print(f"    --network     Enable network sandbox (URL probing)")
    print(f"    --watch       Real-time file monitoring")
    print(f"    --quarantine  Auto-quarantine critical/high threats")
    print(f"    --diff        Compare against WordPress.org official")
    print(f"    --compare     Compare with previous scan results")
    print(f"    --quiet       Suppress banner and details")
    print()


def cli_mode():
    parser = argparse.ArgumentParser(
        description="ThemeGuard - WordPress Theme & Plugin Backdoor Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python themeguard.py --path ./theme/\n"
               "  python themeguard.py --path ./plugin/ --type plugin\n"
               "  python themeguard.py --path ./theme/ --report both --network\n"
               "  python themeguard.py --path ./theme/ --watch\n"
               "  python themeguard.py --path ./theme/ --diff --quarantine",
    )
    parser.add_argument("--path", required=True, help="path to theme/plugin directory")
    parser.add_argument("--type", choices=["theme", "plugin", "full"], default="theme", help="scan type")
    parser.add_argument("--deep", action="store_true", help="enable deep scan")
    parser.add_argument("--report", choices=["html", "json", "sarif", "both"], help="generate report")
    parser.add_argument("--output-dir", default="reports", help="report output directory")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="minimum severity")
    parser.add_argument("--network", action="store_true", help="enable network sandbox")
    parser.add_argument("--watch", action="store_true", help="real-time file monitoring")
    parser.add_argument("--quarantine", action="store_true", help="auto-quarantine threats")
    parser.add_argument("--diff", action="store_true", help="compare against WordPress.org")
    parser.add_argument("--compare", action="store_true", help="compare with previous scan")
    parser.add_argument("--quiet", action="store_true", help="suppress banner and findings")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(red(f"Path not found: {args.path}"))
        sys.exit(1)

    if not args.quiet:
        print_banner()

    if args.watch:
        from core.watcher import watch
        watch(args.path, scan_type=args.type)
        return

    if args.diff:
        from core.wp_diff import diff_against_official
        findings = diff_against_official(args.path, args.type)
        if not findings:
            print(green("  [OK] All files match official release."))
        else:
            for f in findings:
                print(f"  [{f['severity'].upper()}] {f['message']}")
        return

    scanner = Scanner(
        path=args.path,
        deep=args.deep,
        verbosity=0 if args.quiet else 1,
        scan_type=args.type,
        network=args.network,
    )
    scanner.run()
    results = scanner.get_results()

    if args.severity:
        idx = _SEV_ORDER.index(args.severity)
        results["findings"] = [
            f for f in results["findings"]
            if _SEV_ORDER.index(f.get("severity", "low")) <= idx
        ]
        results["total_findings"] = len(results["findings"])

    if args.compare:
        comp = compare_scans(results, args.path)
        if comp:
            print(f"  Comparison: +{comp['new_threats']} new, -{comp['resolved']} resolved, ={comp['unchanged']} unchanged")

    save_scan(results, args.path)

    if args.report in ("html", "both"):
        rpath = generate_html_report(results, args.output_dir)
        print(info(f"HTML report:  {bold(rpath)}"))
    if args.report in ("json", "both"):
        rpath = generate_json_report(results, args.output_dir)
        print(info(f"JSON report:  {bold(rpath)}"))
    if args.report in ("sarif", "both"):
        rpath = generate_sarif_report(results, args.output_dir)
        print(info(f"SARIF report: {bold(rpath)}"))

    if args.quarantine:
        q_dir = os.path.join(args.path, _QUARANTINE_DIR)
        moved = quarantine_files(results.get("findings", []), args.path, q_dir)
        if moved:
            print(info(f"Quarantined {len(moved)} file(s) to {q_dir}"))

    crit = results["severity_counts"].get("critical", 0)
    highs = results["severity_counts"].get("high", 0)
    if crit > 0:
        sys.exit(2)
    elif highs > 0:
        sys.exit(1)
    sys.exit(0)


def main():
    if len(sys.argv) == 1:
        interactive_menu()
    else:
        cli_mode()


if __name__ == "__main__":
    main()
