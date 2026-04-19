"""
Single-file mode: same body as one iteration of main.run_project_pipeline without RepositoryAnalyzer.

Examples:
  python test_main.py dataset/case_048/vulnerable.py

Multiple files:
  python test_main.py dataset/case_048/vulnerable.py dataset/case_049/vulnerable.py

Subdirectory + explicit project root:
  python test_main.py --project path/to/repo path/to/repo/src/foo.py

Pipeline: load source -> generate tests -> Bandit -> (if needed) repair loop and guardrails ->
finally always restore originals and delete generated test_*.py (dataset stays clean on disk even
when repair succeeds; copy the patch separately if you need to keep it).
"""
import argparse
import os
import subprocess
import sys

from auto_generate_tests import generate_test_for_file
from guardrail_manager import verify_patch
from repairer import request_repair
from scanner import run_bandit_scan
from slicer import get_function_and_flow

# Compact console output: tail lines of pytest log when a run fails (quiet mode).
_PYTEST_FAIL_TAIL_LINES = 8
_BASELINE_TAIL_LINES = 4


class Logger(object):
    def __init__(self, filename="execution_results.txt"):
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()

    def flush(self):
        pass


def run_single_file_pipeline(project_path, rel_file_path, verbose=False):
    """
    Same as one iteration of main.py's for rel_file_path in repair_sequence loop, plus teardown:
    original file contents and generated test_<name>.py are always cleaned up in finally.

    Returns dict:
      - overall_ok: True if scanner clean, or vuln fixed with at least one passing guardrail round
      - vuln_found: Bandit reported at least one finding
      - repair_success: only when vuln_found; True/False; otherwise None
    """
    project_path = os.path.abspath(project_path)
    rel_file_path = rel_file_path.replace("\\", "/")
    file_path = os.path.normpath(
        os.path.join(project_path, rel_file_path.replace("/", os.sep))
    )

    dir_name = os.path.dirname(file_path)
    base_name = os.path.basename(file_path)
    test_file_path = os.path.join(dir_name, f"test_{base_name}")

    original_code = None

    try:
        if verbose:
            print(f"\n>>> TARGET: {rel_file_path}")
        else:
            print(f"\n{rel_file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            original_code = f.read()

        if verbose:
            print(f"Generating tests for {base_name}...")
        test_code = generate_test_for_file(original_code, rel_file_path, quiet=not verbose)

        if test_code:
            with open(test_file_path, "w", encoding="utf-8") as f:
                f.write(test_code)

        scan_data = run_bandit_scan(file_path)
        issues = scan_data.get("results", [])

        if not issues:
            if verbose:
                print("Scanner: no issues.")
                print(f"Baseline pytest: {base_name}")
            try:
                abs_test_path = os.path.abspath(test_file_path)
                abs_project_path = os.path.abspath(project_path)

                res = subprocess.run(
                    ["python", "-m", "pytest", abs_test_path, "-v"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=abs_project_path,
                )

                output_lines = (res.stdout + res.stderr).strip().splitlines()
                log_preview = (
                    "\n".join(output_lines[-_BASELINE_TAIL_LINES:])
                    if len(output_lines) > _BASELINE_TAIL_LINES
                    else "\n".join(output_lines)
                )

                if res.returncode == 0:
                    print("  bandit: clean | baseline pytest: PASS")
                else:
                    print(
                        "  bandit: clean | baseline pytest: WARN (tests failed; still counted OK)"
                    )
                    if verbose and log_preview.strip():
                        print(f"  tail:\n{log_preview}")
            except Exception as e:
                print(f"  baseline pytest error: {e}")
            return {"overall_ok": True, "vuln_found": False, "repair_success": None}

        issue = issues[0]
        cwe_id = issue["issue_cwe"]["id"]
        line_no = issue["line_number"]

        func_code, data_flow_fact = get_function_and_flow(file_path, line_no)

        if not func_code:
            print(
                f"  slicer: no function at line {line_no}; using full file."
            )
            func_code = original_code
            data_flow_fact = f"Vulnerability detected around line {line_no}. Please review the entire file context."

        max_retries = 3
        previous_error = None
        repair_success = False

        for attempt in range(1, max_retries + 1):
            print(
                f"  CWE-{cwe_id} | attempt {attempt}/{max_retries}"
                if not verbose
                else f"\n[ATTEMPT {attempt}/{max_retries}] CWE-{cwe_id}"
            )
            reasoning, fixed_code = request_repair(
                cwe_id, func_code, data_flow_fact, previous_error
            )
            full_patched_code = original_code.replace(func_code, fixed_code)

            if verbose:
                print("\n--- reasoning ---")
                print(reasoning)
                print("\n--- patched function ---")
                print(fixed_code)
                print("-" * 60)

            success, msg, repair_log = verify_patch(
                file_path, cwe_id, full_patched_code, test_file_path, project_path
            )

            if success:
                if verbose:
                    print(f"\nPASS: {msg}")
                    if repair_log and repair_log.get("test_report"):
                        print(repair_log["test_report"].strip())
                        print("-" * 60)
                else:
                    snippet = (reasoning or "").strip().replace("\n", " ")
                    if len(snippet) > 140:
                        snippet = snippet[:137] + "..."
                    print(f"  -> PASS ({msg}). {snippet}")

                repair_success = True
                break

            if verbose:
                print(f"\nFAIL: {msg}")
                print(
                    "Likely causes: syntax error, functional regression, or fuzz tests still passing unsafe behavior."
                )

            if repair_log and repair_log.get("test_report"):
                error_lines = repair_log["test_report"].strip().splitlines()
                error_tail = (
                    "\n".join(error_lines[-_PYTEST_FAIL_TAIL_LINES:])
                    if len(error_lines) > _PYTEST_FAIL_TAIL_LINES
                    else "\n".join(error_lines)
                )
                if verbose:
                    print("\n--- pytest tail ---")
                    print(error_tail)
                    print("-" * 60)
                else:
                    print(f"  -> FAIL: {msg}")
                    if error_tail.strip():
                        print(f"  pytest tail:\n{error_tail}")
                previous_error = repair_log["test_report"][-1500:]
            else:
                print(f"  -> FAIL: {msg}")

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(original_code)

        if not repair_success:
            print(f"  FAILED: no passing patch for {rel_file_path}")
        return {
            "overall_ok": repair_success,
            "vuln_found": True,
            "repair_success": repair_success,
        }

    finally:
        if original_code is not None:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(original_code)
            except OSError as e:
                print(f"[teardown] could not restore {file_path}: {e}")
        if os.path.isfile(test_file_path):
            try:
                os.remove(test_file_path)
            except OSError as e:
                print(f"[teardown] could not remove {test_file_path}: {e}")


def print_run_summary(results):
    """Print pass rates (English, compact)."""
    total = len(results)
    overall_ok = sum(1 for r in results if r["overall_ok"])
    vuln_files = [r for r in results if r["vuln_found"]]
    vuln_n = len(vuln_files)
    repair_ok = sum(1 for r in vuln_files if r.get("repair_success") is True)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Files: {total} | task OK: {overall_ok}/{total} ({100.0 * overall_ok / total:.1f}%)")
    print(f"Bandit flagged: {vuln_n}")
    if vuln_n > 0:
        print(f"Repairs OK: {repair_ok}/{vuln_n} ({100.0 * repair_ok / vuln_n:.1f}%)")
    else:
        print("Repairs OK: n/a (nothing to repair)")
    print(
        "Note: sources restored after run; success = guardrails passed once."
    )
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Single-file repair pipeline (no RepositoryAnalyzer)."
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help=".py paths to process (e.g. dataset/case_048/vulnerable.py)",
    )
    parser.add_argument(
        "--project",
        default=None,
        metavar="DIR",
        help="Project root for pytest cwd (default: directory of each target)",
    )
    parser.add_argument(
        "--log",
        default=None,
        metavar="FILE",
        help="Also write stdout to this file.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose pipeline logs (reasoning, full pytest output).",
    )
    args = parser.parse_args()

    targets = [os.path.abspath(t) for t in args.targets]
    for target in targets:
        if not os.path.isfile(target):
            print(f"error: file not found: {target}", file=sys.stderr)
            sys.exit(1)

    if args.log:
        sys.stdout = Logger(args.log)

    results = []
    for target in targets:
        project_path = (
            os.path.abspath(args.project) if args.project else os.path.dirname(target)
        )
        rel_file_path = os.path.relpath(target, project_path)
        if rel_file_path.startswith(".."):
            print(
                "error: target is not under --project; set --project to the repo root.",
                file=sys.stderr,
            )
            sys.exit(1)

        if args.verbose:
            print("\n" + "=" * 60)
            print("SINGLE-FILE MODE")
            print(f"file: {target}")
            print(f"cwd: {project_path}")
            print(f"rel: {rel_file_path}")
            print("=" * 60)

        results.append(
            run_single_file_pipeline(project_path, rel_file_path, verbose=args.verbose)
        )

    print_run_summary(results)

    all_ok = all(r["overall_ok"] for r in results)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
