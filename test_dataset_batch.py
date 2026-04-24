"""
Walk every immediate child of the dataset folder that contains vulnerable.py and reuse
test_main.run_single_file_pipeline for batch evaluation (no manual per-case paths).

From project root (.env + venv configured):
  python test_dataset_batch.py

Options:
  python test_dataset_batch.py --dataset dataset
  python test_dataset_batch.py --log dataset_batch_log.txt
  python test_dataset_batch.py --max-cases 5
  python test_dataset_batch.py --no-progress

Progress bar uses tqdm when installed (see requirement.txt); otherwise stderr prints percent/ETA.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time

from test_main import Logger, print_run_summary, run_single_file_pipeline

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover - fallback progress without tqdm
    tqdm = None  # type: ignore


def _natural_case_key(name: str):
    """Natural sort for case_2 vs case_10: prefix then numeric part."""
    m = re.match(r"^(case_)(\d+)(.*)$", name, re.I)
    if m:
        return (m.group(1).lower(), int(m.group(2)), m.group(3).lower())
    return (name.lower(),)


def discover_vulnerable_cases(dataset_root: str) -> list[tuple[str, str]]:
    """
    Return [(case_dir_name, abs_path_to_vulnerable_py), ...] for each immediate
    child directory of dataset_root that contains vulnerable.py.
    """
    dataset_root = os.path.abspath(dataset_root)
    if not os.path.isdir(dataset_root):
        return []

    rows: list[tuple[str, str, tuple]] = []
    for name in os.listdir(dataset_root):
        sub = os.path.join(dataset_root, name)
        if not os.path.isdir(sub):
            continue
        vuln = os.path.join(sub, "vulnerable.py")
        if not os.path.isfile(vuln):
            continue
        rows.append((name, os.path.abspath(vuln), _natural_case_key(name)))

    rows.sort(key=lambda x: x[2])
    return [(name, path) for name, path, _ in rows]


def main():
    parser = argparse.ArgumentParser(
        description="Run the single-file pipeline on each dataset case and print a summary."
    )
    parser.add_argument(
        "--dataset",
        default="dataset",
        metavar="DIR",
        help="Dataset root (default: dataset)",
    )
    parser.add_argument(
        "--log",
        default=None,
        metavar="FILE",
        help="Also mirror stdout to this file",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=None,
        metavar="N",
        help="Process only the first N cases (debug)",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable tqdm bar (stderr progress still prints fallback lines without tqdm).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose per-case logs (same as test_main.py --verbose).",
    )
    args = parser.parse_args()

    cases = discover_vulnerable_cases(args.dataset)
    if args.max_cases is not None:
        cases = cases[: max(0, args.max_cases)]

    if not cases:
        print(
            f"error: no vulnerable.py under {os.path.abspath(args.dataset)}",
            file=sys.stderr,
        )
        sys.exit(2)

    if args.log:
        sys.stdout = Logger(args.log)

    ds = os.path.abspath(args.dataset)
    print(f"\nDataset batch | root={ds} | cases={len(cases)}")

    results: list[dict] = []
    case_labels: list[str] = []

    total = len(cases)
    use_tqdm = tqdm is not None and not args.no_progress
    pbar = None
    if use_tqdm:
        # stderr so tqdm stays visible when stdout is redirected via --log
        pbar = tqdm(
            total=total,
            desc="Dataset batch",
            unit="case",
            file=sys.stderr,
            dynamic_ncols=True,
            smoothing=0.05,
        )

    t0 = time.perf_counter()
    for idx, (case_name, vuln_abs) in enumerate(cases, start=1):
        project_path = os.path.dirname(vuln_abs)
        rel_file_path = os.path.basename(vuln_abs)

        if pbar is not None:
            pbar.set_description(f"Case {idx}/{total}", refresh=False)
            pbar.set_postfix_str(case_name[:45], refresh=False)

        if args.verbose:
            print("\n" + "=" * 60)
            print(f"[{idx}/{total}] {case_name}")
            print(f"path: {vuln_abs}")
            print(f"cwd: {project_path}")
            print("=" * 60)
        else:
            print(f"\n[{idx}/{total}] {case_name}")

        result = run_single_file_pipeline(
            project_path, rel_file_path, verbose=args.verbose
        )
        results.append(result)
        case_labels.append(case_name)

        if pbar is not None:
            pbar.update(1)
        elif not args.no_progress and tqdm is None:
            elapsed = time.perf_counter() - t0
            done = idx
            rate = done / elapsed if elapsed > 0 else 0.0
            eta = (total - done) / rate if rate > 0 else 0.0
            pct = 100.0 * done / total
            print(
                f"\n[progress] {done}/{total} ({pct:.1f}%) elapsed {elapsed:.0f}s ETA {eta:.0f}s (pip install tqdm for a bar)",
                file=sys.stderr,
            )

    if pbar is not None:
        pbar.close()

    print_run_summary(results)

    failed = [
        (case_labels[i], results[i])
        for i in range(len(results))
        if not results[i]["overall_ok"]
    ]
    if failed:
        print("\nCases not OK (overall_ok=False):")
        for name, r in failed:
            print(
                f"  - {name}: overall_ok={r['overall_ok']}, "
                f"vuln_found={r['vuln_found']}, repair_success={r['repair_success']}"
            )
    else:
        print("\nAll cases passed (task completion metric).")

    all_ok = all(r["overall_ok"] for r in results)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
