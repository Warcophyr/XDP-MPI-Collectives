#!/usr/bin/env python3
"""Recompute the statistics of an existing results_* directory.

run_tests.py writes them at the end of a sweep, so a run made before a change
to the metric set keeps the old columns. This reads that run's raw
test_*.csv back and rewrites stats_*.csv and the pgfplots tables from it,
without re-measuring anything.

    python3 restats.py results_20260911_132134 [...]

Metrics, per combination:
  avg_min, stddev_min, avg_max, stddev_max   the two extremes of each run
  median, p90, p99, mean                     over every sample of every run
  stddev_within                              spread between collectives of a run
  stddev_between                             spread between the runs' medians
"""
import csv
import glob
import os
import re
import statistics
import sys

COLUMN = re.compile(r"^s=(?P<s>[^_]+)_np=(?P<np>[^_]+)_p=(?P<p>[^_]+)_a=(?P<a>.+)$")
METRICS = ["avg_min", "stddev_min", "avg_max", "stddev_max",
           "median", "p90", "p99", "mean", "stddev_within", "stddev_between"]
SERIES_ORDER = ["naive", "tc", "xdp", "inline"]


def read_runs(path):
    rows = list(csv.reader(open(path)))
    header, runs = rows[0], [[]]
    for row in rows[1:]:
        if not any(c.strip() for c in row):
            runs.append([])
            continue
        runs[-1].append(row)
    return header, [r for r in runs if r]


def per_run_values(runs, idx):
    out = []
    for run in runs:
        vals = []
        for row in run:
            if idx < len(row) and row[idx].strip():
                try:
                    vals.append(float(row[idx]))
                except ValueError:
                    pass
        if vals:
            out.append(vals)
    return out


def percentile(sorted_vals, q):
    return sorted_vals[min(len(sorted_vals) - 1, int(q * len(sorted_vals)))]


def metrics_for(per_run):
    pooled = sorted(v for run in per_run for v in run)
    mins = [min(r) for r in per_run]
    maxs = [max(r) for r in per_run]
    medians = [statistics.median(r) for r in per_run]
    within = [statistics.stdev(r) for r in per_run if len(r) > 1]
    sd = lambda xs: statistics.stdev(xs) if len(xs) > 1 else 0.0
    return {
        "avg_min": statistics.mean(mins), "stddev_min": sd(mins),
        "avg_max": statistics.mean(maxs), "stddev_max": sd(maxs),
        "median": statistics.median(pooled),
        "p90": percentile(pooled, 0.90), "p99": percentile(pooled, 0.99),
        "mean": statistics.mean(pooled),
        "stddev_within": statistics.mean(within) if within else 0.0,
        "stddev_between": sd(medians),
    }


def base_algo(algo):
    return algo[len("inline-"):] if algo.startswith("inline-") else algo


def main(dirs):
    for d in dirs:
        raw = glob.glob(os.path.join(d, "test_*.csv"))
        if not raw:
            print(f"{d}: no test_*.csv", file=sys.stderr)
            continue
        header, runs = read_runs(raw[0])
        stats, parsed = {}, {}
        for idx, col in enumerate(header):
            m = COLUMN.match(col)
            per_run = per_run_values(runs, idx)
            if not m or not per_run:
                continue
            stats[col] = metrics_for(per_run)
            parsed[col] = m.groupdict()

        stem = os.path.basename(raw[0])[len("test_"):-len(".csv")]
        out = os.path.join(d, f"stats_{stem}.csv")
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            cols = [c for c in header if c in stats]
            w.writerow(["Metric"] + cols)
            for metric in METRICS:
                w.writerow([metric] + [f"{stats[c][metric]:.6f}" for c in cols])
        print(f"{out}  ({len(METRICS)} metrics x {len(cols)} combinations)")

        # Long form: one row per combination, one column per metric. Easier to
        # import than the wide table, and what a LaTeX table wants.
        out = os.path.join(d, f"metrics_{stem}.csv")
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["algo", "base_algo", "size", "np", "prog", "samples"] + METRICS)
            for col in header:
                if col not in stats:
                    continue
                g = parsed[col]
                n = sum(len(r) for r in per_run_values(runs, header.index(col)))
                w.writerow([g["a"], base_algo(g["a"]), g["s"], g["np"], g["p"], n]
                           + [f"{stats[col][m]:.6f}" for m in METRICS])
        print(f"{out}")

        # pgfplots: a table per base algorithm and size, every metric as its own
        # column pair so the figure can plot any of them.
        by = {}
        for col, g in parsed.items():
            name = "inline" if g["a"].startswith("inline-") else g["p"].lower()
            by[(base_algo(g["a"]), int(g["s"]), int(g["np"]), name)] = stats[col]
        for algo, size in sorted({(a, s) for a, s, _, _ in by}):
            nps = sorted({n for a, s, n, _ in by if (a, s) == (algo, size)})
            names = [n for n in SERIES_ORDER
                     if any((algo, size, n_, n) in by for n_ in nps)]
            out = os.path.join(d, f"pgf_a-{algo}_s-{size}.dat")
            with open(out, "w", encoding="utf-8") as f:
                head = ["N"]
                for n in names:
                    head += [n] + [f"{n}_{m}" for m in METRICS]
                f.write("\t".join(head) + "\n")
                for np_ in nps:
                    cells = [str(np_)]
                    for n in names:
                        s = by.get((algo, size, np_, n))
                        if s is None:
                            cells += ["nan"] * (len(METRICS) + 1)
                        else:
                            # the bare series name is the median, in milliseconds
                            cells.append(f"{s['median'] / 1000.0:.6f}")
                            cells += [f"{s[m] / 1000.0:.6f}" for m in METRICS]
                    f.write("\t".join(cells) + "\n")
            print(f"{out}  (milliseconds)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1:])
