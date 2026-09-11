import argparse
import glob
import itertools
import re
import subprocess
import datetime
import time
import csv
import os
import pwd
import statistics
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np


BASE_ALGORITHMS = ["ring", "linear", "ring_eager"]
# "inline-<algo>": same collective, same wire format, but each copy's header is
# written by the NIC as a WQE inline header instead of by the BPF program.
ALGORITHMS = BASE_ALGORITHMS + [f"inline-{a}" for a in BASE_ALGORITHMS]

# Where MPI lives: next to this script, whatever the working directory is.
MPI_BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "MPI")

# Column labels are parsed back out when plotting, and ring_eager has an
# underscore of its own, so split on the keys rather than on "_".
COLUMN_RE = re.compile(r"^s=(?P<s>[^_]+)_np=(?P<np>[^_]+)_p=(?P<p>[^_]+)_a=(?P<a>.+)$")


def column_label(size, np, prog, algo):
    return f"s={size}_np={np}_p={prog}_a={algo}"


def set_governor(governor):
    try:
        for path in sorted(
            glob.glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor")
        ):
            subprocess.run(
                ["sudo", "tee", path],
                input=governor,
                text=True,
                stdout=subprocess.DEVNULL,
                check=True,
            )
            # print(f"Core {core}: {governor} OK")
    
    except subprocess.CalledProcessError as e:
        print(f"Error setting governor: {e}")

def _sudo_user_ids():
    """Return (uid, gid) of the user who invoked sudo, or None if not running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and os.geteuid() == 0:
        pw = pwd.getpwnam(sudo_user)
        gid = int(os.environ.get("SUDO_GID", pw.pw_gid))
        return pw.pw_uid, gid
    return None


def _chown_recursive(path, uid, gid):
    os.chown(path, uid, gid)
    if os.path.isdir(path):
        for entry in os.scandir(path):
            _chown_recursive(entry.path, uid, gid)


def parse_args():
    parser = argparse.ArgumentParser(description="Run MPI benchmarks")
    parser.add_argument(
        "-i", "--interface", default="enp52s0f1np1", help="Network interface"
    )
    parser.add_argument(
        "-s",
        "--sizes",
        nargs="+",
        type=int,
        default=[1000, 65536],
        help="Sizes to test",
    )
    parser.add_argument(
        "-n",
        "--processes",
        nargs="+",
        type=int,
        default=[2, 4, 8, 16],
        help="Number of processes",
    )
    parser.add_argument(
        "-p",
        "--progs",
        nargs="+",
        default=["naive", "TC", "XDP"],
        choices=["XDP", "TC", "naive"],
        help="Programs to test",
    )

    parser.add_argument(
        "-w", "--warmup", type=int, default=5, help="Warmup runs for MPI program"
    )
    parser.add_argument(
        "-m",
        "--iters",
        type=int,
        default=1,
        help="Collectives timed per MPI run. One -- the default, and what this "
        "always did -- makes every data point a single broadcast, whose "
        "scheduling noise is of the same order as the quantity at small rank "
        "counts: the spread was 90-170%% of the mean. Above one, only the "
        "root's times are kept: the root blocks until all N-1 ACKs are in, so "
        "its elapsed time is the collective's, while the other ranks report "
        "their own arrival and would drag the statistics down.",
    )
    parser.add_argument(
        "-r",
        "--runs",
        type=int,
        default=1,
        help="Number of times to run the full benchmark suite",
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        nargs="+",
        default=["ring"],
        choices=ALGORITHMS,
        help="MPI algorithms to test. Several may be given, and every one is "
        "run against every -p/-n/-s combination in the same suite: "
        "-a linear inline-linear ring inline-ring measures all four datapaths "
        "back to back, under the same machine state, in one go. An "
        "inline-<algo> runs <algo> with the BPF program that has the NIC "
        "write each copy's header (XDP only).",
    )
    parser.add_argument("-o", "--output", default="test.csv", help="Output CSV file")
    parser.add_argument(
        "-x",
        "--indir",
        action="store_true",
        default=False,
        help="Set RSS indirection table via ethtool before each test, using the current process count as the queue count (ethtool --set-rxfh-indir <iface> equal <np>)",
    )
    parser.add_argument(
        "-S",
        "--steer",
        action="store_true",
        default=False,
        help="Deterministically steer dst-port (base_port + k) to RX queue k via ethtool "
        "ntuple flow steering, for k in [0, np). This gives an exact port->queue->core "
        "mapping (unlike --indir, which is hash-based).",
    )
    parser.add_argument(
        "--base-port",
        type=int,
        default=5000,
        help="First destination port used by the ranks; rank k listens on base_port + k "
        "(used by --steer to build the ntuple rules)",
    )
    parser.add_argument(
        "--steer-proto",
        default="udp4",
        choices=["udp4", "tcp4", "udp6", "tcp6"],
        help="ethtool flow-type used for the ntuple steering rules (default: udp4)",
    )
    return parser.parse_args()


def format_output_suffix(args, timestamp):
    sizes = "-".join(map(str, args.sizes))
    processes = "-".join(map(str, args.processes))
    algorithms = "-".join(args.algorithm)
    indir_part = "_x-auto" if args.indir else ""
    steer_part = f"_steer-{args.base_port}" if args.steer else ""
    return (
        f"s-{sizes}"
        f"_n-{processes}"
        f"_w-{args.warmup}"
        f"{'_m-' + str(args.iters) if args.iters > 1 else ''}"
        f"_r-{args.runs}"
        f"_a-{algorithms}"
        f"{indir_part}"
        f"{steer_part}"
        f"_{timestamp}"
    )


def format_csv_value(value):
    if value == "":
        return ""
    if isinstance(value, (int, np.integer)):
        return str(int(value))
    if isinstance(value, (float, np.floating)):
        text = format(float(value), ".15f").rstrip("0").rstrip(".")
        return text if text else "0"
    return str(value)


def set_rxfh_indir(interface, n):
    cmd = ["sudo", "ethtool", "--set-rxfh-indir", interface, "equal", str(n)]
    print(f"Setting RSS indirection table: {' '.join(cmd)}")
    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"ethtool failed (exit {result.returncode}): {result.stderr.strip()}"
        )


def clear_ntuple_steering(interface, max_loc=64):
    """Remove leftover ntuple rules (loc 0..max_loc-1) from previous runs.

    Stale rules from a run with a higher process count would otherwise keep
    steering high ports to queues that may no longer exist, so we always clear
    before (re)applying.
    """
    for loc in range(max_loc):
        subprocess.run(
            ["sudo", "ethtool", "-U", interface, "delete", str(loc)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def set_ntuple_steering(interface, base_port, n, proto="udp4"):
    """Deterministically steer dst-port (base_port + k) to RX queue k, for k in [0, n).

    Requires the NIC to expose at least n combined channels and to support ntuple
    flow steering. Unlike the RSS indirection table, this is an exact, hash-free
    mapping: port base_port+k always lands on queue k (which should be IRQ-pinned
    to the core running rank k).
    """
    # Ensure at least n RX queues are available. This can legitimately fail
    # (e.g. value unchanged, or an XDP program is attached), so do not abort on it.
    subprocess.run(
        ["sudo", "ethtool", "-L", interface, "combined", str(n)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Enable ntuple (flow steering) filtering.
    enable = subprocess.run(
        ["sudo", "ethtool", "-K", interface, "ntuple", "on"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if enable.returncode != 0:
        raise RuntimeError(
            f"failed to enable ntuple on {interface} "
            f"(exit {enable.returncode}): {enable.stderr.strip()}"
        )

    for k in range(n):
        # loc = k keeps each rule stable and easy to delete later.
        cmd = [
            "sudo",
            "ethtool",
            "-U",
            interface,
            "flow-type",
            proto,
            "dst-port",
            str(base_port + k),
            "action",
            str(k),
            "loc",
            str(k),
        ]
        print(f"Steering: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"ethtool ntuple failed for port {base_port + k} "
                f"(exit {result.returncode}): {result.stderr.strip()}"
            )


def run_benchmark(interface, size, np, prog, warmup, algo, iters=1):
    print(f"Running: size={size}, processes={np}, prog={prog}")

    # Run the MPI program
    temp_output = "temp_benchmark_output.csv"
    if os.path.exists(temp_output):
        os.remove(temp_output)

    # create temp_output file

    with open(temp_output, "w") as f:
        f.write("rank,time\n")

    mpi_cmd = [
        "sudo",
        MPI_BINARY,
        "-w",
        str(warmup),
        "-i",
        interface,
        "-s",
        str(size),
        "-n",
        str(np),
        "-a",
        algo,
        "-m",
        str(iters),
        "-o",
        temp_output,
    ]
    if prog == "TC":
        mpi_cmd.append("-t")
    elif prog == "naive":
        mpi_cmd.append("-z")

    try:
        # Capture output of MPI if there is any data of interest
        # Set cwd to ensure it finds .bpf.o files correctly
        cwd = os.path.dirname(os.path.abspath(__file__))
        mpi_result = subprocess.run(
            mpi_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd
        )
        mpi_output = mpi_result.stdout.strip()
        if mpi_result.returncode != 0:
            print(
                f"Error running MPI program: {mpi_result.stderr.strip()} (Return code: {mpi_result.returncode})"
            )
            return None

        # Read the temporary output and get times across all ranks
        times = []
        if os.path.exists(temp_output):
            with open(temp_output, "r") as f:
                for line in f:
                    parts = line.strip().split(",")
                    if len(parts) == 2:
                        if iters > 1 and parts[0].strip() != "0":
                            continue
                        try:
                            # Convert from seconds to microseconds
                            times.append(float(parts[1]) * 1000000)
                        except ValueError:
                            pass
            # os.remove(temp_output)
        return times
    except Exception as e:
        print(f"Error running MPI program: {e}")
        return []


def plot_median_times(
    csv_content, target_size="1000", output_path=None, algo=None, indir=None, steer=None
):
    """
    Parses a custom CSV string with multiple runs separated by empty lines,
    extracts the median time for each column per run, and plots a grouped
    bar chart showing median bars with individual run dots overlaid.
    """
    # Split the content by lines
    lines = csv_content.strip().split("\n")
    header = [col.strip() for col in lines[0].split(",")]

    runs_data = []
    current_run = {col: [] for col in header}

    # Parse lines to separate runs by separator rows (blank line or all-empty fields)
    for line in lines[1:]:
        line = line.strip()
        if not any(v.strip() for v in line.split(",")):
            # Separator row (empty line or row of bare commas) indicates end of a run
            if any(len(v) > 0 for v in current_run.values()):
                run_medians = {}
                for col in header:
                    # Convert to float, ignoring empty strings
                    vals = [float(x) for x in current_run[col] if x != ""]
                    run_medians[col] = np.median(vals) if vals else np.nan
                runs_data.append(run_medians)
                current_run = {col: [] for col in header}
        else:
            # Accumulate values for the current run
            values = line.split(",")
            # Pad values with empty strings in case the row is missing trailing commas
            values += [""] * (len(header) - len(values))

            for i, val in enumerate(values):
                if i < len(header):
                    current_run[header[i]].append(val.strip())

    # Process the final run if not already added
    if any(len(v) > 0 for v in current_run.values()):
        run_medians = {}
        for col in header:
            vals = [float(x) for x in current_run[col] if x != ""]
            run_medians[col] = np.median(vals) if vals else np.nan
        runs_data.append(run_medians)

    # Restructure the data for plotting
    plot_records = []
    for run_idx, run_median in enumerate(runs_data):
        for col, median_val in run_median.items():
            if pd.isna(median_val):
                continue

            # Parse the column header (e.g. "s=1000_np=2_p=XDP_a=inline-ring")
            match = COLUMN_RE.match(col)
            if not match:
                continue
            parts = match.groupdict()

            # Filter by the target size
            if parts["s"] == str(target_size):
                plot_records.append(
                    {
                        "Run": run_idx + 1,
                        "NP": int(parts["np"]),
                        "Prog": parts["p"],
                        "Algo": parts["a"],
                        "MedianTime": median_val,
                    }
                )

    df = pd.DataFrame(plot_records)

    if df.empty:
        print(f"No data available for size {target_size}.")
        return

    # One bar group per datapath. With a single algorithm the label stays the
    # bare program name, so single-algorithm plots look exactly as before.
    if df["Algo"].nunique() > 1:
        df["Prog"] = df["Prog"] + "/" + df["Algo"]

    # Plotting setup
    fig, ax = plt.subplots(figsize=(12, 7))

    np_order = sorted(df["NP"].unique())
    prog_order = list(dict.fromkeys(df["Prog"].tolist()))
    run_order = sorted(df["Run"].unique())
    num_runs = len(run_order)

    print(f"Debug: Found {num_runs} runs, np_order={np_order}, prog_order={prog_order}")
    print(f"Debug: DataFrame:\n{df}")

    # Calculate positions for bars and dots
    bar_width = 0.8 / max(len(prog_order), 1)
    x_positions = np.arange(len(np_order))

    # Draw median bars for each program
    for prog_idx, prog in enumerate(prog_order):
        offset = (prog_idx - len(prog_order) / 2 + 0.5) * bar_width
        prog_data = df[df["Prog"] == prog]

        medians = []
        for np_val in np_order:
            np_prog_data = prog_data[prog_data["NP"] == np_val]["MedianTime"]
            median_val = np_prog_data.median() if len(np_prog_data) > 0 else 0
            medians.append(median_val)

        bars = ax.bar(
            x_positions + offset,
            medians,
            bar_width,
            label=prog,
            alpha=0.7,
            edgecolor="black",
            linewidth=1.2,
        )

        for bar, mval in zip(bars, medians):
            if mval > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height(),
                    f"{mval:.1f}",
                    ha="center",
                    va="bottom",
                    fontsize=8,
                    fontweight="bold",
                )

    # Overlay individual run dots with jitter
    for prog_idx, prog in enumerate(prog_order):
        offset = (prog_idx - len(prog_order) / 2 + 0.5) * bar_width
        prog_data = df[df["Prog"] == prog]

        for np_idx, np_val in enumerate(np_order):
            np_prog_data = prog_data[prog_data["NP"] == np_val].sort_values("Run")

            # Add jitter based on number of runs
            num_data_points = len(np_prog_data)
            if num_data_points > 0:
                # Jitter amount for better visibility
                jitter_amount = bar_width * 0.3

                # Create jitter positions centered around the bar
                if num_data_points == 1:
                    jitter = np.array([0.0])
                else:
                    jitter = np.linspace(-jitter_amount, jitter_amount, num_data_points)

                ax.scatter(
                    np_idx + offset + jitter,
                    np_prog_data["MedianTime"].values,
                    s=100,
                    color="black",
                    alpha=0.7,
                    zorder=5,
                    edgecolors="white",
                    linewidths=1.5,
                    marker="o",
                )

    # Formatting
    ax.set_xlabel("Number of Processes (np)", fontsize=12, fontweight="bold")
    ax.set_ylabel("Median Elapsed Time (µs)", fontsize=12, fontweight="bold")
    ax.set_title(
        f"Median Execution Time per Run (Size s={target_size})",
        fontsize=14,
        fontweight="bold",
    )
    meta_parts = []
    if algo:
        algos = algo if isinstance(algo, str) else ", ".join(algo)
        meta_parts.append(f"algorithm: {algos}")
    if indir:
        meta_parts.append("indir: auto (= np)")
    if steer:
        meta_parts.append("steer: dst-port -> queue")
    if meta_parts:
        fig.text(
            0.5,
            0.97,
            "  |  ".join(meta_parts),
            ha="center",
            va="top",
            fontsize=10,
            color="gray",
        )
    ax.set_xticks(x_positions)
    ax.set_xticklabels(np_order)
    ax.legend(title="Protocol (p)", loc="upper left", framealpha=0.95)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)

    plt.tight_layout()
    if output_path is None:
        output_path = f"max_times_s{target_size}.png"
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()


# Base algorithm of a sweep entry: "inline-linear" is measured as its own
# algorithm but belongs in the same figure as "linear".
def _base_algo(algo):
    return algo[len("inline-"):] if algo.startswith("inline-") else algo


def save_pgfplots_tables(runs_data, combinations, output_dir, stem, suffix):
    r"""One \pgfplotstableread table per base algorithm and payload size.

    Shape matches the paper's figures: a row per rank count, and a value/error
    column pair per series -- naive, tc, xdp, and inline where it exists.
    Values are the median over every collective of every run, errors the
    standard deviation of the per-run medians, which is the spread that more
    runs would actually reduce (see the stats CSV). Times in milliseconds.
    """
    series = {}
    for idx, (size, np_, prog, algo) in enumerate(combinations):
        values = [
            v
            for run in runs_data
            for v in run[idx]
            if isinstance(v, (int, float))
        ]
        if not values:
            continue
        per_run = [
            statistics.median([v for v in run[idx] if isinstance(v, (int, float))])
            for run in runs_data
            if any(isinstance(v, (int, float)) for v in run[idx])
        ]
        name = "inline" if algo.startswith("inline-") else prog.lower()
        series[(_base_algo(algo), size, np_, name)] = (
            statistics.median(values) / 1000.0,
            (statistics.stdev(per_run) if len(per_run) > 1 else 0.0) / 1000.0,
        )

    order = ["naive", "tc", "xdp", "inline"]
    written = []
    keys = sorted({(a, s) for a, s, _, _ in series})
    for algo, size in keys:
        nps = sorted({n for a, s, n, _ in series if (a, s) == (algo, size)})
        names = [n for n in order
                 if any((algo, size, np_, n) in series for np_ in nps)]
        path = os.path.join(output_dir, f"pgf_{stem}_a-{algo}_s-{size}_{suffix}.dat")
        with open(path, "w", encoding="utf-8") as f:
            f.write("N\t" + "\t".join(f"{n}\t{n}_err" for n in names) + "\n")
            for np_ in nps:
                cells = []
                for n in names:
                    v = series.get((algo, size, np_, n))
                    cells.append("nan\tnan" if v is None
                                 else f"{v[0]:.6f}\t{v[1]:.6f}")
                f.write(f"{np_}\t" + "\t".join(cells) + "\n")
        written.append(path)
    return written


def main():
    args = parse_args()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_suffix = format_output_suffix(args, timestamp)
    output_stem, _ = os.path.splitext(args.output)
    if not output_stem:
        output_stem = args.output

    output_dir = f"results_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    results_output = os.path.join(output_dir, f"{output_stem}_{output_suffix}.csv")
    stats_output = os.path.join(output_dir, f"stats_{output_stem}_{output_suffix}.csv")

    # Every algorithm against every program/np/size, in one suite. An
    # inline-<algo> only exists on the XDP path, so those pairs are dropped
    # rather than left to fail in MPI.
    combinations = [
        (size, np, prog, algo)
        for prog in args.progs
        for algo in args.algorithm
        for np in args.processes
        for size in args.sizes
        if prog == "XDP" or not algo.startswith("inline-")
    ]
    if not combinations:
        raise SystemExit(
            "nothing to run: inline-* algorithms need -p XDP"
        )
    dropped = sorted(
        {
            (prog, algo)
            for prog in args.progs
            for algo in args.algorithm
            if prog != "XDP" and algo.startswith("inline-")
        }
    )
    for prog, algo in dropped:
        print(f"Skipping {algo} on {prog}: the inline TX header is XDP-only")

    # Generate CSV Headers: Each parameter combination gets its own column
    headers = [column_label(s, np, prog, algo) for s, np, prog, algo in combinations]

    # We will accumulate all results structured by run
    runs_data = []

    for run in range(args.runs):
        print(f"\n--- Starting benchmark run {run + 1}/{args.runs} ---")
        current_run_data = [[] for _ in combinations]
        for i, (size, np, prog, algo) in enumerate(combinations):
            if args.indir:
                set_rxfh_indir(args.interface, np)
            if args.steer:
                # Clear stale rules first, then map base_port..base_port+np-1
                # onto queues 0..np-1 deterministically.
                clear_ntuple_steering(args.interface)
                set_ntuple_steering(
                    args.interface, args.base_port, np, proto=args.steer_proto
                )
            metrics = run_benchmark(
                args.interface, size, np, prog, args.warmup, algo, args.iters
            )
            if metrics:
                current_run_data[i].extend(metrics)
            # time.sleep(0.5) # Small delay between runs
        runs_data.append(current_run_data)

    if args.steer:
        # Leave the NIC in a clean state once benchmarking is done.
        clear_ntuple_steering(args.interface)

    print(f"\nAll tests completed. Writing results to {results_output}")

    # Transpose columns to rows per run, with a blank row between runs
    results_matrix = []
    for run_idx, run_data in enumerate(runs_data):
        max_rows = max((len(col) for col in run_data), default=0)
        for r_idx in range(max_rows):
            row = []
            for col in run_data:
                if r_idx < len(col):
                    row.append(col[r_idx])
                else:
                    row.append("")
            results_matrix.append(row)

        # Add an empty row to separate runs, except for the last run
        if run_idx < len(runs_data) - 1:
            results_matrix.append([""] * len(headers))

    # Write to CSV
    # Row 1: Headers (the configuration for each column)
    # Row 2+: The results for each iteration/process
    with open(results_output, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        for row in results_matrix:
            writer.writerow([format_csv_value(value) for value in row])

    # Statistics. avg_min/avg_max are the two extremes of each run, kept because
    # they always been here, but they are the worst pair of estimators for these
    # distributions: the slow tail is common to every program -- it comes from
    # scheduling and from the barrier's skew, not from the datapath -- so
    # avg_max comes out nearly equal for TC and XDP (1786.8 against 1780.6 us at
    # 32 ranks) and hides a difference that the body of the distribution shows
    # plainly (420 against 168). Hence the median and the percentiles below.
    #
    # The two spreads answer different questions, and the answer decides whether
    # more runs would help: stddev_within is the spread between the collectives
    # of one run, stddev_between the spread between the runs' own medians.
    # Measured here the first is three to ten times the second, so -r buys
    # nothing -- the dispersion is inside the run, not across runs.
    stats_headers = ["Metric"] + headers
    metric_names = [
        "avg_min", "stddev_min", "avg_max", "stddev_max",
        "median", "p90", "p99", "mean", "stddev_within", "stddev_between",
    ]
    stats_rows = [[m] for m in metric_names]

    def _pct(sorted_vals, q):
        if not sorted_vals:
            return ""
        k = min(len(sorted_vals) - 1, int(q * len(sorted_vals)))
        return sorted_vals[k]

    for col_idx in range(len(combinations)):
        run_mins, run_maxs, run_medians, per_run_sd, pooled = [], [], [], [], []

        for run_data in runs_data:
            col = run_data[col_idx]
            valid_data = [x for x in col if isinstance(x, (int, float))]
            if valid_data:
                run_mins.append(min(valid_data))
                run_maxs.append(max(valid_data))
                run_medians.append(statistics.median(valid_data))
                if len(valid_data) > 1:
                    per_run_sd.append(statistics.stdev(valid_data))
                pooled.extend(valid_data)

        if not pooled:
            for row in stats_rows:
                row.append("")
            continue

        pooled.sort()
        values = [
            statistics.mean(run_mins),
            statistics.stdev(run_mins) if len(run_mins) > 1 else 0.0,
            statistics.mean(run_maxs),
            statistics.stdev(run_maxs) if len(run_maxs) > 1 else 0.0,
            statistics.median(pooled),
            _pct(pooled, 0.90),
            _pct(pooled, 0.99),
            statistics.mean(pooled),
            statistics.mean(per_run_sd) if per_run_sd else 0.0,
            statistics.stdev(run_medians) if len(run_medians) > 1 else 0.0,
        ]
        for row, value in zip(stats_rows, values):
            row.append(value)

    with open(stats_output, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(stats_headers)
        for row in stats_rows:
            writer.writerow([format_csv_value(value) for value in row])

    print(f"Statistics written to {stats_output}")

    for path in save_pgfplots_tables(
        runs_data, combinations, output_dir, output_stem, output_suffix
    ):
        print(f"pgfplots table written to {path}  (milliseconds)")

    csv_content = open(results_output).read()
    for size in args.sizes:
        plot_output = os.path.join(
            output_dir, f"median_times_s{size}_{output_stem}_{output_suffix}.png"
        )
        plot_median_times(
            csv_content,
            target_size=str(size),
            output_path=plot_output,
            algo=args.algorithm,
            indir=args.indir,
            steer=args.steer,
        )
        print(f"Plot written to {plot_output}")

    ids = _sudo_user_ids()
    if ids:
        uid, gid = ids
        _chown_recursive(output_dir, uid, gid)
        if os.path.exists("temp_benchmark_output.csv"):
            os.chown("temp_benchmark_output.csv", uid, gid)


if __name__ == "__main__":
    set_governor("performance")
    main()
    set_governor("schedutil")
