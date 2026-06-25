import argparse
import itertools
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


def set_governor(governor):
    try:
        for core in range(32):
    
            path = f"/sys/devices/system/cpu/cpu{core}/cpufreq/scaling_governor"
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
        "-r",
        "--runs",
        type=int,
        default=1,
        help="Number of times to run the full benchmark suite",
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        default="ring",
        choices=["ring", "linear", "ring_eager"],
        help="MPI algorithm to use",
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
    indir_part = "_x-auto" if args.indir else ""
    steer_part = f"_steer-{args.base_port}" if args.steer else ""
    return (
        f"s-{sizes}"
        f"_n-{processes}"
        f"_w-{args.warmup}"
        f"_r-{args.runs}"
        f"_a-{args.algorithm}"
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


def run_benchmark(interface, size, np, prog, warmup, algo):
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
        "/mnt/shared_p2p/XDP_CLONE/XDP-MPI-Collectives/MPI",
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

            # Parse the column header (e.g., "s=1000_np=2_p=TC")
            parts = dict(part.split("=") for part in col.split("_"))

            # Filter by the target size
            if parts.get("s") == str(target_size):
                plot_records.append(
                    {
                        "Run": run_idx + 1,
                        "NP": int(parts.get("np", 0)),
                        "Prog": parts.get("p"),
                        "MedianTime": median_val,
                    }
                )

    df = pd.DataFrame(plot_records)

    if df.empty:
        print(f"No data available for size {target_size}.")
        return

    # Plotting setup
    fig, ax = plt.subplots(figsize=(12, 7))

    np_order = sorted(df["NP"].unique())
    prog_order = list(dict.fromkeys(df["Prog"].tolist()))
    run_order = sorted(df["Run"].unique())
    num_runs = len(run_order)

    print(f"Debug: Found {num_runs} runs, np_order={np_order}, prog_order={prog_order}")
    print(f"Debug: DataFrame:\n{df}")

    # Calculate positions for bars and dots
    bar_width = 0.35
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
                jitter_amount = 0.12

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
    if algo is not None:
        meta_parts.append(f"algorithm: {algo}")
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

    combinations = [
        (size, np, prog)
        for prog in args.progs
        for np in args.processes
        for size in args.sizes
    ]

    # Generate CSV Headers: Each parameter combination gets its own column
    headers = [f"s={s}_np={np}_p={prog}" for s, np, prog in combinations]

    # We will accumulate all results structured by run
    runs_data = []

    for run in range(args.runs):
        print(f"\n--- Starting benchmark run {run + 1}/{args.runs} ---")
        current_run_data = [[] for _ in combinations]
        for i, (size, np, prog) in enumerate(combinations):
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
                args.interface, size, np, prog, args.warmup, args.algorithm
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

    # Compute statistics (avg of min/max per run and their stddev) and write to a separate CSV
    stats_headers = ["Metric"] + headers
    stats_rows = [["avg_min"], ["stddev_min"], ["avg_max"], ["stddev_max"]]

    for col_idx in range(len(combinations)):
        run_mins = []
        run_maxs = []

        for run_data in runs_data:
            col = run_data[col_idx]
            valid_data = [x for x in col if isinstance(x, (int, float))]
            if valid_data:
                run_mins.append(min(valid_data))
                run_maxs.append(max(valid_data))

        if run_mins and run_maxs:
            stats_rows[0].append(statistics.mean(run_mins))
            stats_rows[1].append(
                statistics.stdev(run_mins) if len(run_mins) > 1 else 0.0
            )
            stats_rows[2].append(statistics.mean(run_maxs))
            stats_rows[3].append(
                statistics.stdev(run_maxs) if len(run_maxs) > 1 else 0.0
            )
        else:
            stats_rows[0].append("")
            stats_rows[1].append("")
            stats_rows[2].append("")
            stats_rows[3].append("")

    with open(stats_output, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(stats_headers)
        for row in stats_rows:
            writer.writerow([format_csv_value(value) for value in row])

    print(f"Statistics written to {stats_output}")

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
