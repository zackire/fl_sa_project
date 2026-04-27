"""
metrics_collector.py
────────────────────────────────────────────────────────────────────────────
Measures per-round performance for the FL Secure Aggregation testbed.
Each node (server or client) runs its own collector independently on its
own Raspberry Pi, measuring only that node's process resources.

Tracked metrics (per round):
  • Latency      — wall-clock time for the full SA protocol (R0→R3) on
                   this node, from the ignition signal to the last message
                   sent/received in Round 3 (seconds)
  • CPU          — average CPU usage of this process, sampled throughout
                   the round at 0.5 s intervals (%)
  • RAM          — average RSS memory of this process, sampled at the
                   same interval (MB)
  • Bandwidth TX — total bytes this node *published* over MQTT (bytes)
  • Bandwidth RX — total bytes this node *received* over MQTT (bytes)
  • Bandwidth    — TX + RX combined (bytes)

CSV filename format:
  <protocol>_<stack>_<role>_<node_id>_<YYYYMMDD_HHMMSS>.csv
  Examples:
    secagg_stackA_server_server_20260426_115300.csv
    secagg_stackA_client_client1_20260426_115300.csv
    baseline_server_server_20260426_115300.csv

Docker note:
  Mount the output directory as a volume so the CSV is visible on the host:
      volumes:
        - ./metrics/results:/app/metrics/results
  Then pass --results-dir /app/metrics/results to main_server.py / main_client.py.

psutil + Docker note:
  cpu_percent(interval=None) always returns 0.0 on the first call inside a
  container because there is no prior reference point. This collector primes
  the process handle at __init__ time and uses blocking cpu_percent(interval=N)
  calls in the sampling thread so every sample is accurate.

Hooks inside each orchestrator:
    self.metrics.round_start(round_number)         # R0 ignition (client) / first pubkey (server)
    self.metrics.record_bytes(len(payload))        # every mqtt.publish() call
    self.metrics.record_recv_bytes(len(payload))   # every mqtt message received
    self.metrics.round_end(round_number)           # after last R3 action
"""

import csv
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False
    logging.warning(
        "[Metrics] psutil not installed — CPU/RAM will be recorded as 0.0. "
        "Install with: pip install psutil"
    )

# Blocking interval per CPU sample (seconds).
# Must be > 0 inside Docker; interval=None returns 0.0 until a reference exists.
_CPU_SAMPLE_INTERVAL_S = 0.5


# ──────────────────────────────────────────────────────────────────────────── #
#  Data model                                                                  #
# ──────────────────────────────────────────────────────────────────────────── #

@dataclass
class RoundMetrics:
    node_label:      str   # e.g. "secagg_stackA_server" or "secagg_stackA_client1"
    round_num:       int
    timestamp:       str   = ""
    latency_s:       float = 0.0
    cpu_avg_pct:     float = 0.0
    ram_avg_mb:      float = 0.0
    bw_tx_bytes:     int   = 0   # bytes this node sent (published)
    bw_rx_bytes:     int   = 0   # bytes this node received
    bw_total_bytes:  int   = 0   # tx + rx

    # Internal — not written to CSV
    _start_time:  float      = field(default=0.0,           repr=False)
    _cpu_samples: List[float] = field(default_factory=list, repr=False)
    _ram_samples: List[float] = field(default_factory=list, repr=False)

    CSV_FIELDS = [
        "node_label", "round_num", "timestamp",
        "latency_s", "cpu_avg_pct", "ram_avg_mb",
        "bw_tx_bytes", "bw_rx_bytes", "bw_total_bytes",
    ]

    def to_row(self) -> Dict:
        return {
            "node_label":     self.node_label,
            "round_num":      self.round_num,
            "timestamp":      self.timestamp,
            "latency_s":      round(self.latency_s, 4),
            "cpu_avg_pct":    round(self.cpu_avg_pct, 2),
            "ram_avg_mb":     round(self.ram_avg_mb, 2),
            "bw_tx_bytes":    self.bw_tx_bytes,
            "bw_rx_bytes":    self.bw_rx_bytes,
            "bw_total_bytes": self.bw_tx_bytes + self.bw_rx_bytes,
        }


# ──────────────────────────────────────────────────────────────────────────── #
#  Collector                                                                   #
# ──────────────────────────────────────────────────────────────────────────── #

class MetricsCollector:
    """
    One collector per process (one per Raspberry Pi node).

    Lifecycle per round:
        round_start(n)
            → record_bytes(b)       [every mqtt.publish()]
            → record_recv_bytes(b)  [every MQTT message received]
        round_end(n)
            → row appended to CSV immediately
    """

    def __init__(self,
                 protocol: str,
                 stack: str,
                 role: str,
                 node_id: str,
                 output_dir: str = "/app/metrics/results"):
        """
        Args:
            protocol:   "secagg" or "baseline"
            stack:      "stackA", "stackB", "stackC", or "" for baseline
            role:       "server" or "client"
            node_id:    unique node name, e.g. "server", "client1", "client2"
            output_dir: Directory for the CSV. Mount this as a Docker volume.

        CSV filename produced:
            <protocol>_<stack>_<role>_<node_id>_<YYYYMMDD_HHMMSS>.csv
            e.g.  secagg_stackA_server_server_20260426_115300.csv
                  secagg_stackA_client_client1_20260426_115300.csv
                  baseline_server_server_20260426_115300.csv
        """
        self.protocol   = protocol
        self.stack      = stack
        self.role       = role
        self.node_id    = node_id
        self.output_dir = output_dir

        # Human-readable label stored in every CSV row
        if stack:
            self.node_label = f"{protocol}_{stack}_{role}_{node_id}"
        else:
            self.node_label = f"{protocol}_{role}_{node_id}"

        # Prime psutil process handle and take a throwaway cpu_percent reading
        # so subsequent blocking calls return real values from the first sample.
        if _PSUTIL_AVAILABLE:
            self._process = psutil.Process()
            self._process.cpu_percent(interval=None)   # priming call — discard result
        else:
            self._process = None

        # Active round state
        self._active:           Optional[RoundMetrics]  = None
        self._sampling_thread:  Optional[threading.Thread] = None
        self._stop_sampling     = threading.Event()

        # Completed rounds (kept in memory for print_summary)
        self._completed: List[RoundMetrics] = []

        # CSV filename: <protocol>_<stack>_<role>_<node_id>_<timestamp>.csv
        os.makedirs(output_dir, exist_ok=True)
        parts = [p for p in [protocol, stack, role, node_id] if p]
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._csv_path = os.path.join(output_dir, f"{'_'.join(parts)}_{ts}.csv")

        self._init_csv()
        logging.info(
            f"[Metrics] Collector ready  |  node={self.node_label}  |  "
            f"output={self._csv_path}"
        )

    # ──────────────────────────────────────────── #
    #  Public API                                  #
    # ──────────────────────────────────────────── #

    def round_start(self, round_num: int):
        """Call at the moment the round begins on this node."""
        if self._active is not None:
            logging.warning(
                f"[Metrics] round_start({round_num}) called while round "
                f"{self._active.round_num} is still open — closing it first."
            )
            self._finalise_active(forced=True)

        self._active = RoundMetrics(
            node_label=self.node_label,
            round_num=round_num,
            timestamp=datetime.now().isoformat(timespec="seconds"),
            _start_time=time.perf_counter(),
        )

        self._stop_sampling.clear()
        if _PSUTIL_AVAILABLE:
            self._sampling_thread = threading.Thread(
                target=self._sample_loop, daemon=True
            )
            self._sampling_thread.start()

    def record_bytes(self, num_bytes: int):
        """Call once per mqtt.publish() — counts bytes this node sent (TX)."""
        if self._active is not None:
            self._active.bw_tx_bytes += num_bytes

    def record_recv_bytes(self, num_bytes: int):
        """Call once per MQTT message received — counts bytes this node received (RX)."""
        if self._active is not None:
            self._active.bw_rx_bytes += num_bytes

    def round_end(self, round_num: int):
        """Call once the global model has been computed for this round."""
        if self._active is None or self._active.round_num != round_num:
            logging.warning(
                f"[Metrics] round_end({round_num}) called but active round is "
                f"{self._active.round_num if self._active else 'None'} — skipping."
            )
            return
        self._finalise_active()

    # ──────────────────────────────────────────── #
    #  Internal                                    #
    # ──────────────────────────────────────────── #

    def _finalise_active(self, forced: bool = False):
        m = self._active

        # Stop background sampler
        self._stop_sampling.set()
        if self._sampling_thread:
            self._sampling_thread.join(timeout=_CPU_SAMPLE_INTERVAL_S * 2)

        # Compute latency
        m.latency_s = time.perf_counter() - m._start_time

        # Aggregate CPU / RAM
        if m._cpu_samples:
            m.cpu_avg_pct = sum(m._cpu_samples) / len(m._cpu_samples)
        if m._ram_samples:
            m.ram_avg_mb = sum(m._ram_samples) / len(m._ram_samples)

        # Compute combined bandwidth
        m.bw_total_bytes = m.bw_tx_bytes + m.bw_rx_bytes

        self._completed.append(m)
        self._write_row(m)   # append to CSV immediately
        self._active = None

    def _sample_loop(self):
        """
        Background thread: blocking cpu_percent call every _CPU_SAMPLE_INTERVAL_S.
        Using interval > 0 is essential inside Docker containers — it forces psutil
        to measure over a real wall-clock window rather than returning a stale 0.0.
        """
        proc = self._process
        while not self._stop_sampling.is_set():
            try:
                # blocking=True variant — waits _CPU_SAMPLE_INTERVAL_S then returns
                cpu = proc.cpu_percent(interval=_CPU_SAMPLE_INTERVAL_S)
                ram = proc.memory_info().rss / (1024 * 1024)   # bytes → MB
                if self._active is not None:
                    self._active._cpu_samples.append(cpu)
                    self._active._ram_samples.append(ram)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            # No extra sleep — cpu_percent(interval=N) already blocks for N seconds

    # ──────────────────────────────────────────── #
    #  CSV I/O                                     #
    # ──────────────────────────────────────────── #

    def _init_csv(self):
        """Write the header row. Called once at construction."""
        with open(self._csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=RoundMetrics.CSV_FIELDS)
            writer.writeheader()

    def _write_row(self, m: RoundMetrics):
        """Append one completed round to the CSV."""
        with open(self._csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=RoundMetrics.CSV_FIELDS)
            writer.writerow(m.to_row())

    # ──────────────────────────────────────────── #
    #  Optional summary (call on shutdown)         #
    # ──────────────────────────────────────────── #

    def print_summary(self):
        """Logs a compact summary table. Call on KeyboardInterrupt in main_server.py/main_client.py."""
        if not self._completed:
            return

        header = (
            f"{'Round':>6}  {'Latency(s)':>10}  "
            f"{'CPU(%)':>7}  {'RAM(MB)':>8}  "
            f"{'TX(bytes)':>12}  {'RX(bytes)':>12}  {'Total BW':>12}"
        )
        bar = "─" * len(header)
        logging.info(f"\n[Metrics] ── Summary  node={self.node_label} ──")
        logging.info(bar)
        logging.info(header)
        logging.info(bar)
        for m in self._completed:
            logging.info(
                f"{m.round_num:>6}  {m.latency_s:>10.3f}  "
                f"{m.cpu_avg_pct:>7.1f}  {m.ram_avg_mb:>8.1f}  "
                f"{m.bw_tx_bytes:>12,}  {m.bw_rx_bytes:>12,}  "
                f"{m.bw_tx_bytes + m.bw_rx_bytes:>12,}"
            )
        logging.info(bar)
        logging.info(f"[Metrics] CSV saved → {self._csv_path}")