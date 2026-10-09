"""
analyze.py
==========
Mengolah berkas hasil pengujian (results/metrics_device_*.csv,
results/metrics_server_*.csv, dan data/db.sqlite) menjadi statistik
deskriptif -- mean, standar deviasi, dan confidence interval (Tabel 1
dokumen rancangan) -- lalu menghasilkan:
  1. results/summary_stats.csv     : tabel statistik tidy (long format)
  2. dashboard/summary.json         : ringkasan dipakai dashboard/index.html
                                       (dashboard NON-REAL-TIME: file ini
                                       hanya diperbarui saat analyze.py
                                       dijalankan ulang, dashboard tidak
                                       melakukan polling otomatis)
  3. results/charts/*.png            : grafik siap pakai untuk lampiran skripsi

Rumus yang dipakai (didokumentasikan sesuai permintaan agar bisa
dijelaskan saat sidang):
  - Mean (rata-rata)      : x_bar = (1/n) * sum(x_i)
  - Standard deviation     : s = sqrt( (1/(n-1)) * sum((x_i - x_bar)^2) )
                              (sample stdev, ddof=1 -- bukan population stdev,
                              karena data yang direkam adalah SAMPEL dari
                              proses pengukuran, bukan seluruh populasi)
  - 95% Confidence Interval (t-distribution, karena n biasanya kecil,
    mis. 31 sesuai acuan pada dokumen rancangan):
        CI = x_bar +/- t(0.025, df=n-1) * (s / sqrt(n))
    dihitung dengan scipy.stats.t.interval().

PENTING (academic integrity): skrip ini TIDAK PERNAH mengarang angka.
Jika file CSV/SQLite belum ada atau kosong, skrip akan melaporkan
"[DATA BENCHMARK BELUM TERSEDIA]" untuk bagian tersebut alih-alih membuat
angka palsu -- jalankan device_sim.py + server.py (atau firmware ESP32-S3)
terlebih dahulu untuk menghasilkan data mentah.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import sqlite3

import numpy as np
import pandas as pd
from scipy import stats

import config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [analyze] %(levelname)s %(message)s")
log = logging.getLogger("analyze")

CHARTS_DIR = os.path.join(config.RESULTS_DIR, "charts")
SUMMARY_STATS_CSV = os.path.join(config.RESULTS_DIR, "summary_stats.csv")

# Palet warna kategorikal tervalidasi (lihat dataviz skill / palette.md):
# blue, orange, aqua, yellow -- dipakai konsisten di seluruh chart matplotlib.
PALETTE = {
    "blue": "#2a78d6",
    "orange": "#eb6834",
    "aqua": "#1baf7a",
    "yellow": "#eda100",
    "violet": "#4a3aa7",
}
STATUS_GOOD = "#0ca30c"
STATUS_CRITICAL = "#d03b3b"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRID_COLOR = "#e1e0d9"


def _load_csvs(pattern: str) -> pd.DataFrame:
    paths = sorted(glob.glob(pattern))
    if not paths:
        return pd.DataFrame()
    frames = [pd.read_csv(p) for p in paths if os.path.getsize(p) > 0]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def load_raw_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    device_df = _load_csvs(os.path.join(config.RESULTS_DIR, "metrics_device_*.csv"))
    server_df = _load_csvs(os.path.join(config.RESULTS_DIR, "metrics_server_*.csv"))
    return device_df, server_df


def mean_std_ci(series: pd.Series, confidence: float = 0.95) -> dict:
    """Return dict(mean, std, n, ci_low, ci_high, min, max, median) untuk satu
    kolom metrik numerik. Mengabaikan NaN. Jika n < 2, CI tidak bisa dihitung
    (butuh minimal 2 sampel untuk standard deviation) -- dilaporkan sebagai
    None, bukan angka yang dikarang."""
    clean = series.dropna()
    n = len(clean)
    if n == 0:
        return {"n": 0, "mean": None, "std": None, "ci_low": None, "ci_high": None,
                "min": None, "max": None, "median": None}
    mean = float(clean.mean())
    if n < 2:
        return {"n": n, "mean": mean, "std": None, "ci_low": None, "ci_high": None,
                "min": float(clean.min()), "max": float(clean.max()), "median": float(clean.median())}
    std = float(clean.std(ddof=1))
    sem = std / np.sqrt(n)
    if sem == 0:
        ci_low, ci_high = mean, mean
    else:
        ci_low, ci_high = stats.t.interval(confidence, df=n - 1, loc=mean, scale=sem)
    return {
        "n": n, "mean": mean, "std": std,
        "ci_low": float(ci_low), "ci_high": float(ci_high),
        "min": float(clean.min()), "max": float(clean.max()), "median": float(clean.median()),
    }


def summarize(device_df: pd.DataFrame, server_df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    group_cols = ["scenario", "payload_size_bytes", "comm_mode", "condition"]

    if not device_df.empty:
        for keys, g in device_df.groupby(group_cols):
            for metric in ["encrypt_time_s", "rtt_s", "throughput_bps"]:
                if metric not in g:
                    continue
                stat = mean_std_ci(g[metric])
                rows.append({**dict(zip(group_cols, keys)), "side": "device", "metric": metric, **stat})
            accepted_rate = g["accepted"].mean() if "accepted" in g and len(g) else None
            rows.append({**dict(zip(group_cols, keys)), "side": "device", "metric": "accepted_rate",
                          "n": len(g), "mean": accepted_rate, "std": None, "ci_low": None, "ci_high": None,
                          "min": None, "max": None, "median": None})

    if not server_df.empty:
        for keys, g in server_df.groupby(group_cols):
            for metric in ["decrypt_time_s", "cpu_percent", "ram_mb"]:
                if metric not in g:
                    continue
                stat = mean_std_ci(g[metric])
                rows.append({**dict(zip(group_cols, keys)), "side": "server", "metric": metric, **stat})
            accepted_rate = g["accepted"].mean() if "accepted" in g and len(g) else None
            tag_valid_rate = g["tag_valid"].mean() if "tag_valid" in g and len(g) else None
            rows.append({**dict(zip(group_cols, keys)), "side": "server", "metric": "accepted_rate",
                          "n": len(g), "mean": accepted_rate, "std": None, "ci_low": None, "ci_high": None,
                          "min": None, "max": None, "median": None})
            rows.append({**dict(zip(group_cols, keys)), "side": "server", "metric": "tag_valid_rate",
                          "n": len(g), "mean": tag_valid_rate, "std": None, "ci_low": None, "ci_high": None,
                          "min": None, "max": None, "median": None})

    return pd.DataFrame(rows)


def load_db_summary() -> dict:
    if not os.path.exists(config.DB_PATH):
        return {"sensor_readings_count": 0, "rejected_count": 0, "latest_readings": []}
    conn = sqlite3.connect(config.DB_PATH)
    try:
        n_valid = conn.execute("SELECT COUNT(*) FROM sensor_readings").fetchone()[0]
        n_rejected = conn.execute("SELECT COUNT(*) FROM rejected_messages").fetchone()[0]
        latest = conn.execute(
            "SELECT device_id, seq, scenario, temp_c, hum_pct, pres_hpa, is_synthetic_sensor, received_at_unix "
            "FROM sensor_readings ORDER BY id DESC LIMIT 20"
        ).fetchall()
        latest_readings = [
            {
                "device_id": r[0], "seq": r[1], "scenario": r[2], "temp_c": r[3], "hum_pct": r[4],
                "pres_hpa": r[5], "is_synthetic_sensor": bool(r[6]), "received_at_unix": r[7],
            }
            for r in latest
        ]
        return {"sensor_readings_count": n_valid, "rejected_count": n_rejected, "latest_readings": latest_readings}
    finally:
        conn.close()


def _style_axes(ax):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(GRID_COLOR)
    ax.spines["bottom"].set_color(INK_MUTED)
    ax.tick_params(colors=INK_SECONDARY)
    ax.yaxis.grid(True, color=GRID_COLOR, linewidth=1, zorder=0)
    ax.set_axisbelow(True)
    ax.title.set_color(INK_PRIMARY)
    ax.xaxis.label.set_color(INK_SECONDARY)
    ax.yaxis.label.set_color(INK_SECONDARY)


def make_charts(summary_df: pd.DataFrame):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    os.makedirs(CHARTS_DIR, exist_ok=True)

    if summary_df.empty:
        log.warning("Tidak ada data untuk divisualisasikan -- [DATA BENCHMARK BELUM TERSEDIA]. "
                     "Jalankan device_sim.py + server.py (atau firmware ESP32-S3) terlebih dahulu.")
        return

    # --- Chart 1: waktu enkripsi vs ukuran payload (skenario S2) ---
    s2 = summary_df[(summary_df.scenario == "S2") & (summary_df.metric == "encrypt_time_s")
                     & (summary_df.side == "device") & (summary_df.condition == "normal")]
    if not s2.empty:
        s2 = s2.sort_values("payload_size_bytes")
        fig, ax = plt.subplots(figsize=(6, 4), dpi=150)
        x = np.arange(len(s2))
        means_ms = s2["mean"].to_numpy() * 1000
        err_ms = np.where(s2["std"].notna(), (s2["mean"] - s2["ci_low"]).to_numpy() * 1000, 0)
        ax.bar(x, means_ms, width=0.5, color=PALETTE["blue"], zorder=3,
               yerr=err_ms, capsize=4, ecolor=INK_SECONDARY)
        ax.set_xticks(x)
        ax.set_xticklabels([f"{int(v)} B" for v in s2["payload_size_bytes"]])
        ax.set_xlabel("Ukuran payload")
        ax.set_ylabel("Waktu enkripsi rata-rata (ms)")
        ax.set_title("SPECK64/128-CTR: Waktu Enkripsi vs Ukuran Payload (S2)")
        _style_axes(ax)
        fig.tight_layout()
        fig.savefig(os.path.join(CHARTS_DIR, "s2_encrypt_time_vs_payload.png"))
        plt.close(fig)

    # --- Chart 2: throughput vs ukuran payload ---
    s2t = summary_df[(summary_df.scenario == "S2") & (summary_df.metric == "throughput_bps")
                      & (summary_df.side == "device") & (summary_df.condition == "normal")]
    if not s2t.empty:
        s2t = s2t.sort_values("payload_size_bytes")
        fig, ax = plt.subplots(figsize=(6, 4), dpi=150)
        x = np.arange(len(s2t))
        means_kbps = s2t["mean"].to_numpy() / 1024
        ax.bar(x, means_kbps, width=0.5, color=PALETTE["orange"], zorder=3)
        ax.set_xticks(x)
        ax.set_xticklabels([f"{int(v)} B" for v in s2t["payload_size_bytes"]])
        ax.set_xlabel("Ukuran payload")
        ax.set_ylabel("Throughput rata-rata (KiB/s)")
        ax.set_title("SPECK64/128-CTR: Throughput vs Ukuran Payload (S2)")
        _style_axes(ax)
        fig.tight_layout()
        fig.savefig(os.path.join(CHARTS_DIR, "s2_throughput_vs_payload.png"))
        plt.close(fig)

    # --- Chart 3: S4 -- tingkat penerimaan normal vs tampered ---
    s4 = summary_df[(summary_df.scenario == "S4") & (summary_df.metric == "accepted_rate")
                     & (summary_df.side == "server")]
    if not s4.empty:
        fig, ax = plt.subplots(figsize=(5, 4), dpi=150)
        conditions = ["normal", "tampered"]
        vals = []
        colors = []
        for c in conditions:
            row = s4[s4.condition == c]
            vals.append(float(row["mean"].iloc[0]) * 100 if not row.empty and row["mean"].iloc[0] is not None else 0)
            colors.append(STATUS_GOOD if c == "normal" else STATUS_CRITICAL)
        x = np.arange(len(conditions))
        ax.bar(x, vals, width=0.5, color=colors, zorder=3)
        ax.set_xticks(x)
        ax.set_xticklabels(["Normal", "Tampered"])
        ax.set_ylabel("Tingkat pesan diterima server (%)")
        ax.set_ylim(0, 105)
        ax.set_title("S4: Verifikasi HMAC Tag -- Normal vs Tampered")
        for xi, v in zip(x, vals):
            ax.text(xi, v + 2, f"{v:.1f}%", ha="center", color=INK_PRIMARY, fontsize=10)
        _style_axes(ax)
        fig.tight_layout()
        fig.savefig(os.path.join(CHARTS_DIR, "s4_accept_rate_normal_vs_tampered.png"))
        plt.close(fig)

    # --- Chart 4: CPU & RAM (proses server, psutil) vs ukuran payload ---
    cpu = summary_df[(summary_df.metric == "cpu_percent") & (summary_df.side == "server")
                      & (summary_df.condition == "normal")]
    ram = summary_df[(summary_df.metric == "ram_mb") & (summary_df.side == "server")
                      & (summary_df.condition == "normal")]
    if not cpu.empty or not ram.empty:
        fig, axes = plt.subplots(1, 2, figsize=(10, 4), dpi=150)
        for ax, df_, label, color, unit in [
            (axes[0], cpu, "CPU (%)", PALETTE["aqua"], "%"),
            (axes[1], ram, "RAM (MB)", PALETTE["violet"], "MB"),
        ]:
            if df_.empty:
                ax.set_visible(False)
                continue
            df_ = df_.sort_values("payload_size_bytes")
            x = np.arange(len(df_))
            ax.bar(x, df_["mean"], width=0.5, color=color, zorder=3)
            ax.set_xticks(x)
            ax.set_xticklabels([f"{int(v)} B" for v in df_["payload_size_bytes"]])
            ax.set_ylabel(f"{label} rata-rata (proses server, host PC)")
            ax.set_xlabel("Ukuran payload")
            _style_axes(ax)
        fig.suptitle("Penggunaan Sumber Daya Proses Server (host PC, psutil) -- BUKAN pengukuran mikrokontroler",
                      color=INK_SECONDARY, fontsize=9)
        fig.tight_layout()
        fig.savefig(os.path.join(CHARTS_DIR, "resource_usage_host.png"))
        plt.close(fig)

    log.info("Chart tersimpan di %s", CHARTS_DIR)


def main():
    device_df, server_df = load_raw_data()
    if device_df.empty and server_df.empty:
        log.warning(
            "Belum ada file results/metrics_device_*.csv maupun metrics_server_*.csv. "
            "[DATA BENCHMARK BELUM TERSEDIA] -- jalankan server.py lalu device_sim.py "
            "(atau firmware ESP32-S3) terlebih dahulu untuk menghasilkan data mentah."
        )

    summary_df = summarize(device_df, server_df)
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    summary_df.to_csv(SUMMARY_STATS_CSV, index=False)
    log.info("Statistik ringkasan (%d baris) ditulis ke %s", len(summary_df), SUMMARY_STATS_CSV)

    make_charts(summary_df)

    db_summary = load_db_summary()
    payload = {
        "generated_at_unix": pd.Timestamp.now(tz="UTC").timestamp(),
        "note": "Dashboard NON-REAL-TIME: data ini hanya diperbarui saat analyze.py dijalankan ulang.",
        "has_data": not (device_df.empty and server_df.empty),
        "summary": json.loads(summary_df.to_json(orient="records")) if not summary_df.empty else [],
        "db": db_summary,
        "experiment_params": {
            "speck_variant": "SPECK64/128",
            "mode": "CTR + HMAC-SHA256 (truncated, encrypt-then-MAC)",
            "rounds": 27,
            "repeats_per_scenario": config.REPEATS_PER_SCENARIO,
            "warmup_requests": config.WARMUP_REQUESTS,
            "payload_sizes_bytes": config.PAYLOAD_SIZES_BYTES,
        },
    }
    os.makedirs(config.DASHBOARD_DIR, exist_ok=True)
    with open(config.SUMMARY_JSON_PATH, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    log.info("dashboard/summary.json diperbarui. Buka dashboard/index.html (lewat local server) untuk melihatnya.")


if __name__ == "__main__":
    main()
