"""Generate a small, hand-labelled CSV to verify detector output by eye.

The file is written in the **raw UNSW-NB15 layout** (49 columns, NO header row),
exactly like the real UNSW-NB15_1..4.csv captures, so it runs with ``--raw``:

    python scripts/make_check_dataset.py
    python network_bouncer.py check_dataset.csv --raw

Every source host is a *deliberately obvious* case, so you can confirm the
verdict matches the expectation. The last column is the ground-truth ``label``
(1 = scanner, 0 = benign); see CHECK_DATASET_ANSWERS.md for the full key.

Only the columns the host detector reads are filled meaningfully
(srcip, sport, dstip, dsport, proto, state, service, attack_cat, label); the
rest are zero-filled, mirroring how the real capture's extra features are
ignored by host-based detection.
"""

from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.constants import UNSW_RAW_COLUMNS  # noqa: E402

ROWS: list[list] = []


def add(srcip, sport, dstip, dsport, proto, service, state, attack_cat, label):
    """Append one flow as a full 49-field raw UNSW-NB15 row (extras zero-filled)."""
    row = {c: 0 for c in UNSW_RAW_COLUMNS}
    row.update(
        srcip=srcip, sport=sport, dstip=dstip, dsport=dsport, proto=proto,
        service=service, state=state, attack_cat=attack_cat, label=label,
    )
    ROWS.append([row[c] for c in UNSW_RAW_COLUMNS])


# --------------------------------------------------------------------------- #
# BENIGN hosts (label 0) — should stay "Normal"
# --------------------------------------------------------------------------- #
# 1) Web client: 14 normal HTTPS sessions to ONE server, all established.
for i in range(14):
    add("10.0.0.10", 40000 + i, "10.0.0.100", 443, "tcp", "https", "FIN", "Normal", 0)

# 2) DB client: 18 sessions to 3 known DB servers on one port, established.
for i in range(18):
    add("10.0.0.11", 41000 + i, f"10.0.0.10{1 + (i % 3)}", 3306, "tcp", "mysql", "FIN", "Normal", 0)

# 3) Mixed normal traffic to 2 services (https + dns), established.
for i in range(12):
    dst, port, svc = ("10.0.0.105", 443, "https") if i % 2 else ("10.0.0.106", 53, "dns")
    add("10.0.0.12", 42000 + i, dst, port, "tcp", svc, "FIN", "Normal", 0)

# 4) EDGE CASE: looks scanny (8 distinct dests + ports) but only 8 flows —
#    below the volume floor (min_connections=10), so it must NOT be flagged.
for i in range(8):
    add("10.0.0.20", 43000 + i, f"10.5.0.{i}", 1000 + i, "tcp", "-", "INT", "Normal", 0)


# --------------------------------------------------------------------------- #
# SCANNERS (label 1) — should be flagged "Suspicious"
# --------------------------------------------------------------------------- #
# 5) HORIZONTAL scan: one source -> 40 different hosts, same port 80.
for i in range(40):
    add("10.0.0.50", 50000 + i, f"10.1.0.{i}", 80, "tcp", "-", "INT", "Reconnaissance", 1)

# 6) VERTICAL scan: one source -> ONE host, 40 different ports.
for i in range(40):
    add("10.0.0.51", 51000 + i, "10.2.0.5", 1000 + i, "tcp", "-", "REQ", "Reconnaissance", 1)

# 7) BLOCK scan: 20 hosts x 20 ports = 400 flows (many ports across many hosts).
for d in range(20):
    for p in range(20):
        add("10.0.0.52", 52000 + (d * 20 + p), f"10.3.0.{d}", 2000 + p, "tcp", "-", "INT", "Analysis", 1)


def main() -> None:
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "check_dataset.csv")
    with open(out, "w", newline="", encoding="utf-8") as fh:
        # No header row — raw UNSW-NB15 layout. Run the tool with --raw.
        csv.writer(fh).writerows(ROWS)
    print(f"Wrote {len(ROWS)} headerless rows ({len(UNSW_RAW_COLUMNS)} cols) for 7 hosts -> {out}")
    print("Run:  python network_bouncer.py check_dataset.csv --raw")


if __name__ == "__main__":
    main()
