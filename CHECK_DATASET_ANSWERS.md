# ✅ Check Dataset — Answer Key

A hand-built dataset to verify the detector produces the *correct* verdict.
The CSV is written in the **raw UNSW-NB15 layout (49 columns, no header row)**,
just like the real `UNSW-NB15_1..4.csv` captures — so run it with `--raw`:

```bash
python scripts/make_check_dataset.py        # writes check_dataset.csv (532 rows, 7 hosts)
python network_bouncer.py check_dataset.csv --raw
```

Then compare the tool's verdict against this table. **The last column (`label`)
is the ground truth** (1 = scanner, 0 = benign).

| Source IP | What it is | label | Expected verdict | Why |
|---|---|:---:|---|---|
| `10.0.0.10` | Web client — 14 HTTPS sessions to **1** server | 0 | **Normal** | Repeated traffic to one service; no diversity |
| `10.0.0.11` | DB client — 18 sessions to 3 servers, port 3306 | 0 | **Normal** | Few destinations, one port, established |
| `10.0.0.12` | Mixed normal traffic (https + dns) | 0 | **Normal** | 2 destinations, 2 known services |
| `10.0.0.20` | **Edge case** — 8 distinct dests + ports | 0 | **Normal** | *Looks* scanny but only 8 flows → below the volume floor (`min_connections=10`) |
| `10.0.0.50` | **Horizontal scan** — 1 src → 40 hosts, port 80 | 1 | **Suspicious / High** | 40 destinations, each touched ~once |
| `10.0.0.51` | **Vertical scan** — 1 src → 1 host, 40 ports | 1 | **Suspicious / High** | 40 ports on one host, every flow a fresh port |
| `10.0.0.52` | **Block scan** — 20 hosts × 20 ports = 400 flows | 1 | **Suspicious / High** | Many ports across many hosts simultaneously |

## Actual tool output (verified)

```
Flagged hosts       : 3 of 7
Severity breakdown  : Critical=0  High=3  Medium=0  Low=0

10.0.0.52  Block scan   High  →  swept 20 ports across 20 hosts; no known service; never established
10.0.0.51  Vertical     High  →  probed 40 ports on 1 host; 100% fresh ports; never established
10.0.0.50  Horizontal   High  →  contacted 40 destinations; ~1 conn/dest; never established
```

✅ **All 3 scanners flagged. All 4 benign hosts (incl. the edge case) stay Normal. Zero false positives.**

## What this proves

- **True positives:** every host with `label=1` is flagged.
- **True negatives:** every host with `label=0` is Normal — including `10.0.0.20`,
  which proves the **volume floor** stops small probes from over-alerting.
- **Explainability:** each alert lists the exact rule + numbers that fired.

> Tip: run `python network_bouncer.py check_dataset.csv --raw --sensitivity high`
> — `10.0.0.20` (the 8-flow edge host) starts to get flagged, because
> `min_connections` drops to 5. That demonstrates the sensitivity slider working.
