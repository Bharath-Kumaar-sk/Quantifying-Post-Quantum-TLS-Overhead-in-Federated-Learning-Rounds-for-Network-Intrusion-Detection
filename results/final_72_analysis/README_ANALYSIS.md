# Final 72-grid analysis package

Run ID: `20261104T160518Z_35ffc0d1`
Conditions: 72; connection attempts: 44,800.

## Reproduction
The script consumes both the aggregate 72-row CSV and the 44,800-row per-connection CSV. It validates their run IDs, condition keys, per-condition counts, full/resumed counts, capture flags and TLS profile algorithm evidence before generating outputs.

```bash
python generate_final_analysis.py \
  --aggregate raw_measurements_FINAL_72_GRID_COMPLETE.csv \
  --samples handshake_samples_FINAL_72_GRID_COMPLETE.csv \
  --out analysis_output
```

## Measured tables
Tables 01–12 cover the 72 conditions, 36 paired comparisons, weighted profile summaries, TLS profile matrix, high-load comparison, per-connection latency distributions, full/resumed distributions, per-condition percentiles, observed algorithm validation, cipher-suite counts, full/resumed timing and within-run bootstrap intervals.

## Measured plots
Plots 01–09 include traffic and latency scaling, paired resumption savings, per-connection traffic, high-load comparison, connection-level latency distributions, full-versus-resumed distributions and per-condition P95 heatmaps.

## Robustness / sensitivity plots
Robustness 01 models intermediate resumption hit rates using measured full/resumed traffic endpoints. Robustness 02 models assumed WAN RTT added to measured local TCP+TLS setup time (2 RTT baseline and 3 RTT stress). Robustness 03 compares measured TLS-frame traffic with one assumed model payload. These are scenarios, not WAN/Flower experiments.

## Statistical caution
Bootstrap intervals are connection-level percentile intervals within this one sequential run. They quantify observed within-run sampling variation; they are not between-run, between-machine or population-level confidence intervals. The sequential nature of the benchmark must remain explicit.

## Protocol / algorithm caveats
Negotiated groups and CertificateVerify signatures are checked on full handshakes. Empty CertificateVerify values on TLS 1.3 PSK resumptions are expected. Cipher suites are audited separately from the key-exchange group and certificate signature. All empirical byte counts are TShark frame.len totals for captured TLS/TCP frames, not a WAN link-layer measurement.

## Not included
No actual WAN emulation (`tc netem`), CPU throughput benchmark, or full Flower/gRPC model-update packet capture is performed by this script. Such claims require separate experiments.
