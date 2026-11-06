#!/usr/bin/env python3
"""Reproducible full analysis for the validated 72-condition TLS benchmark.

Inputs:
  * raw_measurements_FINAL_72_GRID_COMPLETE.csv (72 aggregate rows)
  * handshake_samples_FINAL_72_GRID_COMPLETE.csv (44,800 connection rows)

Outputs:
  * condition-level, paired, profile, high-load and per-connection summary tables
  * algorithm/cipher validation tables
  * measured-data plots and explicitly labelled scenario/sensitivity plots

The script never fabricates empirical measurements. WAN, resumption hit-rate and
payload plots are scenario models, not additional experiments.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CONFIGS = ["K1", "H1", "H2", "P1"]
CLIENTS = [5, 10, 20]
ROUNDS = [10, 50, 100]
RESUMPTIONS = ["OFF", "ON"]
EXPECTED = {
    "K1": {"group": {"29", "0x001d", "x25519"}, "signature": {"0x0403", "1027", "ecdsa_secp256r1_sha256"},
           "group_name": "X25519", "signature_name": "ECDSA P-256 / SHA-256", "key_exchange": "Classical", "auth": "Classical"},
    "H1": {"group": {"4588", "0x11ec", "x25519mlkem768"}, "signature": {"0x0403", "1027", "ecdsa_secp256r1_sha256"},
           "group_name": "X25519 + ML-KEM-768", "signature_name": "ECDSA P-256 / SHA-256", "key_exchange": "Hybrid", "auth": "Classical"},
    "H2": {"group": {"4588", "0x11ec", "x25519mlkem768"}, "signature": {"0x0905", "2309", "mldsa65"},
           "group_name": "X25519 + ML-KEM-768", "signature_name": "ML-DSA-65", "key_exchange": "Hybrid", "auth": "Post-quantum"},
    "P1": {"group": {"513", "0x0201", "mlkem768"}, "signature": {"0x0905", "2309", "mldsa65"},
           "group_name": "ML-KEM-768", "signature_name": "ML-DSA-65", "key_exchange": "Post-quantum", "auth": "Post-quantum"},
}
MODEL_STATE_BYTES = 32540  # Quantum2.ipynb: float32 parameters + BatchNorm buffers/counter

plt.rcParams.update({"font.size": 9.5, "axes.titlesize": 11, "axes.labelsize": 10,
                     "legend.fontsize": 8.5, "figure.titlesize": 13})


def norm(v):
    return "".join(ch.lower() for ch in str(v).strip() if ch.isalnum())


def matches(v, aliases):
    return norm(v) in {norm(x) for x in aliases}


def pct_reduction(a, b):
    return (float(a) - float(b)) / float(a) * 100.0 if float(a) else np.nan


def require_columns(df, cols, label):
    missing = set(cols) - set(df.columns)
    if missing:
        raise ValueError(f"{label} is missing columns: {sorted(missing)}")


def load_validate(aggregate_path: Path, samples_path: Path):
    agg = pd.read_csv(aggregate_path)
    samples = pd.read_csv(samples_path, keep_default_na=False)
    req_agg = ["Run_ID","Clients","Rounds","Config","Resumption","Execution_Model",
               "Attempted_Connections","Successful_Connections","Failed_Connections",
               "Full_Handshakes","Resumed_Handshakes","Resumption_Attempts",
               "Resumption_Hit_Rate_pct","Mean_TCP_Connect_ms","Mean_Handshake_ms",
               "Median_Handshake_ms","P95_Handshake_ms","Total_Handshake_ms",
               "TCP_Traffic_Bytes","TLS_Traffic_Bytes","Capture_Packets_Dropped",
               "Capture_Valid","Profile_Validation"]
    req_samples = ["Run_ID","Clients","Rounds","Config","Resumption","Client_ID","Round_ID",
                   "Connection_ID","Local_Port","TCP_Stream","TCP_Connect_ms","TLS_Handshake_ms",
                   "Total_Connection_ms","Session_Reused","Session_Offered","Handshake_Status",
                   "TLS_Version","Cipher","Negotiated_Group","Signature_Algorithm"]
    require_columns(agg, req_agg, "Aggregate CSV")
    require_columns(samples, req_samples, "Per-connection CSV")
    expected = {(n,r,c,s) for n in CLIENTS for r in ROUNDS for c in CONFIGS for s in RESUMPTIONS}
    ak = set(zip(agg.Clients.astype(int), agg.Rounds.astype(int), agg.Config, agg.Resumption))
    sk = set(zip(samples.Clients.astype(int), samples.Rounds.astype(int), samples.Config, samples.Resumption))
    if len(agg) != 72 or ak != expected:
        raise ValueError(f"Aggregate must contain exactly the 72 unique conditions; got {len(agg)} rows")
    if sk != expected or len(samples) != 44800:
        raise ValueError(f"Per-connection file must contain 44,800 rows across the same 72 conditions; got {len(samples)}")
    if agg.Run_ID.nunique() != 1 or samples.Run_ID.nunique() != 1 or agg.Run_ID.iloc[0] != samples.Run_ID.iloc[0]:
        raise ValueError("Aggregate and sample files must belong to the same single Run_ID")
    if not (agg.Capture_Valid == "VALID").all() or not (agg.Profile_Validation == "MATCH").all():
        raise ValueError("At least one aggregate condition failed capture/profile validation")
    if (pd.to_numeric(agg.Failed_Connections) != 0).any() or (pd.to_numeric(agg.Capture_Packets_Dropped) != 0).any():
        raise ValueError("Aggregate contains failed connections or packet drops")
    if not (samples.Handshake_Status == "SUCCESS").all() or not (samples.TLS_Version == "TLSv1.3").all():
        raise ValueError("A per-connection sample is not a successful TLS 1.3 handshake")
    for c in ["TCP_Connect_ms", "TLS_Handshake_ms", "Total_Connection_ms"]:
        samples[c] = pd.to_numeric(samples[c], errors="raise")
        if samples[c].isna().any():
            raise ValueError(f"Missing numeric measurements in {c}")
    for c in ["Clients", "Rounds", "Client_ID", "Round_ID", "Connection_ID"]:
        samples[c] = pd.to_numeric(samples[c], errors="raise").astype(int)
    samples["Session_Reused_Bool"] = samples.Session_Reused.astype(str).str.lower().map({"true": True, "false": False})
    if samples.Session_Reused_Bool.isna().any():
        raise ValueError("Unexpected Session_Reused values")
    samples["Handshake_Type"] = np.where(samples.Session_Reused_Bool, "Resumed", "Full")
    samples["Handshake_Condition"] = samples.Config + "_" + samples.Resumption
    # Exact full-handshake algorithm verification. Signature is legitimately absent on PSK resumptions.
    full = samples.loc[~samples.Session_Reused_Bool]
    audit_rows = []
    for cfg in CONFIGS:
        g = full[full.Config == cfg]
        exp = EXPECTED[cfg]
        observed_groups = sorted(g.Negotiated_Group.astype(str).unique().tolist())
        observed_sigs = sorted(g.Signature_Algorithm.astype(str).unique().tolist())
        group_ok = all(matches(x, exp["group"]) for x in observed_groups) and len(observed_groups) == 1
        sig_ok = all(matches(x, exp["signature"]) for x in observed_sigs) and len(observed_sigs) == 1
        audit_rows.append({"Config":cfg,"Expected_Group":exp["group_name"],"Observed_Group_Values":";".join(observed_groups),
                           "Full_Handshakes_Checked":len(g),"Group_Match":group_ok,
                           "Expected_CertificateVerify":exp["signature_name"],"Observed_Signature_Values":";".join(observed_sigs),
                           "Signature_Match":sig_ok,"TLS_Versions":";".join(sorted(g.TLS_Version.unique())),
                           "Cipher_Suites_All_Connections":";".join(sorted(samples.loc[samples.Config==cfg,"Cipher"].unique())),
                           "Algorithm_Audit":"PASS" if group_ok and sig_ok else "FAIL"})
    audit = pd.DataFrame(audit_rows)
    if not (audit.Algorithm_Audit == "PASS").all():
        raise ValueError("Per-connection algorithm evidence does not match the intended TLS profile")
    if samples.Cipher.nunique() != 1:
        # Not a failure, but report it: profiles may legitimately negotiate different cipher suites.
        print("WARNING: Multiple TLS cipher suites detected; inspect table_09_cipher_suite_distribution.csv", file=sys.stderr)
    samples["Total_Connections"] = samples.Clients * samples.Rounds
    agg = agg.copy()
    numeric = ["Clients","Rounds","Attempted_Connections","Successful_Connections","Failed_Connections",
               "Full_Handshakes","Resumed_Handshakes","Resumption_Attempts","Mean_TCP_Connect_ms",
               "Mean_Handshake_ms","Median_Handshake_ms","P95_Handshake_ms","Total_Handshake_ms",
               "TCP_Traffic_Bytes","TLS_Traffic_Bytes"]
    for c in numeric:
        agg[c] = pd.to_numeric(agg[c], errors="raise")
    agg["Total_Connections"] = agg.Clients * agg.Rounds
    agg["TLS_Bytes_per_Connection"] = agg.TLS_Traffic_Bytes / agg.Attempted_Connections
    agg["TCP_Bytes_per_Connection"] = agg.TCP_Traffic_Bytes / agg.Attempted_Connections
    agg["Summed_TLS_Handshake_s"] = agg.Total_Handshake_ms / 1000.0
    # Check per-condition sample denominators and exact full/resumed counts against aggregate.
    grouped = samples.groupby(["Clients","Rounds","Config","Resumption"], as_index=False).agg(
        Sample_Count=("Connection_ID","size"), Sample_Full=("Session_Reused_Bool",lambda x:int((~x).sum())),
        Sample_Resumed=("Session_Reused_Bool",lambda x:int(x.sum())))
    merged = agg.merge(grouped, on=["Clients","Rounds","Config","Resumption"], how="left", validate="one_to_one")
    if (merged.Sample_Count != merged.Attempted_Connections).any():
        raise ValueError("Per-condition sample counts do not agree with aggregate attempts")
    if (merged.Sample_Full != merged.Full_Handshakes).any() or (merged.Sample_Resumed != merged.Resumed_Handshakes).any():
        raise ValueError("Full/resumed handshake counts do not agree between aggregate and sample files")
    agg = agg.sort_values(["Clients","Rounds","Config","Resumption"]).reset_index(drop=True)
    return agg, samples, audit


def describe_latency(g):
    x = g.TLS_Handshake_ms.to_numpy(dtype=float)
    med = float(np.median(x))
    mad = float(np.median(np.abs(x-med)))
    return {"Connections":len(x),"Mean_ms":float(np.mean(x)),"StdDev_ms":float(np.std(x,ddof=1)),
            "Median_ms":med,"MAD_ms":mad,"P05_ms":float(np.quantile(x,.05)),"P25_ms":float(np.quantile(x,.25)),
            "P75_ms":float(np.quantile(x,.75)),"P95_ms":float(np.quantile(x,.95)),"P99_ms":float(np.quantile(x,.99)),
            "Min_ms":float(np.min(x)),"Max_ms":float(np.max(x))}


def make_tables(agg, samples, audit, out):
    t=out/"tables"; t.mkdir(parents=True,exist_ok=True)
    cols=["Run_ID","Clients","Rounds","Total_Connections","Config","Resumption","Execution_Model",
          "Attempted_Connections","Successful_Connections","Failed_Connections","Full_Handshakes","Resumed_Handshakes",
          "Resumption_Attempts","Sessions_Offered","Resumption_Misses","Resumption_Failures","Resumption_Hit_Rate_pct",
          "Mean_TCP_Connect_ms","Mean_Handshake_ms","Median_Handshake_ms","P95_Handshake_ms","Total_Handshake_ms",
          "Summed_TLS_Handshake_s","TLS_Traffic_Bytes","TLS_Bytes_per_Connection","TCP_Traffic_Bytes","TCP_Bytes_per_Connection",
          "Capture_Packets_Dropped","Capture_Valid","Profile_Validation","PCAP_File"]
    agg[[c for c in cols if c in agg.columns]].to_csv(t/"table_01_all_72_measured_conditions.csv",index=False)
    idx=["Clients","Rounds","Total_Connections","Config"]
    off=agg[agg.Resumption=="OFF"].set_index(idx); on=agg[agg.Resumption=="ON"].set_index(idx)
    paired=pd.DataFrame(index=off.index)
    for label,col in [("TLS_Frame_Bytes","TLS_Traffic_Bytes"),("TCP_Frame_Bytes","TCP_Traffic_Bytes"),
                      ("Summed_Handshake_ms","Total_Handshake_ms"),("Mean_Handshake_ms","Mean_Handshake_ms"),
                      ("Median_Handshake_ms","Median_Handshake_ms"),("P95_Handshake_ms","P95_Handshake_ms")]:
        paired[label+"_OFF"]=off[col]; paired[label+"_ON"]=on[col]
        paired[label+"_Reduction_pct"]=[pct_reduction(a,b) for a,b in zip(off[col],on[col])]
    paired["Resumed_Handshakes_ON"]=on.Resumed_Handshakes
    paired["Resumption_Attempts_ON"]=on.Resumption_Attempts
    paired["Resumption_Hit_Rate_pct_ON"]=on.Resumption_Hit_Rate_pct
    paired.reset_index().to_csv(t/"table_02_off_on_paired_comparison_36.csv",index=False)
    summaries=[]
    for cfg in CONFIGS:
        for mode in RESUMPTIONS:
            q=agg[(agg.Config==cfg)&(agg.Resumption==mode)]
            n=int(q.Attempted_Connections.sum()); total_hs=float(q.Total_Handshake_ms.sum())
            summaries.append({"Config":cfg,"Resumption":mode,"Conditions":len(q),"Connections":n,
                              "TLS_Frame_Bytes_Total":int(q.TLS_Traffic_Bytes.sum()),"TLS_Bytes_per_Connection":q.TLS_Traffic_Bytes.sum()/n,
                              "TCP_Frame_Bytes_Total":int(q.TCP_Traffic_Bytes.sum()),"TCP_Bytes_per_Connection":q.TCP_Traffic_Bytes.sum()/n,
                              "Connection_Weighted_Mean_Handshake_ms":total_hs/n,"Summed_Handshake_s":total_hs/1000,
                              "Full_Handshakes":int(q.Full_Handshakes.sum()),"Resumed_Handshakes":int(q.Resumed_Handshakes.sum()),
                              "Resumption_Attempts":int(q.Resumption_Attempts.sum()),
                              "Resumption_Hit_Rate_pct":(q.Resumed_Handshakes.sum()/q.Resumption_Attempts.sum()*100 if q.Resumption_Attempts.sum() else np.nan)})
    pd.DataFrame(summaries).to_csv(t/"table_03_profile_summary_weighted.csv",index=False)
    profile_rows=[]
    for cfg,e in EXPECTED.items():
        profile_rows.append({"Config":cfg,"Key_Exchange_Group":e["group_name"],"Key_Exchange_Type":e["key_exchange"],
                             "Server_Authentication":e["signature_name"],"Authentication_Type":e["auth"],
                             "Classification":{"K1":"Classical baseline","H1":"Hybrid KEX / classical authentication",
                                               "H2":"Hybrid KEX / post-quantum authentication","P1":"Post-quantum KEX and authentication"}[cfg]})
    pd.DataFrame(profile_rows).to_csv(t/"table_04_tls_profile_matrix.csv",index=False)
    h=agg[(agg.Clients==20)&(agg.Rounds==100)]
    high=[]
    for cfg in CONFIGS:
        a=h[(h.Config==cfg)&(h.Resumption=="OFF")].iloc[0]; b=h[(h.Config==cfg)&(h.Resumption=="ON")].iloc[0]
        high.append({"Config":cfg,"TLS_Bytes_OFF":a.TLS_Traffic_Bytes,"TLS_Bytes_ON":b.TLS_Traffic_Bytes,
                     "TLS_Bytes_Reduction_pct":pct_reduction(a.TLS_Traffic_Bytes,b.TLS_Traffic_Bytes),
                     "TCP_Bytes_OFF":a.TCP_Traffic_Bytes,"TCP_Bytes_ON":b.TCP_Traffic_Bytes,
                     "Summed_Handshake_ms_OFF":a.Total_Handshake_ms,"Summed_Handshake_ms_ON":b.Total_Handshake_ms,
                     "Mean_Handshake_ms_OFF":a.Mean_Handshake_ms,"Mean_Handshake_ms_ON":b.Mean_Handshake_ms,
                     "Resumption_Hit_Rate_pct_ON":b.Resumption_Hit_Rate_pct})
    pd.DataFrame(high).to_csv(t/"table_05_high_load_N20_R100.csv",index=False)
    latency=[]
    for (cfg,mode),g in samples.groupby(["Config","Resumption"],sort=True):
        latency.append({"Config":cfg,"Resumption":mode,**describe_latency(g),
                        "Mean_TCP_Connect_ms":g.TCP_Connect_ms.mean(),"Mean_Total_Connection_ms":g.Total_Connection_ms.mean()})
    latdf=pd.DataFrame(latency); latdf.to_csv(t/"table_06_connection_latency_distribution_by_profile_mode.csv",index=False)
    bytype=[]
    for (cfg,mode,ht),g in samples.groupby(["Config","Resumption","Handshake_Type"],sort=True):
        bytype.append({"Config":cfg,"Resumption":mode,"Handshake_Type":ht,**describe_latency(g)})
    bytype=pd.DataFrame(bytype); bytype.to_csv(t/"table_07_full_vs_resumed_latency_distribution.csv",index=False)
    cond=[]
    for keys,g in samples.groupby(["Clients","Rounds","Config","Resumption"],sort=True):
        cond.append({"Clients":keys[0],"Rounds":keys[1],"Config":keys[2],"Resumption":keys[3],**describe_latency(g),
                     "Mean_TCP_Connect_ms":g.TCP_Connect_ms.mean(),"Mean_Total_Connection_ms":g.Total_Connection_ms.mean()})
    pd.DataFrame(cond).to_csv(t/"table_08_per_condition_latency_distribution_72.csv",index=False)
    # Profile observations from full certificate-authenticated handshakes only.
    audit.to_csv(t/"table_09_algorithm_validation_from_samples.csv",index=False)
    cipher=(samples.groupby(["Config","Resumption","Cipher"],as_index=False).size().rename(columns={"size":"Connections"}))
    cipher.to_csv(t/"table_10_cipher_suite_distribution.csv",index=False)
    # Separate full and resumed latency for each profile, especially useful for resumed TLS 1.3 handshakes.
    reuse=[]
    for cfg in CONFIGS:
        for ht,g in samples[samples.Config==cfg].groupby("Handshake_Type"):
            reuse.append({"Config":cfg,"Handshake_Type":ht,**describe_latency(g)})
    pd.DataFrame(reuse).to_csv(t/"table_11_full_vs_resumed_latency_by_profile.csv",index=False)
    # Connection-level percentile bootstrap: within-this-run uncertainty, not independent-run replication.
    rng=np.random.default_rng(20261104); boot=[]
    for (cfg,mode),g in samples.groupby(["Config","Resumption"],sort=True):
        x=g.TLS_Handshake_ms.to_numpy(float); means=np.empty(2000)
        for start in range(0,2000,100):
            size=min(100,2000-start)
            idxs=rng.integers(0,len(x),size=(size,len(x)))
            means[start:start+size]=x[idxs].mean(axis=1)
        boot.append({"Config":cfg,"Resumption":mode,"N":len(x),"Observed_Mean_ms":float(x.mean()),
                     "Bootstrap_Mean_95CI_Lower_ms":float(np.quantile(means,.025)),
                     "Bootstrap_Mean_95CI_Upper_ms":float(np.quantile(means,.975)),"Bootstrap_Replicates":2000,
                     "Method":"Connection-level percentile bootstrap within this single sequential run; not between-run CI"})
    pd.DataFrame(boot).to_csv(t/"table_12_bootstrap_mean_latency_ci.csv",index=False)
    return paired.reset_index(),latdf,bytype,cond


def plot_scaling(agg,metric,ylabel,title,filename,out,per_connection=False):
    fig,axes=plt.subplots(1,2,figsize=(15,5.8),sharey=True)
    order=[(n,r) for n in CLIENTS for r in ROUNDS]
    for ax,mode in zip(axes,RESUMPTIONS):
        q=agg[agg.Resumption==mode]
        for cfg in CONFIGS:
            vals=[]
            for n,r in order:
                z=q[(q.Clients==n)&(q.Rounds==r)&(q.Config==cfg)].iloc[0]
                vals.append(float(z[metric])/(float(z.Attempted_Connections) if per_connection else 1))
            ax.plot(range(9),vals,marker="o",linewidth=1.7,label=cfg)
        ax.set_title(f"Resumption {mode}"); ax.set_xticks(range(9),[f"{n}×{r}" for n,r in order],rotation=35,ha="right")
        ax.set_xlabel("Clients × rounds"); ax.grid(True,linestyle=":",alpha=.5); ax.legend(title="Profile")
    axes[0].set_ylabel(ylabel); fig.suptitle(title); fig.tight_layout()
    fig.savefig(out/"plots"/filename,dpi=240,bbox_inches="tight"); plt.close(fig)


def make_main_plots(agg,samples,paired,out):
    p=out/"plots"; p.mkdir(parents=True,exist_ok=True)
    plot_scaling(agg,"TLS_Traffic_Bytes","Captured TLS-frame bytes per condition","TLS traffic scaling across the 72-condition grid","plot_01_tls_traffic_scaling.png",out)
    plot_scaling(agg,"Summed_TLS_Handshake_s","Summed per-connection do_handshake() time (s)","Sum of individually measured TLS handshake durations","plot_02_summed_handshake_time.png",out)
    plot_scaling(agg,"Mean_Handshake_ms","Mean per-connection TLS handshake time (ms)","Mean TLS handshake latency across the 72-condition grid","plot_03_mean_handshake_latency.png",out)
    # Paired OFF/ON measured traffic reduction.
    fig,axes=plt.subplots(2,2,figsize=(13,8),sharex=True,sharey=True)
    for ax,cfg in zip(axes.flat,CONFIGS):
        q=paired[paired.Config==cfg]; piv=q.pivot(index="Clients",columns="Rounds",values="TLS_Frame_Bytes_Reduction_pct").reindex(index=CLIENTS,columns=ROUNDS)
        im=ax.imshow(piv.values,aspect="auto",vmin=-5,vmax=100)
        ax.set_title(cfg); ax.set_xticks(range(3),ROUNDS); ax.set_yticks(range(3),CLIENTS)
        ax.set_xlabel("Rounds"); ax.set_ylabel("Clients")
        for i in range(3):
            for j in range(3): ax.text(j,i,f"{piv.iloc[i,j]:.1f}%",ha="center",va="center",fontsize=8)
    fig.colorbar(im,ax=axes.ravel().tolist(),label="TLS-frame traffic reduction (%)",shrink=.85)
    fig.suptitle("Measured traffic reduction from TLS session resumption"); fig.savefig(p/"plot_04_resumption_traffic_reduction_heatmap.png",dpi=240,bbox_inches="tight"); plt.close(fig)
    # Per-connection normalized traffic N=20.
    fig,axes=plt.subplots(1,2,figsize=(14,5.5),sharey=True)
    for ax,mode in zip(axes,RESUMPTIONS):
        q=agg[(agg.Clients==20)&(agg.Resumption==mode)]
        for cfg in CONFIGS:
            z=q[q.Config==cfg].sort_values("Rounds"); ax.plot(z.Rounds,z.TLS_Bytes_per_Connection,marker="o",label=cfg)
        ax.set_title(f"Resumption {mode}"); ax.set_xlabel("Rounds"); ax.grid(True,linestyle=":",alpha=.5); ax.legend(title="Profile")
    axes[0].set_ylabel("Captured TLS-frame bytes per connection"); fig.suptitle("Per-connection TLS traffic at N=20"); fig.tight_layout(); fig.savefig(p/"plot_05_per_connection_tls_traffic.png",dpi=240,bbox_inches="tight"); plt.close(fig)
    # High load N20/R100.
    q=agg[(agg.Clients==20)&(agg.Rounds==100)]; x=np.arange(4); width=.36
    fig,axes=plt.subplots(1,2,figsize=(13,5.4))
    for ax,metric,title,ylab in [(axes[0],"TLS_Traffic_Bytes","High-load TLS-frame traffic","Bytes (log scale)"),(axes[1],"Total_Handshake_ms","Summed handshake time","Milliseconds")]:
        off=[float(q[(q.Config==c)&(q.Resumption=="OFF")].iloc[0][metric]) for c in CONFIGS]
        on=[float(q[(q.Config==c)&(q.Resumption=="ON")].iloc[0][metric]) for c in CONFIGS]
        ax.bar(x-width/2,off,width,label="OFF"); ax.bar(x+width/2,on,width,label="ON")
        if metric=="TLS_Traffic_Bytes": ax.set_yscale("log")
        ax.set_xticks(x,CONFIGS); ax.set_title(title); ax.set_ylabel(ylab); ax.grid(axis="y",linestyle=":",alpha=.5); ax.legend()
    fig.suptitle("High load: N=20, R=100"); fig.tight_layout(); fig.savefig(p/"plot_06_high_load_profile_comparison.png",dpi=240,bbox_inches="tight"); plt.close(fig)
    # Per-connection latency distributions (boxplot summaries built from all raw samples).
    fig,axes=plt.subplots(1,2,figsize=(14,6),sharey=True)
    for ax,mode in zip(axes,RESUMPTIONS):
        data=[samples[(samples.Config==c)&(samples.Resumption==mode)].TLS_Handshake_ms.to_numpy() for c in CONFIGS]
        ax.boxplot(data,tick_labels=CONFIGS,showfliers=False,showmeans=True)
        ax.set_title(f"Resumption {mode}"); ax.set_xlabel("TLS profile"); ax.grid(axis="y",linestyle=":",alpha=.5)
    axes[0].set_ylabel("Per-connection TLS handshake time (ms)"); fig.suptitle("Connection-level TLS handshake latency distributions (44,800 samples)")
    fig.tight_layout(); fig.savefig(p/"plot_07_latency_distributions_boxplot.png",dpi=240,bbox_inches="tight"); plt.close(fig)
    # Full vs resumed handshake latency.
    fig,axes=plt.subplots(1,4,figsize=(16,5.4),sharey=True)
    for ax,cfg in zip(axes,CONFIGS):
        q=samples[samples.Config==cfg]
        d=[q[q.Handshake_Type==typ].TLS_Handshake_ms.to_numpy() for typ in ["Full","Resumed"]]
        ax.boxplot(d,tick_labels=["Full","Resumed"],showfliers=False,showmeans=True)
        ax.set_title(cfg); ax.grid(axis="y",linestyle=":",alpha=.5)
    axes[0].set_ylabel("Per-connection TLS handshake time (ms)"); fig.suptitle("Full versus resumed TLS 1.3 handshake latency")
    fig.tight_layout(); fig.savefig(p/"plot_08_full_vs_resumed_latency.png",dpi=240,bbox_inches="tight"); plt.close(fig)
    # P95 latency heatmaps, one panel per profile/mode, values computed from raw records.
    fig,axes=plt.subplots(2,4,figsize=(16,7),sharex=True,sharey=True)
    for j,cfg in enumerate(CONFIGS):
        for i,mode in enumerate(RESUMPTIONS):
            ax=axes[i,j]; q=samples[(samples.Config==cfg)&(samples.Resumption==mode)]
            mat=np.zeros((3,3))
            for a,n in enumerate(CLIENTS):
                for b,r in enumerate(ROUNDS):
                    z=q[(q.Clients==n)&(q.Rounds==r)].TLS_Handshake_ms
                    mat[a,b]=z.quantile(.95)
            im=ax.imshow(mat,aspect="auto")
            ax.set_title(f"{cfg} / {mode}"); ax.set_xticks(range(3),ROUNDS); ax.set_yticks(range(3),CLIENTS)
            for a in range(3):
                for b in range(3): ax.text(b,a,f"{mat[a,b]:.2f}",ha="center",va="center",fontsize=7)
    fig.colorbar(im,ax=axes.ravel().tolist(),label="P95 handshake latency (ms)",shrink=.8)
    fig.suptitle("P95 handshake latency across clients and rounds"); fig.savefig(p/"plot_09_p95_latency_heatmaps.png",dpi=240,bbox_inches="tight"); plt.close(fig)


def make_robustness(agg,samples,out):
    p=out/"plots"; t=out/"tables"
    # Hit-rate model decomposed into measured full and resumed traffic components.
    rows=[]; n=20; r=100; eligible=n*(r-1)
    for cfg in CONFIGS:
        off=agg[(agg.Clients==n)&(agg.Rounds==r)&(agg.Config==cfg)&(agg.Resumption=="OFF")].iloc[0]
        on=agg[(agg.Clients==n)&(agg.Rounds==r)&(agg.Config==cfg)&(agg.Resumption=="ON")].iloc[0]
        full_bytes=float(off.TLS_Traffic_Bytes)/int(off.Attempted_Connections)
        resumed_count=int(on.Resumed_Handshakes)
        initial_full=n
        resumed_bytes=(float(on.TLS_Traffic_Bytes)-initial_full*full_bytes)/resumed_count if resumed_count else np.nan
        for hit in np.linspace(0,1,11):
            est=initial_full*full_bytes+eligible*((1-hit)*full_bytes+hit*resumed_bytes)
            rows.append({"Clients":n,"Rounds":r,"Config":cfg,"Assumed_Eligible_Resumption_Hit_Rate_pct":hit*100,
                         "Measured_Full_Handshake_TLS_Bytes_per_Connection":full_bytes,
                         "Estimated_Resumed_TLS_Bytes_per_Connection":resumed_bytes,"Estimated_Total_TLS_Frame_Bytes":est,
                         "Model":"Full and resumed bytes decomposed from N20/R100 OFF/ON measured totals; hit rate is scenario"})
    churn=pd.DataFrame(rows); churn.to_csv(t/"robustness_01_resumption_hit_rate_scenario.csv",index=False)
    fig,ax=plt.subplots(figsize=(9,5.5))
    for cfg in CONFIGS:
        q=churn[churn.Config==cfg]; ax.plot(q.Assumed_Eligible_Resumption_Hit_Rate_pct,q.Estimated_Total_TLS_Frame_Bytes/1e6,marker="o",label=cfg)
    ax.set_xlabel("Assumed hit rate among eligible post-first-round connections (%)"); ax.set_ylabel("Estimated TLS-frame traffic (MB)")
    ax.set_title("Resumption hit-rate sensitivity at N=20, R=100"); ax.grid(True,linestyle=":",alpha=.5); ax.legend(title="Profile")
    fig.text(.5,.01,"Scenario model decomposed from measured full/resumed endpoints; intermediate hit rates were not experimentally run.",ha="center",fontsize=8)
    fig.tight_layout(rect=[0,.05,1,1]); fig.savefig(p/"robustness_01_resumption_hit_rate.png",dpi=240,bbox_inches="tight"); plt.close(fig)
    # RTT sensitivity: assume one RTT for TCP establishment and one RTT for TLS 1.3 handshake; 3-RTT is stress.
    wan=[]; rtts=[1,5,10,20,45,75,100,150,200]
    for cfg in CONFIGS:
        for mode in RESUMPTIONS:
            q=samples[(samples.Config==cfg)&(samples.Resumption==mode)&(samples.Clients==20)&(samples.Rounds==100)]
            local=float(q.Total_Connection_ms.mean())
            for rtt in rtts:
                wan.append({"Config":cfg,"Resumption":mode,"Assumed_RTT_ms":rtt,"Measured_Loopback_Total_Connection_ms":local,
                            "Estimated_Total_Setup_ms_2RTT":local+2*rtt,"Estimated_Total_Setup_ms_3RTT_Stress":local+3*rtt,
                            "Assumption":"Local TCP+TLS setup mean plus 1 TCP RTT + 1 TLS 1.3 RTT; 3 RTT is stress scenario; not tc/netem data"})
    wdf=pd.DataFrame(wan); wdf.to_csv(t/"robustness_02_wan_rtt_scenario.csv",index=False)
    fig,axes=plt.subplots(1,2,figsize=(14,5.5),sharey=True)
    for ax,mode in zip(axes,RESUMPTIONS):
        for cfg in CONFIGS:
            q=wdf[(wdf.Config==cfg)&(wdf.Resumption==mode)]
            ax.plot(q.Assumed_RTT_ms,q.Estimated_Total_Setup_ms_2RTT,marker="o",label=f"{cfg} (2 RTT)")
            ax.plot(q.Assumed_RTT_ms,q.Estimated_Total_Setup_ms_3RTT_Stress,linestyle="--",alpha=.6,label=f"{cfg} (3 RTT stress)")
        ax.set_title(f"Resumption {mode}"); ax.set_xlabel("Assumed network RTT (ms)"); ax.grid(True,linestyle=":",alpha=.5)
    axes[0].set_ylabel("Estimated TCP + TLS setup time (ms)"); axes[1].legend(bbox_to_anchor=(1.02,1),loc="upper left",fontsize=7)
    fig.suptitle("WAN RTT sensitivity scenario (N=20, R=100)"); fig.text(.5,.01,"Modeled from measured loopback total setup times; no WAN emulation was performed.",ha="center",fontsize=8)
    fig.tight_layout(rect=[0,.05,.82,.94]); fig.savefig(p/"robustness_02_wan_rtt_sensitivity.png",dpi=240,bbox_inches="tight"); plt.close(fig)
    # Model payload sensitivity.
    payload_kib=[1,2,4,8,16,24,MODEL_STATE_BYTES/1024,48,64,128,256,512,1024]
    vals=[]
    for cfg in CONFIGS:
        for mode in RESUMPTIONS:
            row=agg[(agg.Clients==20)&(agg.Rounds==100)&(agg.Config==cfg)&(agg.Resumption==mode)].iloc[0]
            tls_per=float(row.TLS_Traffic_Bytes)/int(row.Attempted_Connections)
            for payload in payload_kib:
                pbytes=payload*1024
                vals.append({"Config":cfg,"Resumption":mode,"Model_Update_Payload_KiB":payload,
                             "Measured_TLS_Frame_Bytes_per_Connection":tls_per,
                             "TLS_Fraction_of_TLS_plus_One_Model_Payload_pct":tls_per/(tls_per+pbytes)*100,
                             "Model_State_Tensor_Bytes":MODEL_STATE_BYTES,
                             "Assumption":"One update payload; excludes Flower/gRPC framing, compression, retransmission and transfer multiplicity"})
    pdf=pd.DataFrame(vals); pdf.to_csv(t/"robustness_03_model_payload_sensitivity.csv",index=False)
    fig,axes=plt.subplots(1,2,figsize=(14,5.5),sharey=True)
    for ax,mode in zip(axes,RESUMPTIONS):
        for cfg in CONFIGS:
            q=pdf[(pdf.Config==cfg)&(pdf.Resumption==mode)]
            ax.plot(q.Model_Update_Payload_KiB,q.TLS_Fraction_of_TLS_plus_One_Model_Payload_pct,marker="o",label=cfg)
        ax.axvline(MODEL_STATE_BYTES/1024,linestyle=":",color="black",label=f"Model state {MODEL_STATE_BYTES/1024:.1f} KiB")
        ax.set_xscale("log"); ax.set_title(f"Resumption {mode}"); ax.set_xlabel("One model-update payload (KiB, log scale)"); ax.grid(True,which="both",linestyle=":",alpha=.5)
    axes[0].set_ylabel("TLS-frame bytes / (TLS-frame bytes + model payload) (%)"); axes[1].legend(bbox_to_anchor=(1.02,1),loc="upper left",fontsize=7)
    fig.suptitle("TLS setup-traffic fraction versus model-update payload size"); fig.text(.5,.01,"Scenario using measured TLS-frame traffic and model tensor size; not a Flower/gRPC packet capture.",ha="center",fontsize=8)
    fig.tight_layout(rect=[0,.05,.82,.94]); fig.savefig(p/"robustness_03_model_payload_sensitivity.png",dpi=240,bbox_inches="tight"); plt.close(fig)
    pd.DataFrame([{"Model_Architecture":"Linear(87,64) + BatchNorm1d(64) + Linear(64,32) + Linear(32,5)",
                   "State_Tensor_Bytes":MODEL_STATE_BYTES,"State_Tensor_KiB":MODEL_STATE_BYTES/1024,
                   "Caveat":"Tensor payload only; excludes serialization/protocol framing and transfer multiplicity"}]).to_csv(t/"model_payload_size_calculation.csv",index=False)


def write_readme(agg,out):
    lines=["# Final 72-grid analysis package", "", f"Run ID: `{agg.Run_ID.iloc[0]}`", f"Conditions: {len(agg)}; connection attempts: {int(agg.Attempted_Connections.sum()):,}.",
           "", "## Reproduction", "The script consumes both the aggregate 72-row CSV and the 44,800-row per-connection CSV. It validates their run IDs, condition keys, per-condition counts, full/resumed counts, capture flags and TLS profile algorithm evidence before generating outputs.",
           "", "```bash", "python generate_final_analysis.py \\", "  --aggregate raw_measurements_FINAL_72_GRID_COMPLETE.csv \\", "  --samples handshake_samples_FINAL_72_GRID_COMPLETE.csv \\", "  --out analysis_output", "```",
           "", "## Measured tables", "Tables 01–12 cover the 72 conditions, 36 paired comparisons, weighted profile summaries, TLS profile matrix, high-load comparison, per-connection latency distributions, full/resumed distributions, per-condition percentiles, observed algorithm validation, cipher-suite counts, full/resumed timing and within-run bootstrap intervals.",
           "", "## Measured plots", "Plots 01–09 include traffic and latency scaling, paired resumption savings, per-connection traffic, high-load comparison, connection-level latency distributions, full-versus-resumed distributions and per-condition P95 heatmaps.",
           "", "## Robustness / sensitivity plots", "Robustness 01 models intermediate resumption hit rates using measured full/resumed traffic endpoints. Robustness 02 models assumed WAN RTT added to measured local TCP+TLS setup time (2 RTT baseline and 3 RTT stress). Robustness 03 compares measured TLS-frame traffic with one assumed model payload. These are scenarios, not WAN/Flower experiments.",
           "", "## Statistical caution", "Bootstrap intervals are connection-level percentile intervals within this one sequential run. They quantify observed within-run sampling variation; they are not between-run, between-machine or population-level confidence intervals. The sequential nature of the benchmark must remain explicit.",
           "", "## Protocol / algorithm caveats", "Negotiated groups and CertificateVerify signatures are checked on full handshakes. Empty CertificateVerify values on TLS 1.3 PSK resumptions are expected. Cipher suites are audited separately from the key-exchange group and certificate signature. All empirical byte counts are TShark frame.len totals for captured TLS/TCP frames, not a WAN link-layer measurement.",
           "", "## Not included", "No actual WAN emulation (`tc netem`), CPU throughput benchmark, or full Flower/gRPC model-update packet capture is performed by this script. Such claims require separate experiments."]
    (out/"README_ANALYSIS.md").write_text("\n".join(lines)+"\n")


def main():
    ap=argparse.ArgumentParser(description="Generate complete tables, measured plots and scenario robustness plots for the validated TLS 72-grid.")
    ap.add_argument("--aggregate",type=Path,required=True)
    ap.add_argument("--samples",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args(); args.out.mkdir(parents=True,exist_ok=True)
    agg,samples,audit=load_validate(args.aggregate,args.samples)
    paired,latdf,bytype,cond=make_tables(agg,samples,audit,args.out)
    make_main_plots(agg,samples,paired,args.out)
    make_robustness(agg,samples,args.out)
    write_readme(agg,args.out)
    print("INPUT VALIDATION PASSED")
    print(f"Run ID: {agg.Run_ID.iloc[0]}")
    print(f"Aggregate conditions: {len(agg)}; per-connection samples: {len(samples):,}")
    print(f"Algorithm profiles matched: {len(audit)}/{len(CONFIGS)}")
    print(f"Cipher suites observed: {', '.join(sorted(samples.Cipher.unique()))}")
    print(f"Generated 12 core summary tables + 4 robustness-support tables, 9 main plots and 3 robustness/sensitivity plots in: {args.out}")

if __name__=="__main__":
    try: main()
    except Exception as exc:
        print(f"ANALYSIS FAILED: {type(exc).__name__}: {exc}",file=sys.stderr)
        raise
