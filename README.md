# Quantifying Post-Quantum TLS Overhead in Federated Learning Rounds for Network Intrusion Detection

## Overview

This project investigates the performance overhead introduced by Post-Quantum Cryptography (PQC) in TLS 1.3 connections used within Federated Learning (FL) environments for Network Intrusion Detection Systems (NIDS).

Federated Learning enables multiple clients to collaboratively train a shared machine learning model without exchanging their raw network traffic data. However, repeated client-server communication across training rounds requires secure connections, making TLS handshake latency and communication overhead important performance considerations.

This project evaluates classical, hybrid, and fully post-quantum TLS configurations under different client counts, training rounds, and TLS session resumption states. It combines empirical TLS benchmarking with a Flower-based federated intrusion detection workload to investigate how cryptographic overhead accumulates across repeated communication rounds.

## Objectives

- Benchmark classical, hybrid, and post-quantum TLS 1.3 configurations.
- Measure TCP connection time, TLS handshake latency, and captured network traffic.
- Evaluate the impact of TLS 1.3 session resumption on connection performance.
- Implement a federated intrusion detection workload using Flower and PyTorch.
- Investigate the relationship between cryptographic overhead, client counts, and training rounds.
- Evaluate model-based Time to Convergence (TTC) projections under different cryptographic configurations.

## System Architecture

The project consists of two independent experimental components followed by a common analysis stage.

### 1. TLS Benchmarking

A Python-based TLS collector establishes repeated TLS 1.3 connections against four locally configured cryptographic endpoints.

The collector:
- Configures TLS cryptographic profiles using OpenSSL.
- Establishes fresh TCP/TLS connections for each client-round combination.
- Evaluates session resumption enabled and disabled states.
- Captures network packets using tcpdump.
- Uses TShark to extract TLS handshake and traffic information.
- Records connection-level measurements and generates aggregate CSV results.

### 2. Federated Learning

A Flower-based federated learning environment simulates distributed network intrusion detection.

The implementation:
- Uses the CIC-IDS2017 Friday-WorkingHours-Afternoon-DDoS dataset.
- Performs data cleaning, feature preprocessing, and label encoding.
- Divides the training dataset into five client partitions.
- Uses a PyTorch neural network for local intrusion detection training.
- Coordinates training through a Flower server.
- Aggregates client model parameters using Federated Averaging (FedAvg).

### 3. Performance Analysis

The outputs from both experimental components are examined to evaluate the impact of TLS configurations on repeated federated learning communication.

The analysis includes handshake latency, captured traffic, session resumption efficiency, workload scaling, and model-based convergence-time projections.

## Cryptographic Configurations

Four TLS 1.3 cryptographic profiles are evaluated.

| Profile | Key Establishment | Server Authentication |
|---|---|---|
| K1 | X25519 | ECDSA P-256 |
| H1 | X25519 + ML-KEM-768 | ECDSA P-256 |
| H2 | X25519 + ML-KEM-768 | ML-DSA-65 |
| P1 | ML-KEM-768 | ML-DSA-65 |

- **K1:** Classical cryptographic baseline.
- **H1:** Hybrid key establishment with classical authentication.
- **H2:** Hybrid key establishment with post-quantum authentication.
- **P1:** Fully post-quantum key establishment and authentication.

Each profile is evaluated with TLS session resumption both enabled (ON) and disabled (OFF).

## Experimental Configuration

The TLS benchmarking experiment evaluates 72 distinct configurations.

| Parameter | Values |
|---|---|
| Client count (N) | 5, 10, 20 |
| Training rounds (R) | 10, 50, 100 |
| TLS profiles | K1, H1, H2, P1 |
| Session resumption | ON, OFF |
| Total configurations | 72 |

Each client-round combination creates a fresh TCP/TLS connection. Connections are executed sequentially in the benchmarking environment.

The total number of connection attempts per configuration is:

`M = N × R`

The final benchmark produced 44,800 connection-level records across the 72 configurations.

## Dataset and Machine Learning Model

**Dataset:** CIC-IDS2017 – Friday-WorkingHours-Afternoon-DDoS.

The dataset undergoes preprocessing, including:
- Removal of metadata fields that could introduce data leakage.
- Handling of missing and infinite values.
- Label encoding.
- Stratified 80/20 train-test split.
- Standardization of numerical features.

The training data is distributed across five client partitions, while a separate held-out dataset is used for global model evaluation.

**Neural network architecture:**
- Input layer: 87 numerical features.
- Hidden layer 1: 64 units with Batch Normalization, ReLU, and Dropout (0.2).
- Hidden layer 2: 32 units with ReLU activation.
- Output layer: 5 classes.

**Training configuration:**
- Framework: PyTorch.
- Orchestration: Flower.
- Aggregation: FedAvg.
- Optimizer: Adam.
- Learning rate: 0.001.
- Batch size: 64.
- Local training: One epoch per round.
- Loss function: CrossEntropyLoss.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | TLS collector and experimental processing |
| OpenSSL 3.5.9 | TLS 1.3 configuration and benchmarking |
| liboqs | Post-quantum cryptographic implementation |
| oqs-provider | Integrating PQC algorithms with OpenSSL |
| tcpdump | Network packet capture |
| TShark / Wireshark | Packet analysis and TLS traffic extraction |
| Flower | Federated learning orchestration |
| PyTorch | Neural network implementation and training |
| scikit-learn | Dataset preprocessing and evaluation |
| NumPy / pandas | Data manipulation and analysis |
| Ubuntu on WSL | Experimental environment |

## Experimental Results

The final TLS benchmark successfully completed all 72 configurations, producing 44,800 successful connection-level records.

### TLS Handshake Latency

Mean handshake latency under session resumption OFF:

| Profile | Mean Latency |
|---|---:|
| K1 | 3.680 ms |
| H1 | 4.476 ms |
| H2 | 8.057 ms |
| P1 | 7.343 ms |

### Impact of Session Resumption

Enabling session resumption significantly reduced handshake latency and captured traffic, particularly for H2 and P1.

| Profile | Handshake Latency Reduction |
|---|---:|
| K1 | 28.47% |
| H1 | 29.14% |
| H2 | 60.35% |
| P1 | 62.94% |

All eligible resumption attempts in the final benchmark were successfully resumed.

### Key Findings

- Post-quantum authentication using ML-DSA-65 introduces substantial communication overhead due to larger signatures and certificate-related data.
- Hybrid key establishment alone introduces considerably less overhead than configurations combining hybrid key establishment with post-quantum authentication.
- TLS session resumption reduces repeated handshake costs, particularly for the H2 and P1 profiles.
- The impact of TLS overhead on federated learning execution time is comparatively smaller when local model computation is included.

The federated learning evaluation also uses a model-based Time to Convergence calculation with an assumed local computation time of 0.450 seconds per round. These projections should not be interpreted as directly measured distributed training times.

## Output Artifacts

The experiment generates several outputs for reproducibility and analysis.

**TLS benchmarking:**
- Raw PCAP captures: `quantum/pcaps/raw`
- CSV measurements: `quantum/results/csv`
- Summary tables: `quantum/results/final_72_analysis/tables`
- Generated plots: `quantum/results/final_72_analysis/plots`

**Federated learning:**
- Client and server implementation.
- Client dataset partitions.
- Global test dataset.
- Round-level training telemetry.
- `FL_PQ_TLS_Evaluation_Grid.csv`
- Parameter-sweep results and plots.

## Running the Experiments

The following describes the intended execution workflow. Exact commands and environment configuration depend on the repository's accompanying scripts and configuration files.

### 1. Configure the Environment

Set up Ubuntu on WSL and install the required Python, OpenSSL, liboqs, and oqs-provider dependencies.

Ensure that OpenSSL supports the required post-quantum algorithms and that the TLS endpoints and certificates are configured correctly.

### 2. Run the TLS Benchmark

Execute the Python TLS collector:

`python collect_72_grid.py`

The collector performs the configured TLS connection experiments, captures packets, extracts handshake measurements, and generates CSV outputs.

### 3. Run the Federated Learning Experiment

Open the Flower-based federated learning notebook and execute the dataset preprocessing, client partitioning, model training, and server aggregation workflow.

### 4. Perform Analysis

Use the generated CSV files and experimental outputs to compare the cryptographic profiles, session resumption states, handshake latency, traffic overhead, and federated learning performance projections.

## Limitations

- TLS measurements are conducted over a local loopback interface in WSL, without real-world network propagation delays.
- TLS connections are executed sequentially rather than concurrently.
- The large-scale federated learning performance evaluation uses a model-based connection-cost projection.
- Local computation time is treated as a fixed modelling assumption.
- Physical multi-machine federated deployment and evaluation across heterogeneous edge devices remain areas for future work.

## Conclusion

This project provides an experimental framework for understanding the performance implications of integrating post-quantum TLS into federated learning communication.

The findings demonstrate that post-quantum cryptographic overhead is multidimensional: handshake latency, communication volume, and accumulated application-level execution costs do not necessarily increase proportionally.

In particular, the results highlight the importance of evaluating cryptographic configurations within repeated communication workloads rather than relying exclusively on isolated handshake benchmarks.

The project also demonstrates how TLS session resumption can mitigate a significant portion of the overhead associated with post-quantum cryptographic configurations.

---

**Project:** Quantifying Post-Quantum TLS Overhead in Federated Learning Rounds for Network Intrusion Detection

**Focus Areas:** Post-Quantum Cryptography | TLS 1.3 | Federated Learning | Network Intrusion Detection | Performance Benchmarking
