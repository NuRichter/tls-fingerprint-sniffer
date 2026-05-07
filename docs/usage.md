# Usage Guide for TLS Fingerprint Sniffer

The TLS Fingerprint Sniffer is a network analysis tool designed to inspect TLS traffic, generate fingerprints, and support detection workflows for security research. This guide walks through installation, configuration, and usage.

---

# Installation

## Prerequisites

- Arch Linux or Kali Linux
- Rust programming language (version 1.56.0 or later)
- Cargo package manager

## Install Rust

To install Rust, run the following command:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Clone Repository

Clone the TLS Fingerprint Sniffer repository from GitHub:

```sh
git clone https://github.com/your-username/tls-fingerprint-sniffer.git
cd tls-fingerprint-sniffer
```

---

# Configuration

## Environment Variables

The tool requires several environment variables to be set. You can configure them in a `.env` file or directly in your terminal.

## Example `.env` File

```env
TLSFINGERPRINTSNIFTER_INTERFACE=eth0
TLSFINGERPRINTSNIFTER_SIGNATURES=data/signatures/malware_patterns.bin
TLSFINGERPRINTSNIFTER_MODEL=data/models/traffic_classifier_v2.onnx
```

## Setting Variables in Terminal

```sh
export TLSFINGERPRINTSNIFTER_INTERFACE=eth0
export TLSFINGERPRINTSNIFTER_SIGNATURES=data/signatures/malware_patterns.bin
export TLSFINGERPRINTSNIFTER_MODEL=data/models/traffic_classifier_v2.onnx
```

---

# Running the Tool

## Basic Sniffer

```sh
cargo run --bin basic_sniffer
```

## Machine Learning Detection Demo

```sh
cargo run --bin ml_detection_demo
```

## eBPF Filtering

```sh
cargo run --bin ebpf_filtering
```

---

# Features

## Capture Module

The capture module handles packet collection using PCAP, eBPF, and ring buffers.

### Example

```sh
cargo run --bin basic_sniffer
```

---

## Parser Module

The parser module processes captured packets and identifies TLS handshakes and metadata.

### Example

```sh
cargo run --bin ml_detection_demo
```

---

## Fingerprint Module

The fingerprint module generates TLS fingerprints using JA3, JA5, and behavioral analysis.

### Example

```sh
cargo run --bin basic_sniffer
```

---

## Detector Module

The detector module identifies suspicious traffic patterns using fingerprints and machine learning models.

### Example

```sh
cargo run --bin ml_detection_demo
```

---

## Database Module

The database module manages signature databases and synchronization workflows.

### Example

```sh
cargo run --bin basic_sniffer
```

---

## AI Module

The AI module handles machine learning models for traffic classification and anomaly detection.

### Example

```sh
cargo run --bin ml_detection_demo
```

---

## Utils Module

The utils module contains hashing utilities, optimization helpers, and miscellaneous functions.

### Example

```sh
cargo run --bin basic_sniffer
```

---

# Advanced Configuration

## Custom Signatures

You can customize signatures by editing the signature database file.

```sh
nano data/signatures/malware_patterns.bin
```

## Custom Models

Place custom ONNX models into the `data/models/` directory.

```sh
cp /path/to/your/model.onnx data/models/
export TLSFINGERPRINTSNIFTER_MODEL=data/models/your_model.onnx
```

---

# Troubleshooting

## Common Issues

### Network Interface Not Found

Ensure the interface specified in `TLSFINGERPRINTSNIFTER_INTERFACE` exists and is active.

### Permission Denied

Run the tool with elevated privileges if necessary.

```sh
sudo cargo run --bin basic_sniffer
```

---

## Log Files

Logs are generated inside the `target/` directory.

```sh
tail -f target/log.txt
```

---

# Examples

## Basic Sniffer Example

Capture and analyze TLS traffic:

```sh
cargo run --bin basic_sniffer
```

## Machine Learning Detection Example

Analyze traffic using machine learning:

```sh
cargo run --bin ml_detection_demo
```

## eBPF Filtering Example

Filter packets using eBPF:

```sh
cargo run --bin ebpf_filtering
```

---

# Benchmarks

Run benchmark tests using Cargo:

```sh
cargo bench
```

---

# Contributing

Contributions are welcome.

## Workflow

1. Fork the repository
2. Create a feature or bug-fix branch
3. Commit changes
4. Push to your fork
5. Open a pull request

---

# Code Style

- Follow Rustfmt conventions

```sh
cargo fmt
```

- Write clear and maintainable code
- Keep modules organized and documented

---

# License

The TLS Fingerprint Sniffer project is licensed under the MIT License.

See the `LICENSE` file for additional details.

---

# Contact

## Maintainer

- Email: your.email@example.com
- GitHub: https://github.com/your-username

---

# Notes

This guide provides instructions for installing, configuring, and running the TLS Fingerprint Sniffer project for TLS traffic inspection, fingerprint generation, and anomaly analysis workflows.
