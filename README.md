# T-PBS: TEE-based Privacy Budget Scheduling

> **Paper**: *T-PBS: TEE-based Privacy Budget Scheduling for Secure Data Analytics*

A privacy-preserving data query system built on Intel SGX, featuring EPC-aware scheduling algorithms for managing differential privacy budgets within Trusted Execution Environments (TEEs).

## Overview

T-PBS implements a server-client architecture where:
- **Server** (AppResponder): Hosts SGX enclaves that store and manage data with privacy budget enforcement, using custom scheduling algorithms (FCFS, DPF, DPack, ExpireLA).
- **Client** (AppInitiator): Establishes secure sessions with the server via SGX remote attestation (DCAP), submits privacy-budget-aware queries, and performs GWAS analysis.
- **User** (AppInitiator): Inserts data into the server's enclave through attested secure channels.

Key features:
- **SGX DCAP Remote Attestation** for mutual authentication between enclaves
- **Differential Privacy Budget Management** with per-data-block budget tracking
- **EPC-Aware Scheduling** (ExpireLA algorithm) that considers enclave memory constraints
- **Multiple Scheduling Policies**: FCFS, DPF (Differential Privacy First), DPack, and ExpireLA
- **GWAS (Genome-Wide Association Study)** secure computation support
- **Kubernetes Deployment** with SGX device plugin support

## Architecture

```
┌─────────────┐    SGX RA + Encrypted Channel    ┌─────────────────┐
│   Client     │ ◄──────────────────────────────► │     Server       │
│ (Requester)  │    DCAP Quote Verification       │  (Responder)     │
│              │                                   │                  │
│ ┌──────────┐ │                                   │ ┌──────────────┐ │
│ │ Enclave  │ │                                   │ │   Enclave    │ │
│ │Initiator │ │                                   │ │  Responder   │ │
│ └──────────┘ │                                   │ │ ┌──────────┐ │ │
│ ┌──────────┐ │                                   │ │ │Scheduler │ │ │
│ │ Enclave  │ │                                   │ │ │(ExpireLA)│ │ │
│ │ Executor │ │                                   │ │ └──────────┘ │ │
│ │ (GWAS)   │ │                                   │ │ ┌──────────┐ │ │
│ └──────────┘ │                                   │ │ │DP Budget │ │ │
└─────────────┘                                   │ │ │ Manager  │ │ │
                                                   │ └──────────────┘ │
┌─────────────┐    SGX RA + Encrypted Channel     │                  │
│    User      │ ◄──────────────────────────────► │                  │
│ (Inserter)   │    Data Insertion                 └─────────────────┘
└─────────────┘
```

## Prerequisites

- **OS**: Ubuntu 18.04/20.04 (with SGX support)
- **Hardware**: Intel CPU with SGX support (tested on Intel Pentium Silver J5005)
- **Intel SGX SDK**: v2.17+ (`/opt/intel/sgxsdk`)
- **Intel SGX DCAP**: For remote attestation
- **Dependencies**:
  - `libglog-dev` (Google Logging)
  - `libssl-dev` (OpenSSL)
  - `build-essential`, `cmake`, `pkg-config`

### Install Dependencies (Ubuntu)

```bash
# Install Intel SGX SDK (follow Intel's official guide)
# https://github.com/intel/linux-sgx

# Install system packages
sudo apt-get install -y libglog-dev libssl-dev build-essential cmake pkg-config
```

## Build

### Generate Signing Keys

Before building, generate the enclave signing keys (required once):

```bash
chmod +x generate_signing_keys.sh
./generate_signing_keys.sh
```

### Native Build (Makefile — Recommended)

```bash
# Hardware mode (requires SGX hardware)
make SGX_MODE=HW

# Simulation mode (for development without SGX hardware)
make SGX_MODE=SIM SGX_DEBUG=1
```

This will build all three components:
- `server/bin/appserver` + `libenclave_responder.signed.so`
- `client/bin/apprequester` + `libenclave_initiator.signed.so` + `libenclave_executor.signed.so`
- `user/bin/appinsertor` + `libenclave_initiator.signed.so`

### Clean

```bash
make clean
```

## Usage

### 1. Start Server

```bash
cd server/bin
./appserver <pageSize> <numThreads> <managerCap>

# Example: page size 1024, 4 threads, max 6 concurrent enclaves
./appserver 1024 4 6
```

Environment variable to select scheduling algorithm:
```bash
SCHEDULER_TYPE=expirela ./appserver 1024 4 6   # ExpireLA (default)
SCHEDULER_TYPE=fcfs ./appserver 1024 4 6       # First-Come-First-Served
SCHEDULER_TYPE=dpf ./appserver 1024 4 6        # Differential Privacy First
SCHEDULER_TYPE=dpack ./appserver 1024 4 6      # DPack
```

### 2. Insert Data (User)

```bash
cd user/bin
./appinsertor -n <numPerUser>

# Example: insert 200 records per user
./appinsertor -n 200
```

### 3. Query Data (Client)

```bash
cd client/bin
./apprequester --maxId <maxId> --reqNum <reqNum> --pageSize <pageSize> [--runGWAS] [--getFile]

# Example
./apprequester --maxId 10000 --reqNum 20 --pageSize 128 --runGWAS --getFile
```

### Configuration

Server configuration is in `config/server.conf`:
```properties
SERVER_ADDR=0.0.0.0
SERVER_PORT=9999
```

Can also be overridden via environment variables:
```bash
export EXPIRE_LA_SERVER_ADDR=<SERVER_IP>
export EXPIRE_LA_SERVER_PORT=8888
```

## Docker & Kubernetes

### Build Docker Image

```bash
docker build -t t-pbs:latest .
```

### Kubernetes Deployment

K8s manifests are provided in the `k8s/` directory:

```bash
# Deploy SGX AESMD daemon
kubectl apply -f k8s/sgx-aesmd-fixed.yaml

# Deploy PCCS config
kubectl apply -f k8s/pccs-config-configmap.yaml

# Deploy the application
kubectl apply -f k8s/expire-la-deployment-fixed.yaml
```

## Project Structure

```
T-PBS/
├── server/                  # Server (Data Provider / Responder)
│   ├── AppResponder/        # Untrusted app: server, scheduler, task manager
│   │   └── MerkleTree/      # Merkle tree for integrity verification
│   ├── EnclaveResponder/    # Trusted enclave: data storage, DP budget, crypto
│   │   ├── KeyGen/          # Key generation utilities
│   │   ├── MerkleTree/      # In-enclave Merkle tree
│   │   └── ShieldStore/     # Shielded key-value store (with gperftools)
│   ├── Include/             # Shared headers
│   └── util/                # Network utilities
├── client/                  # Client (Data Requester)
│   ├── AppInitiator/        # Untrusted app: query interface, GWAS
│   ├── EnclaveInitiator/    # Trusted enclave: session management, attestation
│   ├── EnclaveExecutor/     # Trusted enclave: GWAS computation
│   ├── Include/             # Shared headers
│   └── util/                # Network utilities
├── user/                    # User (Data Inserter)
│   ├── AppInitiator/        # Untrusted app: data insertion interface
│   ├── EnclaveInitiator/    # Trusted enclave: secure data upload
│   ├── Include/             # Shared headers
│   ├── test_data/           # Sample GWAS data + generation script
│   └── util/                # Network utilities
├── k8s/                     # Kubernetes deployment manifests
├── Dockerfile               # Container build file
├── Makefile                 # Top-level build script
├── generate_signing_keys.sh # Generate enclave signing keys
└── CMakeLists.txt           # CMake build (alternative)
```

## Scheduling Algorithms

| Algorithm | Description |
|-----------|-------------|
| **FCFS** | First-Come-First-Served baseline |
| **DPF** | Differential Privacy First — prioritizes requests with higher privacy budget consumption |
| **DPack** | Bin-packing based scheduler for EPC resource optimization |
| **ExpireLA** | Our proposed algorithm — weighted multi-objective scheduling considering fairness, efficiency, urgency, and EPC utilization |

## License

This project is released under the [MIT License](LICENSE).

## Citation

If you use this code in your research, please cite:

```bibtex
@article{tpbs2025,
  title={T-PBS: TEE-based Privacy Budget Scheduling for Secure Data Analytics},
  author={[Author Names]},
  journal={[Venue]},
  year={2025}
}
```

## Acknowledgments

- Built on [Intel SGX SDK](https://github.com/intel/linux-sgx) and [Intel SGX DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives)
- ShieldStore enclave key-value store component

## Test Data

The `user/test_data/generated_gwas/` directory contains 10 sample GWAS data files for quick testing. To generate the full dataset (5000 files):

```bash
cd user/test_data
python3 generate_test_data.py --count 5000 --output generated_gwas
```
