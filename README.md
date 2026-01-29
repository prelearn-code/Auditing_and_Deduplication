# Auditing and Deduplication (C++ Reference Skeleton)

This repository provides a **two-file C++ implementation skeleton** for the auditing & deduplication scheme described in the provided notes. The code is structured to mirror the paper's math flow (System Setup, Initial Upload, PoW for deduplication, and audit flows), while keeping cryptographic operations lightweight and self-contained for readability.

> **Security Notice**: This is a **didactic reference**. The implementation uses toy hashing and arithmetic to mimic bilinear pairing operations, **not real cryptographic security**. For production, replace the stubs with a pairing-friendly library (e.g., PBC, MCL, or RELIC).

## Files

- `src/scheme.hpp`: Data structures and API prototypes that map directly to the paper's notation.
- `src/scheme.cpp`: Implementation of the flow logic and placeholder group/pairing operations.
- `Makefile`: Builds a static library `libauditing_dedupe.a` from the two code files.

## Mapping to the Note

### 3.1 系统初始化 (System Setup)

- **Pairing**: simulated by `Pairing(a, b)`.
- **Hash functions**: `HashToZq*` and `HashToGroup` serve as H1–H4 placeholders.
- **SPG (System Parameters Generation)**: `SystemSetup(n, s, m)` returns `SystemParams` with
  - `g`, `gamma`, `varpi`, `v`, `h`, `h^{gamma^i}`
  - `u_k = g^{a_k}` stored as `params.u`

- **DOPG (User Parameters Generation)**: `UserSetup(...)` generates:
  - `x_t`, `ssk_t`, `sk_{ID_t}`
  - `pk_t`, `spk_t`

### 3.2 数据上传与去重 (Upload & Dedup)

- **Initial upload**: `InitialUpload(...)`
  - Computes `K_c`, `T(F)`, file encryption, `K_l = k_l ⊕ K_c`
  - Builds blocks/sectors and authenticators:
    ```text
    σ_i = ( H4(η_l || i) * Π u_j^{c_ij} )^{sk_F}
    ```
  - Creates `Hdr_F = (C_F1, C_F2)` and encrypts `K_c` / `k_F`

- **Verification**: `VerifyUpload(...)` checks the aggregated pairing relation.

- **PoW (dedup)**:
  - `GeneratePoWChallenge` and `GeneratePoWProof` compute `μ_j`.
  - `VerifyPoW` verifies
    ```text
    e(σ, K_{F,y}) == e( Π H4(η||i)^{v_i} * Π u_j^{μ_j}, pk_y )
    ```

- **IBBE update**: `UpdateIBBEHeader(...)` applies
  ```text
  C_new = C_old^{γ + H1(ID_y)}
  ```

### 3.3 数据审计 (Single Audit)

- `GenerateAuditChallenge` creates `(c, k1, k2)`.
- `GenerateAuditProof` outputs `(σ, μ_j)`.
- `VerifyAudit` checks the pairing equality using `K_{F,t}`.

### 3.4 批量审计 (Batch Auditing)

- **Single user, multi-file**:
  - `GenerateBatchProofMultiFile` and `VerifyBatchMultiFile`
  - Uses weights `x_k` and aggregates `σ` and `μ`

- **Multi-user, single file**:
  - `GenerateBatchProofMultiUser` and `VerifyBatchMultiUser`
  - Aggregates user public keys and audit keys

## Build

```bash
make
```

This produces:

```text
libauditing_dedupe.a
```

To clean:

```bash
make clean
```

## Example Usage (Pseudo-code)

```cpp
#include "scheme.hpp"
using namespace audit_dedupe;

SystemParams params = SystemSetup(/*n=*/4, /*s=*/3, /*m=*/4);
MasterSecret msk{params.g, params.gamma};

auto [sk, pk] = UserSetup(params, msk, "userA");
UploadPacket packet = InitialUpload(params, sk, pk, "userA", "hello file");

bool ok = VerifyUpload(params, packet, pk);
```

## Extending with Real Cryptography

Replace the following stubs with real pairing operations:

- `Pairing(a, b)`
- `HashToZq*` and `HashToGroup`
- `ModPow` / `ModMul` should use group-specific operations
- `SymmetricEncrypt` should use AES-GCM or ChaCha20-Poly1305

When integrating a real pairing library, keep the structure of functions and data intact; the API was designed to follow the original formulas closely.
