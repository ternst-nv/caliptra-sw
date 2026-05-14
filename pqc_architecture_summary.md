# PQC ML-DSA Identity Retrofit -- Architecture Summary

## Executive Summary

Caliptra 1.x ships with ECDSA-only device identity. As post-quantum cryptography mandates approach (2027-2028), the installed base risks deprecation. This retrofit adds a parallel ML-DSA-87 identity chain through a firmware-only update to Runtime (RT), requiring no hardware or ROM changes. A SOC Manager-provided seed drives deterministic ML-DSA key generation and signing in software, integrated with DPE for dual-identity attestation.

---

## Where PQC Lives in the Firmware Stack

PQC is confined entirely to RT. ROM and FMC are untouched.

```mermaid
block-beta
    columns 3

    ROM["ROM (immutable)\nECDSA DICE chain\nHW ECC-384 accelerator"]:3

    space:3

    FMC["FMC (24 KB budget)\nRt.Alias derivation\nOne-shot, no command loop\nNO PQC"]:3

    space:3

    RT_ECDSA["RT -- ECDSA Path\nExisting DICE identity\nHW ECC-384\nINVOKE_DPE"]
    RT_PQC["RT -- ML-DSA Path\nPQ.DevID from seed\nSW caliptra-mldsa\nINVOKE_DPE_MLDSA87"]
    RT_Shared["RT -- Shared\nDPE dual-identity\nMailbox commands\nPersistentData"]
```

**Why RT-only**: FMC is a one-shot boot stage with a 24 KB code budget and no command loop. ML-DSA software requires significant code space and stack. RT has 96 KB code budget, 85 KB stack, and a persistent command loop.

---

## Dual Identity Architecture

Two independent identity chains coexist. The ECDSA chain is unchanged. The ML-DSA chain is additive.

```mermaid
flowchart TB
    subgraph ecdsa [ECDSA Identity Chain]
        direction TB
        UDS[UDS\nHardware fuse] --> IDevID[IDevID\nROM-derived]
        IDevID --> LDevID[LDevID\nFMC-derived]
        LDevID --> AliasRT[Rt.Alias\nRT-derived]
        AliasRT --> DPE_E[DPE Contexts\nECDSA signing]
    end

    subgraph mldsa [ML-DSA Identity Chain]
        direction TB
        Seed[PQ.DevID.Seed\nSOC Manager] --> PQDevID["PQ.DevID\nRT-derived\n(= PQ.AliasRT)"]
        PQDevID --> DPE_M[DPE Contexts\nML-DSA signing]
    end

    SOC[SOC Manager] -->|SET_PQ_SEED| Seed
    SOC -->|INVOKE_DPE| DPE_E
    SOC -->|INVOKE_DPE_MLDSA87| DPE_M
    MFG[Manufacturing] -->|GET_PQ_CSR| PQDevID
```

**Key simplification**: Since firmware measurements are excluded from PQC identity (to avoid costly re-provisioning on firmware updates), PQ.DevID and PQ.AliasRT are the same identity. There is no separate FMC-layer PQC certificate.

---

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| PQC firmware stage | RT only | FMC has no command loop and only 24 KB code budget |
| Seed source | SOC Manager (external) | Avoids awkward internal derivation from ECDSA keypair hash |
| FW measurement in PQC identity | Excluded | Re-provisioning ML-DSA cert on every FW update is operationally unacceptable |
| Persistent storage | Seed only (32 B) | PersistentData has only 3 KB reserved; pubkey (2.6 KB) + sig (4.6 KB) would not fit |
| Artifact regeneration | On-demand deterministic | ML-DSA keygen/signing are deterministic; trade compute for memory |
| DPE integration | Dual-identity (separate commands) | Follows caliptra-dpe `hybrid` feature pattern from main branch |
| DPE init timing | Deferred until after first command | Allows seed reception without changing ROM/SOC Manager protocol |
| PQ CDI storage | KeyVault slot 11 | Hardware-protected; never leaves KeyVault; mirrors ECDSA CDI pattern |

---

## Key Derivation Flow

```mermaid
flowchart LR
    subgraph socManager [SOC Manager]
        ExtSeed[Per-device\n384-bit seed]
    end

    subgraph caliptraRT [Caliptra RT]
        direction LR
        PD[PersistentData\n32-byte seed storage]

        subgraph hwProtected [Hardware Protected]
            HMAC1[HMAC-384 KDF\nlabel: pq_devid_cdi]
            KV11["KeyVault Slot 11\nPQ Root CDI\n(384-bit)"]
        end

        subgraph perContext [Per DPE Context]
            HMAC2[HMAC-384 KDF\ncontext-specific label]
            SwBuf["Software Buffer\n48 bytes\n(first 32 used)"]
        end

        subgraph swMldsa [Software ML-DSA]
            KeyGen["Mldsa87::pub_from_seed()\nPubKey: 2,592 B"]
            Sign["Mldsa87::sign_deterministic()\nSig: 4,627 B"]
        end
    end

    ExtSeed -->|SET_PQ_SEED| PD
    PD --> HMAC1
    HMAC1 --> KV11
    KV11 --> HMAC2
    HMAC2 --> SwBuf
    SwBuf --> KeyGen
    SwBuf --> Sign
    Sign -.->|zeroize seed| SwBuf
```

**Contrast with ECDSA**: The ECDSA path uses hardware ECC-384 throughout -- private keys never leave the KeyVault. The ML-DSA path must extract a derived seed to software because `caliptra-mldsa` is a pure software implementation. Seeds are zeroized immediately after use.

---

## Cold Reset Boot Flow

```mermaid
sequenceDiagram
    participant SOC as SOC Manager
    participant RT as Caliptra RT

    Note over RT: Cold Reset begins

    rect rgb(240, 240, 255)
        Note over RT: Phase 1 -- ECDSA Setup
        RT->>RT: run_reset_flow_phase1()
        RT->>RT: create_cert_chain() [ECDSA only]
        RT->>RT: assert_ready_for_runtime()
        RT->>RT: report_boot_status(RtReadyForCommands)
    end

    rect rgb(255, 250, 230)
        Note over RT: Seed Window -- first command determines PQC mode
        RT->>RT: WFI (wait for interrupt)

        alt PQC-capable SOC
            SOC->>RT: SET_PQ_SEED (384-bit seed)
            RT->>RT: Validate + store seed
            RT->>RT: Build ML-DSA cert chain
            RT->>RT: pqc_mode = true
            RT-->>SOC: Success
        else Non-PQC SOC
            SOC->>RT: Any other command
            RT->>RT: pqc_mode = false
            Note over RT: Command stays in mailbox HW
        end
    end

    rect rgb(230, 255, 230)
        Note over RT: Phase 2 -- DPE Init
        RT->>RT: initialize_dpe() [dual-identity if pqc_mode]
        RT->>RT: report_boot_status(RtDpeInitComplete)
    end

    alt Held command pending
        RT->>RT: handle_command() [process held command]
        RT-->>SOC: Response
    end

    Note over RT: Enter normal command loop
```

**Why deferred DPE init**: DPE initialization is lightweight (~milliseconds, mostly data structure setup, no crypto). Deferring it until after the first command allows `SET_PQ_SEED` to arrive before DPE needs to know about PQC mode, without requiring any changes to ROM or the existing SOC Manager protocol (ROM expects `RtReadyForCommands` before sending any commands).

**Held command handling**: When the first command is not `SET_PQ_SEED`, the mailbox hardware naturally holds it. The command ID register is a non-destructive read, and the payload stays in mailbox SRAM until explicitly consumed. No software buffering is needed.

---

## Warm Reset Flow

```mermaid
sequenceDiagram
    participant SOC as SOC Manager
    participant RT as Caliptra RT

    Note over RT: Warm Reset begins

    RT->>RT: run_reset_flow()
    RT->>RT: Detect seed in PersistentData
    alt Seed present
        RT->>RT: Rebuild ML-DSA cert chain
        RT->>RT: pqc_mode = true
    else No seed
        RT->>RT: pqc_mode = false
    end
    RT->>RT: validate_dpe() [DPE survives in SRAM]
    RT->>RT: report_boot_status(RtReadyForCommands)
    Note over RT: Enter normal command loop
    Note over RT: SET_PQ_SEED always rejected in command loop
```

**Key difference from cold reset**: No seed window. The seed persists in PersistentData (DCCM SRAM, inside Caliptra trust boundary). PQC mode is determined automatically. DPE is validated, not re-initialized.

---

## Memory Architecture

```mermaid
block-beta
    columns 4

    block:dccm:4
        columns 4
        DCCM_Title["DCCM (128 KB)"]:4

        PD["PersistentData\n~10 KB\nPQ seed: 32 B\nfrom 3,070 B reserved"]
        Data["Global Data\n~30 KB\nDrivers, buffers"]
        Stack["Stack\n85 KB\nML-DSA signing\nneeds ~55-80 KB"]
        Unused["Remaining\n~3 KB"]
    end

    space:4

    block:kv:4
        columns 4
        KV_Title["KeyVault (32 x 384-bit slots)"]:4
        KV_ECDSA["Slots 0-10\nECDSA CDIs\nRt.Alias keys"]
        KV_PQ["Slot 11\nPQ Root CDI\nHW-protected"]
        KV_Free["Slots 12-31\nAvailable"]:2
    end

    space:4

    block:sizes:4
        columns 4
        Sizes_Title["ML-DSA-87 Data Sizes"]:4
        S1["Seed\n32 B\n(stored)"]
        S2["Public Key\n2,592 B\n(regenerated)"]
        S3["Signature\n4,627 B\n(regenerated)"]
        S4["CSR\n~7,400 B\n(regenerated)"]
    end
```

**Stack is the critical constraint**: ML-DSA signing requires ~55-80 KB of stack (PrivateKey 23.7 KB expanded + Signature 15.4 KB + polynomial temporaries). The 85 KB stack leaves very little headroom. The ML-DSA driver uses `#[inline(never)]` to prevent keygen and signing frames from coexisting on the stack.

---

## Command Interface

```mermaid
flowchart TB
    subgraph bootPhase [Boot Phase Only]
        SET["SET_PQ_SEED\nReceive 384-bit seed\nMust be first command\non cold reset"]
    end

    subgraph runtime [Runtime Command Loop]
        GET["GET_PQ_CSR\nRegenerate and return\nML-DSA CSR (~7.4 KB)"]
        INV_M["INVOKE_DPE_MLDSA87\nCertifyKey / Sign /\nDeriveContext\nML-DSA profile"]
        INV_E["INVOKE_DPE\nExisting ECDSA\nDPE commands"]
        SET_REJECT["SET_PQ_SEED\nAlways rejected"]
    end

    SET -->|enables| pqcMode{pqc_mode = true}
    pqcMode -->|yes| GET
    pqcMode -->|yes| INV_M
    pqcMode -->|no| FAIL[Error:\nPQC not initialized]
    INV_E -->|always available| OK[Success]
```

**Gating**: `GET_PQ_CSR` and `INVOKE_DPE_MLDSA87` require `pqc_mode == true`. Existing ECDSA commands are always available regardless of PQC mode. `SET_PQ_SEED` is only accepted as the very first command on cold reset.

---

## Implementation Roadmap

```mermaid
flowchart LR
    PR1[PR 1\nML-DSA Driver\ndrivers/src/mldsa87.rs]
    PR2[PR 2\nML-DSA X.509\nx509 templates + builders]
    PR3[PR 3\nDPE Upgrade\nhybrid caliptra-dpe]
    PR4[PR 4\nMailbox API +\nPersistentData]
    PR5[PR 5\nDeferred DPE Init\n+ SET_PQ_SEED]
    PR6[PR 6\nSW ML-DSA\nDpeCrypto Backend]
    PR7[PR 7\nCert Chain +\nDPE Dual-Identity]
    PR8[PR 8\nCommands +\nIntegration Tests]

    PR1 --> PR6
    PR2 --> PR7
    PR3 --> PR6
    PR3 --> PR7
    PR4 --> PR5
    PR5 --> PR7
    PR6 --> PR7
    PR7 --> PR8
```

| PR | Scope | Key Risk |
|----|-------|----------|
| 1 | `caliptra-mldsa` driver wrapper, KAT tests | None (isolated) |
| 2 | Generic `CertBuilder`, ML-DSA CSR template | ECDSA regression from refactor |
| 3 | External DPE upgrade with `hybrid` feature | Largest API surface change |
| 4 | Command IDs, request/response types, PersistentData | Layout compatibility |
| 5 | Boot flow restructure, seed window | Most architecturally complex |
| 6 | DPE crypto backend for ML-DSA | Stack depth for signing |
| 7 | PQ.DevID cert chain, dual-identity DPE init | Integration of all prior PRs |
| 8 | Final command handlers, full test suite | End-to-end correctness |

---

## Open Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Stack depth**: ML-DSA signing needs ~55-80 KB against 85 KB stack | High | `#[inline(never)]` on driver methods; may need to refactor `sign_internal` to split loop body into sub-functions |
| **Code size**: `caliptra-mldsa` adds polynomial arithmetic to RT's 96 KB budget | Medium | Measure at PR 1; `opt-level = "s"` + LTO already enabled; feature-gated so disabled builds are unaffected |
| **Performance**: Software ML-DSA on RISC-V for CSR regeneration on every `GET_PQ_CSR` call | Low | Acceptable for manufacturing flow; can cache CSR later if needed |
