# Intel TDX Attestation Process — Graph

**Scope:** TDX core flow only (quote generation → local or remote verification → appraisal → key release).
**Basis:** SLES 16.1 source tree.
**Local vs remote:** *local* = DCAP QVL verifies the quote on the same host using locally-cached PCCS collateral (no Trustee). *remote* = quote sent to Trustee (KBS + Attestation Service).
**Guest vs host:** blue = runs **inside the TD (guest VM)**; orange = runs **on the host** (VMM / platform / verifier). The TD report body is generated in the guest, then handed to the host-side QGS to be signed into a quote.

---

## 1. Main flow — local vs remote (guest vs host)

```mermaid
flowchart TD
    subgraph GUEST["GUEST (TD) — inside the confidential VM"]
        A["TD requests attestation<br/>(attestation-agent)"]
        B["TDG.MR.REPORT → TD report body<br/>mr_td · mr_seam · mrsigner_seam<br/>rtmr0-3 · report_data=nonce<br/>td_attributes · tcb_svn"]
        E["CC Event Log (CCEL)<br/>ACPI table of measured events"]
        A --> B
        B --> E
    end

    subgraph HOST["HOST — VMM + platform (signing + collateral)"]
        C["QGS / QvE (Quoting Enclave)<br/>wraps + signs report (ECDSA)"]
        D[("TDX Quote v4 / v5<br/>(v4 = TDX 1.0 · v5 = TDX 1.0/1.5)")]
        F["Collateral: PCK cert chain<br/>+ TCB info + CRLs<br/>(Intel PCS / local PCCS)"]
        C --> D
    end

    B -->|"report body → host (shared mem)"| C

    D --> G{"attest<br/>locally or remotely?"}
    E --> G
    F --> G

    subgraph LOCAL["LOCAL verify — DCAP QVL (runs on HOST)"]
        L1["DCAP QVL verify"] --> L2["parse quote (v4/v5)"]
        L2 --> L3["verify ECDSA sig (QE attestation key)"]
        L3 --> L4["verify PCK cert chain → Intel root CA"]
        L4 --> L5["check TCB status (tcb_svn, advisory IDs)"]
        L5 --> L6["bind report_data (nonce)"]
        L6 --> L7["local trust decision"]
    end

    subgraph REMOTE["REMOTE verify — Trustee KBS + AS (HOST or server)"]
        R1["evidence → KBS /kbs/v0/attest (RCAR)"]
        R2{"AS backend"}
        R3["BuiltInCoCoAs (in-process)"]
        R4["CoCoAS gRPC (remote AS)"]
        R5["AttestationService::evaluate()"]
        R6["dispatch Tee::Tdx → tdx verifier"]
        R7["tdx verify (DCAP-based)<br/>1 base64 decode quote<br/>2 DCAP QVL ECDSA verify<br/>3 reject SGX v3 (keep TDX v4/v5)<br/>4 bind report_data (64B)<br/>5 bind MRCONFIGID (48B init data)<br/>6 replay CCEL vs RTMR0-3 (SHA384)<br/>7 parse PCK chain → platform info<br/>8 emit claims (measurements, TCB, attrs)"]
        R8["Rego/OPA + RVPS → decision"]
        R9["EAR JWT"]
        R10["KBS releases secrets (JWE) → guest"]
        R1 --> R2
        R2 -->|in-proc| R3 --> R5
        R2 -->|grpc| R4 --> R5
        R5 --> R6 --> R7 --> R8 --> R9 --> R10
    end

    G -->|local| L1
    G -->|remote| R1
    L7 --> H["attested / rejected"]
    R10 --> H

    classDef guest fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#0d47a1;
    classDef host fill:#fff3e0,stroke:#ef6c00,stroke-width:2px,color:#e65100;
    classDef neutral fill:#f5f5f5,stroke:#616161,color:#212121;
    class A,B,E guest;
    class C,D,F,L1,L2,L3,L4,L5,L6,L7,R1,R2,R3,R4,R5,R6,R7,R8,R9,R10 host;
    class G,H neutral;
```

---

## 2. Remote path — RCAR sequence (guest vs host)

Request-Challenge-Attestation-Response exchange. Blue box = guest, orange box = host.

```mermaid
sequenceDiagram
    box rgb(227,242,253) GUEST
        participant AG as attestation-agent (TD guest)
    end
    box rgb(255,243,224) HOST
        participant KBS as KBS
        participant AS as Attestation Service
        participant TDX as tdx verifier (DCAP QVL)
        participant PCCS as PCCS / Intel PCS
    end
    AG->>KBS: POST /kbs/v0/attest (TDX quote + CCEL)
    KBS->>AS: evaluate(VerificationRequest)
    AS->>TDX: verify(evidence)
    TDX->>PCCS: fetch collateral (PCK certs, TCB info, CRLs)
    PCCS-->>TDX: collateral
    TDX->>TDX: ECDSA sig + PCK chain + TCB + report_data + MRCONFIGID + CCEL vs RTMR0-3
    TDX-->>AS: claims (mr_td, mr_seam, rtmr0-3, tcb_svn, td_attributes)
    AS->>AS: Rego/OPA + RVPS appraisal
    AS-->>KBS: EAR JWT
    KBS-->>AG: result + secrets (JWE)
```

---

## 3. Legend

### Placement (who runs where)

| Color | Runs in | Components |
| ------- | --------- | ----------- |
| 🔵 Blue | **Guest (TD)** | attestation-agent, `TDG.MR.REPORT` + TD report body, CC Event Log (CCEL), `report_data` nonce |
| 🟠 Orange | **Host (VMM / platform / verifier)** | QGS / QvE (quote signing), PCK chain + collateral (PCCS/PCS), DCAP QVL (local verify), Trustee KBS + AS (remote verify) |

> The **TD report body** is created in the guest, then crosses to the host where the QGS signs it into the **TDX Quote**. All verification (local or remote) runs outside the guest.

### Terms

| Term | Meaning |
| ------ | --------- |
| **TD** | Trust Domain — the confidential VM (TDX equivalent of an AMD SNP guest). |
| **QGS** | Quote Generation Service — host service that produces the signed TDX quote from a TD report. |
| **QvE** | Quote Verification Enclave — enclave-based alternative to the QVL for quote work. |
| **QVL** | Quote Verification Library — DCAP library that verifies TDX/SGX quotes. |
| **QE** | Quoting Enclave — signs the quote with its attestation key. |
| **PCK** | Provisioning Certification Key — per-platform key; the PCK cert binds it to the platform TCB level. |
| **PCS** | Provisioning Certification Service — Intel cloud service for collateral (PCK certs, TCB info, CRLs). |
| **PCCS** | Provisioning Certification Caching Service — local cache of PCS collateral (Node.js + SQLite); enables offline verification after an initial sync. |
| **RTMR0-3** | Four 48-byte extend-only runtime measurement registers. RTMR0 = SEAM module, RTMR1 = TDVF firmware, RTMR2 = guest bootloader/kernel, RTMR3 = guest OS. |
| **CCEL** | CC Event Log — ACPI table describing measured events; replayed against RTMR0-3 (SHA384) to prove the log is authentic. |
| **mr_td** | Measurement of the TD (guest image/config) — the TDX analogue of AMD's launch digest. |
| **mr_seam** | Measurement of the SEAM module (TDX firmware). |
| **mr_config_id** | Measurement of the TD's configuration (init data); checked against the expected init-data hash. |
| **report_data** | 64-byte field carrying the challenge nonce, binds the quote to this attestation session. |
| **tcb_svn** | TCB Sub-Version numbers — used for TCB status checks (security advisories). |
| **td_attributes** | TD attribute bits (e.g. debug enabled/disabled). |
| **EAR** | EAT Attestation Result — JWT (built on EAT, RFC 9711) the AS returns after appraisal. |
| **RCAR** | Request-Challenge-Attestation-Response — the KBS attestation protocol. |
| **RVPS** | Reference Value Provider Service — supplies expected measurements for appraisal. |
