# Trustee 0.23: grpc-as panics on every attestation request

Status: **open upstream** (no fix on `confidential-containers/trustee` `main`
as of commit `9dd128c`, 2026-11-23). Workaround available in this repo:
`tdx-attest.sh collateral-offline` — **verified on tdxdev1 (SLES 16.1,
trustee 0.23): quote verified, TCB `UpToDate`, no panic.**

## Symptom

`./tdx-attest.sh attest` fails. First run after the panic:

```
grpcurl call failed:
  Code: Canceled
  Message: stream terminated by RST_STREAM with error code: CANCEL
```

`journalctl -u grpc-as.service`:

```
grpc_as::grpc: AttestationEvaluate API called.
thread 'tokio-rt-worker' panicked at .../vendor/reqwest-0.13.5/src/async_impl/client.rs:2524:38:
Client::new(): reqwest::Error { kind: Builder, source: Normal(ErrorStack([])) }
```

Every later request on the same process:

```
thread 'tokio-rt-worker' panicked at .../library/std/src/sync/lazy_lock.rs:415:5:
LazyLock instance has previously been poisoned
```

If the service is then stopped, `attest` reports
`dial tcp 127.0.0.1:3000: connect: connection refused`.

## Environment where it was observed

| Item | Value |
|------|-------|
| OS | SLES 16.1 |
| trustee | `0.23.0~git0.564a3ba5-SGX.1610.2.1` (Virtualization:SGX) — **broken** |
| trustee | `0.22.0~git0.512fed6-SGX.1610.2.1` — **works** |
| libopenssl3 | `3.5.0-160100.3.2` (unchanged between working and broken) |
| crypto-policies | `20250714.cd6043a-160100.2.1`, policy `DEFAULT`, FIPS off |
| Service user | `coco_as`, `OPENSSL_CONF=/etc/ssl/openssl.cnf` (readable) |

Timeline: trustee upgraded 0.22 → 0.23 at 15:19, first panic 16:50; no
OpenSSL / crypto-policy / ca-certificates change since October.

## Root cause

Trustee 0.23 replaced the QCNL C library collateral path with a native Rust
PCS/PCCS client, `deps/verifier/src/intel_dcap/pcs.rs`:

```rust
static PCS_CLIENT: LazyLock<reqwest_middleware::ClientWithMiddleware> = LazyLock::new(|| {
    ClientBuilder::new(reqwest::Client::new())   // line 38
        ...
```

- `reqwest::Client::new()` **panics** if the TLS backend fails to initialise
  (it is `Client::builder().build().expect("Client::new()")`).
- It runs inside a `LazyLock`, so the first panic poisons the lock and every
  following request panics too.
- `Normal(ErrorStack([]))` is a `native-tls` / OpenSSL error with an empty
  error queue: OpenSSL TLS context setup failed in the service process. The
  exact trigger on SLES 16.1 is still unknown (0.22 never built an HTTPS
  client in-process, so it was never exercised).

Two separate problems:

1. **Upstream (trustee):** a TLS init failure crashes the service instead of
   returning an attestation error. Should use `Client::builder().build()` and
   propagate the error.
2. **Packaging / platform (SUSE):** why OpenSSL TLS init fails for `coco_as`
   on SLES 16.1.

Related reqwest 0.13 `Client::new()` panic reports (all rustls variants, none
with the OpenSSL `ErrorStack([])` form):
[progenitor #1440](https://github.com/oxidecomputer/progenitor/issues/1440),
[pixi #6825](https://github.com/prefix-dev/pixi/issues/6825),
[sccache #2917](https://github.com/mozilla/sccache/pull/2917),
[developing-today/code #12608](https://github.com/developing-today/code/issues/12608).

## Configuration change in 0.23

0.23 no longer uses QCNL (`QCNL_CONF_PATH`, `/etc/sgx_default_qcnl.conf`) for
quote verification. The collateral source is read from `/etc/grpc-as.json`:

```json
"verifier_config": {
  "dcap_verifier": {
    "collateral_service": "https://api.trustedservices.intel.com/sgx/certification/v4/",
    "tcb_update_type": "early"
  }
}
```

`setup-trustee` already writes this block, so PCS/PCCS selection keeps working
on 0.23 (QCNL is still used by QGS on the host for quote *generation*).
`collateral_service` also accepts a `file://` URL to a JSON file in the
[Intel PCS Client Tool](https://github.com/intel/confidential-computing.tee.dcap/tree/main/tools/PcsClientTool)
format ([config docs](https://github.com/confidential-containers/trustee/blob/main/attestation-service/docs/config.md)).

## Other 0.23 change: EAR token claim layout

Upstream commit `5aceb8d` ("as: migrate EAR token to draft-04 claim layout",
BREAKING) renamed the token claims:

| trustee <= 0.22 | trustee >= 0.23 |
|-----------------|-----------------|
| `submods.cpu0."ear.status"` | `submods.cpu0.ear_status` |
| `"ear.trustworthiness-vector"` | `ear_trustworthiness_vector` |
| `"ear.veraison.annotated-evidence".tdx.quote` | `ear_attester_claims.claims.quote` |
| `"ear.veraison.annotated-evidence".tdx.tcb_status` | `ear_attester_claims.claims.tcb_status` |

`tdx-attest.sh attest` parses both layouts (`ear_fields` in `lib/attest.sh`).
Before that fix the report showed `EAR Status: Unknown` on 0.23. Any custom
KBS policy that reads `ear.status` must switch to `ear_status` (see
upstream `kbs/sample_policies/affirming.rego`).

## Workarounds

### A. Offline collateral (stay on 0.23) — implemented here

The `file://` backend never constructs the HTTPS client, so it avoids the
panic. `tdx-attest.sh` fetches the collateral on the host with `curl` (system
OpenSSL works fine there), builds the JSON the verifier expects, and points
CoCo-AS at it:

```bash
# FMSPC taken from a fresh guest quote (interactive VM pick, or --guest-ip)
sudo ./tdx-attest.sh collateral-offline
# or, without touching the guest
sudo ./tdx-attest.sh collateral-offline --fmspc 00806F050000
# from a local PCCS instead of Intel PCS
sudo ./tdx-attest.sh collateral-offline --collateral pccs --pccs-url https://127.0.0.1:8081

sudo ./tdx-attest.sh attest
```

What it does:

1. Resolves the FMSPC (`--fmspc`, or the PCK certificate inside a guest quote).
2. Fetches from the selected source (`--collateral pcs|pccs`): TDX/SGX TCB
   info and QE identities (`standard` + `early`), PCK CRLs (processor,
   platform) with their issuer chains, and the Intel Root CA CRL.
3. Writes `/var/lib/attestation-service/dcap/collateral.json` (owned by
   `coco_as`).
4. Sets `collateral_service` to `file:///var/lib/attestation-service/dcap/collateral.json`
   in `/etc/grpc-as.json` and restarts `grpc-as`.
5. Prints the earliest `nextUpdate`.

Notes:

- **Collateral expires** (TCB info / QE identity `nextUpdate`, about 30 days;
  CRLs). Re-run `collateral-offline` before then; `verify` reports
  PASS / FAIL (expired) for the file.
- Only the FMSPC of the platform the quote came from is included. Run it on
  each host (or extend it) for multi-platform setups.
- New TCB recoveries are only seen after a refresh.
- `setup-trustee` keeps an existing `file://` source.
- Revert to online collateral: `sudo ./tdx-attest.sh collateral-online`.

### B. Downgrade to trustee 0.22

```bash
systemctl stop grpc-as kbs rvps
zypper in --oldpackage trustee-0.22.0~git0.512fed6-SGX.1610.2.1 \
                       system-user-coco_trustee-0.22.0~git0.512fed6-SGX.1610.2.1
zypper al trustee trustee-intel system-user-coco_trustee
systemctl restart grpc-as kbs rvps
```

`trustee-intel` is a new sub-package in 0.23; zypper offers to remove it.

## Data for the bug reports

Find which file OpenSSL fails on:

```bash
systemctl stop grpc-as
sudo -u coco_as strace -f -e trace=openat -o /tmp/grpc-as.strace \
  /usr/libexec/grpc-as --config-file /etc/grpc-as.json &
./tdx-attest.sh attest; kill %1
grep -E 'ENOENT|EACCES' /tmp/grpc-as.strace | grep -vE '\.so|locale' | tail -20
```

Include: the panic line, trustee and libopenssl3 versions, SLES 16.1, "0.22
works", and the strace excerpt.

- Upstream: <https://github.com/confidential-containers/trustee/issues> —
  `pcs.rs` should not panic on TLS init failure.
- SUSE: trustee package in Virtualization:SGX — OpenSSL TLS init fails for
  `coco_as`.

## Diagnostics added to `tdx-attest.sh`

- Pre-flight check before `grpcurl`: is `grpc-as.service` active, is the
  port open (explains crashed vs stopped).
- The CoCo-AS log dump drops Rust backtrace frames so the `panicked at` line
  stays visible.
- Recognises this `Client::new()` panic and the `LazyLock ... poisoned`
  state, and prints the matching hint.

## Sources

- [trustee v0.23.0 release](https://github.com/confidential-containers/trustee/releases/tag/v0.23.0)
- [trustee AS config docs](https://github.com/confidential-containers/trustee/blob/main/attestation-service/docs/config.md)
- [trustee helm README, offline DCAP collateral](https://github.com/confidential-containers/trustee/blob/main/deployment/helm-chart/README.md)
- [progenitor #1440](https://github.com/oxidecomputer/progenitor/issues/1440)
- [pixi #6825](https://github.com/prefix-dev/pixi/issues/6825)
- [sccache PR #2917](https://github.com/mozilla/sccache/pull/2917)
- [developing-today/code #12608](https://github.com/developing-today/code/issues/12608)
