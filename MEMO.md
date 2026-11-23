# MEMO — What This Process Is About

**In one sentence:** prove to a remote verifier that a virtual machine is a genuine,
untampered Intel TDX confidential environment — and only then hand it a secret.

This is a step-by-step walkthrough for setting up and running **Intel TDX attestation**.
It is written for a person following along on a real machine, and every step explains
**what** happens, **why** it is needed, and **how to verify** it worked.

## The Big Picture

The process has two sides:

- **HOST** — the physical machine you are working on. Everything in this guide runs here.
- **GUEST** — the virtual machine that turns into a *Trust Domain*. Inside a Trust Domain,
  the memory is encrypted by hardware and its state is measured by the CPU itself.

The whole goal is to answer one question for a remote party: *"Can I trust what is running
on that machine, without having been there?"*

## The Flow, in Plain Terms

1. **Install the prerequisites.** The host needs a set of Intel confidential-computing
   packages (the DCAP / QGS / Trustee stack) before anything else can happen.

2. **Set up the attestation service.** A small local service is installed and configured so
   it can talk to Intel's attestation infrastructure and validate measurements correctly.

3. **Verify the service.** Before trusting it, the service is checked live — its certificate,
   its position in the chain of trust, and a live connection test are all confirmed.

4. **Prepare the guest.** The virtual machine is configured to become a Trust Domain, with its
   memory encrypted and measured by the TDX hardware.

5. **Attest the guest.** The guest produces a signed measurement of its own state — a
   cryptographic fingerprint proving exactly what and how it is running.

6. **Verify and decide.** A remote verifier checks that fingerprint against Intel's records.
   If it matches and is valid, the guest is proven genuine and untampered — and only then is
   the secret released to it.

## Why It Matters

Without this, someone could run a copy of the machine that looks right but has been tampered
with. Attestation removes the guesswork: it gives cryptographic proof, from hardware, that the
environment is exactly what it claims to be.

---
*See `README.md` for the full guided walkthrough and `CHANGELOG.md` for change history.*
