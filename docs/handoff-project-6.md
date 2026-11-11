# Handoff: Project 5 to Project 6

DocuTrust signing and attestation posture, ready for admission-time enforcement. Nothing here needs to be re-derived.

## Artifacts

| Item | Value |
|---|---|
| Registry | GHCR (`ghcr.io`), public package |
| Image | `ghcr.io/mykaelhunter/docutrust` |
| **Signed digest** | `sha256:660c1bc2a8327e8c83787a53c0f149251a6a52f79f5342ef6220361a40cbbac4` |
| Source workflow | `.github/workflows/ci.yml`, job `provenance`, push to `main` |
| **Tampered image** | `ghcr.io/mykaelhunter/docutrust:tampered` |
| Tampered digest | `sha256:fb74fca62144ebc948f8384dd4c6f45ab4ed0eaaf8a5a1a6e6cc3c8f1c4d55f0` |
| Forgery-test image | `ghcr.io/mykaelhunter/docutrust-fork@sha256:1b89acf24aa3ffc8a03edaf083ba4fda02140b8dfbee457a841f484a3763c8b8` |

The tampered image is the signed build plus `RUN echo tampered > /tmp/.tampered`. It was built locally and pushed outside CI, so it has no Sigstore signature or attestation. Do not delete the `:tampered` tag; Project 6's negative test reuses it.

## What is attached to the signed digest

`cosign tree` shows all three on `sha256:660c1bc2...`:

| Claim | Stored as | How verified |
|---|---|---|
| Keyless Cosign signature | `.sig` tag in GHCR | `cosign verify` with identity and issuer |
| SPDX SBOM attestation (from Syft, run against the built image digest) | `.att` tag in GHCR | `cosign verify-attestation --type spdxjson` |
| SLSA build provenance v1 (Project 4) | OCI referrer in GHCR, also in GitHub's attestation store (`push-to-registry: true`) | `gh attestation verify oci://... --owner mykaelHunter` |

All three were confirmed against the same digest in one terminal session (SIGNATURE OK, SBOM OK, PROVENANCE OK).

## Verification policy

| Field | Value |
|---|---|
| Issuer | `https://token.actions.githubusercontent.com` |
| Identity | `https://github.com/mykaelHunter/docutrust/.github/workflows/ci.yml@refs/heads/main` |

Full reasoning is in `verification-policy.md`. Use the exact identity, never `.*`.

## Test results Project 6 builds on

| Test | Result |
|---|---|
| Signed image verified (Cosign v2.4.1) | Pass |
| Tampered image verified | Rejected: `no signatures found` |
| Fork's validly signed image verified against DocuTrust identity | Rejected: subject was `.../docutrust-fork/...` |
| Same fork image with `--certificate-identity-regexp '.*'` | Accepted (shows why loose policies fail) |
| Same fork image with anchored regex | Rejected |

## Tool versions

| Tool | Version |
|---|---|
| Cosign in CI (signing and attesting) | v2.4.1 (`sigstore/cosign-installer@v3`, `cosign-release: v2.4.1`) |
| Cosign locally, verification | v2.4.1 (`/tmp/cosign2`) for the evidence screenshots; v3.1.4 also installed |
| Syft | **fill in from the CI log, step "Generate SBOM from the built image" (`syft version`)** |
| Rekor entry | **fill in the log index from the CI line `tlog entry created with index: <n>`** |

## Findings worth carrying forward

- **Cosign v3 output differs from v2.** In testing, v3.1.4 `cosign verify` reported the SLSA provenance bundle (`"type":"https://slsa.dev/provenance/v1"`, empty `optional`) and does not print `Bundle.Payload.logIndex`. The v2.4.1 binary showed the plain signature and its Rekor bundle. Kyverno's verification behavior depends on its own embedded Cosign version; test it rather than assuming it matches either result.
- **`cosign-installer@v3` could not install Cosign v3.1.4** (exit code 22 while fetching the detached `.sig`, which that release does not provide). CI therefore signs with v2.4.1. Moving CI to Cosign v3 would need a compatible installer release and a re-test of every verification here.
- **Provenance verification path:** this report verified provenance with `gh attestation verify`. `cosign verify-attestation --type slsaprovenance1` was not tested.
- **buildx metadata:** images built with `docker buildx` carry Docker's own unsigned attestation manifest. It is not a Sigstore attestation and must not be mistaken for one when writing admission rules.

## Known limitations

- Identity depends on the filename `ci.yml` and ref `refs/heads/main`. Renaming the workflow breaks verification until both policies are updated.
- Public repo and public package are required. Signing identities are permanently logged in the public Rekor transparency log.
- The signing job must stay free of the Project 4 adversarial steps. Those were removed from `ci.yml` before Project 5 signing.
- The signed digest is a point-in-time reference. Every new `main` push produces a new digest that must be signed and attested before Project 6 policy will admit it.
- Docker Hub's `library/...` namespace and shell variable mistakes during testing caused no registry changes; the only extra package version created was the intentional `:tampered` tag.

## What Project 6 should do

1. Write a Kyverno `verifyImages` policy using the identity and issuer above (exact `subject`, not `subjectRegExp`).
2. Positive test: admit `ghcr.io/mykaelhunter/docutrust@sha256:660c1bc2...cbbac4`.
3. Negative tests: reject an unsigned build and reject `ghcr.io/mykaelhunter/docutrust:tampered` (`sha256:fb74fca6...d55f0`).
4. Add a second rule requiring the `spdxjson` SBOM attestation.
5. Feed the SBOM and provenance into GUAC.
