# DocuTrust Image Verification Policy

Project 5, Deliverable 9. This policy defines which signing identity DocuTrust trusts. Project 6's Kyverno admission policy consumes these values directly.

## Trusted identity

| Field | Value |
|---|---|
| Certificate OIDC issuer | `https://token.actions.githubusercontent.com` |
| Certificate identity (SAN) | `https://github.com/mykaelHunter/docutrust/.github/workflows/ci.yml@refs/heads/main` |
| Image repository | `ghcr.io/mykaelhunter/docutrust` (lowercase) |
| Reference form | by digest only (`@sha256:...`), never by tag |

Note the casing: the image path is lowercase, but the certificate identity keeps GitHub's casing (`mykaelHunter`). The two are not interchangeable.

## Required claims for an image to be admitted

1. A valid keyless Cosign signature matching the identity and issuer above.
2. An SPDX SBOM attestation (`--type spdxjson`) signed by the same identity.
3. A SLSA build provenance attestation (`https://slsa.dev/provenance/v1`) from Project 4, verified with `gh attestation verify --owner mykaelHunter`.

Verification commands (Cosign v2.4.1):

```bash
export IMG=ghcr.io/mykaelhunter/docutrust
export ID="https://github.com/mykaelHunter/docutrust/.github/workflows/ci.yml@refs/heads/main"
export ISS=https://token.actions.githubusercontent.com

cosign verify "$IMG@$DIGEST" --certificate-identity "$ID" --certificate-oidc-issuer "$ISS"
cosign verify-attestation --type spdxjson "$IMG@$DIGEST" --certificate-identity "$ID" --certificate-oidc-issuer "$ISS"
gh attestation verify "oci://$IMG@$DIGEST" --owner mykaelHunter
```

## Why this exact identity

The certificate subject encodes the repository, the workflow file path and the git ref. Pinning all three means:

- **Repository:** a fork or look-alike repo cannot satisfy the policy. Tested in Deliverable 8: a valid signature from `mykaelHunter/docutrust-fork` (digest `sha256:1b89acf24aa3ffc8a03edaf083ba4fda02140b8dfbee457a841f484a3763c8b8`) was rejected because its subject was `.../docutrust-fork/.github/workflows/ci.yml@refs/heads/main`.
- **Workflow file:** only `ci.yml` is trusted. A new or modified workflow file produces a different subject and is rejected.
- **Ref `refs/heads/main`:** pull request runs (`refs/pull/N/merge`) and feature branches do not match. Only code that reached `main` through the branch's protections can produce a trusted signature.
- **Issuer:** restricts trust to GitHub Actions OIDC tokens, not any other OIDC provider.

## Why not a regular expression

Observed in the Deliverable 8 forgery test:

| Verification option | Result against the fork's image |
|---|---|
| Exact `--certificate-identity` (DocuTrust) | Rejected (correct) |
| `--certificate-identity-regexp '.*'` | **Accepted** (policy defeated) |
| Anchored regex `^https://github.com/mykaelHunter/docutrust/\.github/workflows/ci\.yml@refs/heads/main$` | Rejected (correct) |

A signature proves who signed. The verifier's policy decides whether that signer is trusted. `.*` trusts every workflow on GitHub, so the cryptographic checks pass while the security boundary disappears. An unanchored prefix such as `https://github.com/mykaelHunter/docutrust` is also unsafe because `docutrust-fork` starts with it.

Rule: use the exact `--certificate-identity`. If a regex is unavoidable, anchor it with `^...$` and escape dots.

## Known limitations of this policy

- The identity is tied to the filename `ci.yml`. Renaming or splitting the workflow changes the subject, so verification will fail until this policy and Project 6's Kyverno policy are updated together.
- The identity does not say *which commit* was built. Provenance (Project 4) carries the commit; this policy only proves the signer.
- Anyone who can push to `main` and modify `ci.yml` can produce a trusted signature. Branch protection and review enforcement (Project 8) are what constrain that.
- Public repo and public GHCR package: signing identities are written to the public Rekor log permanently.

## Input for Project 6 (Kyverno)

Use these in the `keyless` attestor of the `verifyImages` rule:

```yaml
imageReferences:
  - "ghcr.io/mykaelhunter/docutrust*"
attestors:
  - entries:
      - keyless:
          issuer: "https://token.actions.githubusercontent.com"
          subject: "https://github.com/mykaelHunter/docutrust/.github/workflows/ci.yml@refs/heads/main"
```

Use `subject` (exact), not `subjectRegExp`, for the same reasons as above.
