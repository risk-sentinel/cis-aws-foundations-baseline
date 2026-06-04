# cis-aws-foundations — verification coverage matrix

Phase C (verification-rigor sweep). Principle: **verify the technical state
wherever the platform can answer it; never accept a human attestation as proof
of a checkable fact.**

| Control | Disposition | Notes |
|---|---|---|
| **C-2.19 centralized identity** | **VERIFY (Phase C)** | When `iam_require_federation: true`, assert a SAML/OIDC identity provider is registered (`aws_iam_saml_providers` / `aws_iam_oidc_providers`). IAM Identity Center / Organizations SSO is org-level (no account provider) → attestation floor. |
| C-2.1.1 / 2.1.2 / 2.1.4 / 2.1.5 / 2.1.6 (Organizations) | dual-mode (verify-when-org-role) | Already auto when `aws_organizations_role_arn` is set (`aws_organizations_management`, via PR #102): the control AssumeRoles into the management account and verifies the org-level config; attests only when the org role isn't provided. |
| C-2.1.3 mgmt account not used for workloads | attest (justified) | The *workload-vs-infrastructure* classification of resources in the management account is a human judgment; cross-service compute enumeration can be automated but the "is this a workload" determination is governance-bound. Freshness floor retained. |
| C-5.16 / C-3.1.3 / C-2.21 etc. | implemented | Direct API assertions (Security Hub, Macie, cross-resource `Principal:*` scan). |

## Residual attestation — why
- **C-2.1.3** — enumerating compute in the mgmt account is automatable, but whether a given resource constitutes a *workload* (vs governance/security tooling) is a classification only the operator can make; we evidence the periodic determination, not re-derive it.

## Inherited
No `inherited` controls in this profile (Tier-1 boundary surface; all either implemented, dual-mode, or the single C-2.1.3 attestation).
