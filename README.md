# AWS Foundations CIS Baseline

InSpec / CINC Auditor profile validating an AWS account against **CIS Amazon Web Services Foundations Benchmark v7.0.0**.

## Scope

- **AWS Commercial** (`aws_partition=aws`) — primary target.
- **AWS GovCloud non-DoD** (`aws_partition=aws-us-gov`) — primary target.
- Azure and other cloud providers — out of scope.

Per-control partition applicability lives in
`partition_applicability.yml` and is mirrored on each control via
`tag applicable_partitions: [...]`. Controls not applicable to the
running partition skip (impact 0.0) via `only_if`; they do not fail.

## Running Locally

Prerequisites: Docker. Vendor once to pull the `inspec-aws` resource pack:

```bash
docker pull risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1

docker run --rm -v "$PWD:/src" risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 \
  vendor /src/profiles/cis-aws-foundations --overwrite
```

Execute against AWS Commercial:

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-aws-foundations \
  --input aws_partition=aws \
  --reporter cli json:/src/hdf.json
```

For GovCloud, switch the partition input and region:

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION=us-gov-west-1 \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-aws-foundations \
  --input aws_partition=aws-us-gov \
  --reporter cli json:/src/hdf.json
```

## Portability

This profile is designed to run unchanged across AWS partitions (Commercial + GovCloud non-DoD) and across human access models (hybrid IAM+SSO, pure AWS IAM Identity Center, legacy IAM-heavy). Consumers never fork the profile — they set declared inputs in their own `inputs.yml` or via `--input-file` / `--input`.

### Inputs

| Input | Default | When to override |
| - | - | - |
| `aws_partition` | `aws` | Set to `aws-us-gov` when scanning GovCloud non-DoD. Controls the `only_if` partition guard on each control. |
| `root_mfa_requirement` | `hardware_required` | Set to `virtual_ok` when hardware MFA is impractical across many accounts (CIS 2.6 notes this logistical caveat). Passes 2.6 on MFA-enabled alone, regardless of device type. |
| `scan_regions` | `[]` (dynamic discovery) | Set to an explicit array to scope region-iterating checks (2.18 Access Analyzer; 4.8 / 4.9 CloudTrail data events). Default queries `ec2:DescribeRegions` at scan time. Allowlisting trades drift-detection for scan speed / scope discipline — if Access Analyzer or a CloudTrail data-event selector is missing in a region you excluded, 2.18 / 4.8 / 4.9 will not flag it. |
| `iam_access_model` | `hybrid` | `pure_sso` when human access is only via IAM Identity Center (adds stricter 2.11 / 2.12 checks: no IAM users with console passwords, active keys only for declared service accounts). `legacy_iam` is functionally identical to hybrid in code; the tag exists for coverage-narrative honesty. |
| `iam_service_account_usernames` | `[]` | Consulted only when `iam_access_model == 'pure_sso'`. Usernames of IAM principals authorised to hold active long-lived access keys (CI/CD, break-glass). CIS 2.12's 90-day-rotation rule still applies to listed usernames. |
| `c_2_1_3_attestation_uri` | `''` | URI (`s3://`, `https://`, or `file://`) of the periodic-review attestation that the Organizations management account hosts no workloads. Checked via the `document_attestation` resource — the control PASSES when the document exists and is current, FAILS when empty/missing/stale. Empty default fails C-2.1.3 until configured. |
| `c_2_1_3_attestation_max_age_days` | `365` | Staleness window (days) for the C-2.1.3 attestation. |
| `c_2_19_attestation_uri` | `''` | URI (`s3://`, `https://`, or `file://`) of the attestation documenting centralized IAM identity (federation / AWS Organizations). Checked via `document_attestation`; empty default fails C-2.19 until configured. |
| `c_2_19_attestation_max_age_days` | `365` | Staleness window (days) for the C-2.19 attestation. |

### Partition posture

GovCloud applicability claims in HDF / OSCAL output rest on **AWS documentation**, not on live scan evidence — this profile is developed and validated against AWS Commercial. The profile's `partition_applicability.yml` marks controls `applicable / applicable` only where AWS publishes identical SDK + service availability for both partitions. Partition-specific handling in code:

- CloudTrail event-selector S3-ARN matcher accepts both `arn:aws:s3` and `arn:aws-us-gov:s3`.
- Per-region resources pull the region list from `describe_regions`, so GovCloud runs naturally narrow to `us-gov-west-1` / `us-gov-east-1`.

### Access-model posture

The `iam_access_model` input only *adds* stricter describes in `pure_sso` mode. It never relaxes a CIS baseline rule — 2.11 and 2.12 enforce the same stale-credential and key-rotation thresholds in all three modes. The input's job is to close the defensive gap that appears in pure-SSO accounts, where IAM-user-focused checks pass trivially because IAM users are rare to absent; the stricter describes flag any regression toward IAM-user-based human access.

Identity Center–specific controls (stale permission-set assignments, over-privileged permission sets, session durations) are **not** in CIS AWS Foundations v7.0 and are not enforced by this profile. Those would need custom resources against `sso-admin` / `identitystore` — future work, outside this profile's scope.

### Example: pure-SSO consumer `inputs.yml`

```yaml
aws_partition: aws
iam_access_model: pure_sso
iam_service_account_usernames:
  - cicd-deployer
  - terraform-runner
scan_regions:
  - us-east-1
  - us-west-2
```

### Example: hybrid IAM+SSO consumer (default)

`inputs.yml` needs only `aws_partition: aws`. Every other input inherits the declared default.

## Logging strategy (#42)

§4 (CloudTrail / Config / VPC flow / S3 access logging — 10 controls) and §5 (CloudWatch metric filters + Security Hub — 16 controls) assert per-account artefacts that may legitimately live in a central logging account. The `logging_strategy` input expresses that boundary cleanly.

Two values:

- **`logging_strategy: aws_default`** (recommended for consumers with consolidated CloudTrail / centralised SIEM / Organizations-level audit trails). Every §4 + §5 control skips with a `boundary-inheritance` rationale citing `logging_attestation_reference`. The eight failures that previously lit up nightly runs (`cis-aws-foundations 5.1` / `5.10`–`5.16`) become attestation-skips with a doc reference.
- **`logging_strategy: custom`** (default — preserves pre-#42 behaviour). Every §4 + §5 check runs as before, unless `logging_requirements.required_metric_filters` is non-empty:
  - Listed CIS rule IDs run their checks.
  - Unlisted rule IDs skip with the boundary-inheritance rationale.

**Per-rule overrides** via `logging_requirements.metric_filter_overrides` (consulted under `custom` mode only):

```yaml
logging_requirements:
  log_group_arn_prefix: "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail"
  retention_days: 365
  required_metric_filters: ["5.1", "5.7", "5.16"]
  metric_filter_overrides:
    "5.7":
      log_group_arn_prefix: "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail-Console"
    "5.16":
      hub_arn: "arn:aws:securityhub:us-east-1:999999999999:hub/default"   # delegated-admin hub
```

`5.1`–`5.15` recognise `log_group_arn_prefix` per rule (asserts the resolved log group's ARN starts with the prefix). `5.16` recognises `hub_arn` (asserts a specific Security Hub ARN exists — useful when the delegated-admin hub lives in a separate account).

Helper methods exposed by `libraries/_logging_strategy_helpers.rb`:

```ruby
logging_strategy_inherits?(rid)            # bool — should this control skip?
logging_strategy_skip_message(rid, default)# string — for the skip body
logging_strategy_metric_filter_override(rid)# hash — per-rule overrides
```

## NIST 800-53 Tagging

Every control carries `tag nist: [...]` resolved at scaffold time from
the XCCDF's DISA CCI identifiers via Heimdall's
`CciNistMappingData.ts`. Provenance chain:

```ruby
XCCDF <ident system="http://cyber.mil/cci">CCI-XXXXXX</ident>
    ↓ (lookup in heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts)
NIST 800-53 control (e.g. "AC-2 (3)")
    ↓ (emitted by tools/xccdf_to_inspec/scaffold.py)
tag nist: ['AC-2 (3)']
```

The scaffolder **fails loudly** if any rule has a CCI that is not
present in the map — we never ship controls with CCI-only tags.

## Regenerating From XCCDF

```bash
python3 tools/xccdf_to_inspec/scaffold.py \
  --xccdf benchmarks/xccdf/cis_amazon_web_services_foundations_benchmark_v700.xml \
  --cci-map /path/to/heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts \
  --output profiles/cis-aws-foundations \
  --profile-name cis-aws-foundations \
  --profile-title "AWS Foundations CIS Baseline" \
  --supports-platform aws
```

Use `--only <cis-number>` to regenerate a single control.

## Status

All 70 controls scaffolded and filled. Each control carries a `tag implementation_status:` mapped to OSCAL's native vocabulary (added in #31) — see the [Control Classification Guide](../../docs/dev/Control_Classification_Guide.md) for the full 5-bucket taxonomy.

### Coverage distribution

| Type | `implementation_status` | Count |
| - | - | - |
| **Automated** | `implemented` | 62 (post cis-aws-foundations completion — #64 — and post C-2.21 cross-resource scan — #72) |
| **Attestation** | `alternative` | 8 (4 from #21 §2.1 + 4 from completion: §2.1.3 / §2.1.4 / §2.19 / §3.1.3) |
| **Pending** | `planned` | 0 |

Subset still marked as attestation:

- **`alternative` (attestation-bound)** — 8 controls:
  - **2.1.1, 2.1.2, 2.1.5, 2.1.6** (#21) — Organizations-management-account state not observable from a member-account scanner. `tag attestation_category: 'policy'`, annual cadence.
  - **2.1.3, 2.1.4, 2.19** (#64) — workload-inventory / OU-taxonomy / IdP-architecture governance reviews. `tag attestation_category: 'policy'`, annual cadence.
  - **3.1.3** (#64) — Macie classification + finding-triage cadence. `tag attestation_category: 'operational'`, quarterly cadence (engineering / SecOps owned).
- **`planned`** — none. C-2.21 was the last `planned` control; #72 closes the cross-resource Principal: "*" scan via `aws_resource_policy_violations` (S3 / KMS / Secrets Manager / SQS / SNS / Lambda).

### Attestation-bound controls

The 8 attestation-bound controls use the SAF CLI / CMSgov attestation pattern. The profile ships:

- **`attestations.example.json`** — generic SAF-format JSON template; consumers fork this and fill in real reviewer / date / evidence values.

`attestation_category` routes to team queues per `docs/dev/Attestation_Strategy.md` "Categorization for team routing":

- **`policy`** (7 controls — 2.1.1, 2.1.2, 2.1.3, 2.1.4, 2.1.5, 2.1.6, 2.19): Organizations / IdP governance reviewed annually by the Policy / Compliance team.
- **`operational`** (1 control — 3.1.3): operational hygiene reviewed quarterly by the Engineering / SecOps team.

When SAF CLI integration lands in `validate.yml` (separate follow-up), these controls' HDF outcomes will reflect the actual attestation `status` + frequency-window check rather than the current `skip 'attestation-required'`. See `docs/dev/Attestation_Strategy.md` for the full decision matrix and authoring guide.

Custom resources live under `libraries/`:

- `aws_iam_root_user.rb` — local override fixing an upstream NPE when no virtual MFA devices exist; preserves the vendored API (`has_mfa_enabled?`, `has_hardware_mfa_enabled?`, etc.). Extended in #64 with credential-report-driven `last_used_at` / `used_recently?(within_days:)` for CIS 2.7.
- `aws_iam_access_analyzers.rb` — per-region Access Analyzer enumeration for CIS 2.18.
- `aws_cloudtrail_event_selectors.rb` — S3 object-level logging predicates for CIS 4.8 / 4.9.
- `aws_account_contact.rb` — `aws_account_primary_contact` + `aws_account_alternate_contact(contact_type:)` for CIS 2.2 / 2.3.
- `aws_s3_bucket_versioning.rb` (#64) — exposes Status + MfaDelete from GetBucketVersioning for CIS 3.1.2.
- `aws_network_acls_admin_ingress.rb` (#64) — first-match-wins NACL scanner for CIS 6.2 (admin-port ingress from 0.0.0.0/0).
- `aws_vpc_peering_route_violations.rb` (#64) — VPC-peering route-table least-access scanner for CIS 6.6 (per-peering CIDR allowlist).
- `aws_vpc_endpoint_coverage.rb` (#64) — per-VPC required-service coverage scanner for CIS 6.8.
- `iam_policy_statement.rb` (#72) — pure-Ruby parser for resource-policy JSON. Walks Statement[]; exposes `effect`, `principal_is_wildcard?` (covers `"*"`, `{"AWS":"*"}`, `{"Service":"*"}`, `{"Federated":"*"}`, `{"CanonicalUser":"*"}`, plus arrays), and `has_condition?` (coarse — any non-empty Condition counts as restrictive). No SDK calls; reusable by future controls that need wildcard-principal heuristics.
- `aws_resource_policy_violations.rb` (#72) — account-wide scanner across S3, KMS, Secrets Manager, SQS, SNS, Lambda for CIS 2.21. Per-service walkers swallow AccessDenied / NoSuch... → `partial_failures` (informational, non-failing) so a missing IAM permission on one service doesn't mask findings on the others. Honors `c221_excluded_arns` (exact-ARN exemption) + `scan_regions`.

See the top-level `README.md` for the overall repo state and the sub-issue tracker for per-profile progress.

---

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-aws-foundations-v7.0.0)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-aws-foundations-v7.0.0)
