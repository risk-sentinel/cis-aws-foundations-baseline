# cis-aws-foundations-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-aws-foundations-baseline)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-aws-foundations-baseline)

InSpec / CINC Auditor profile validating an AWS account against the
**CIS Amazon Web Services Foundations Benchmark v7.0.0** — 70 controls across
identity, logging, monitoring, networking and account-level configuration.

Targets **AWS Commercial** and **AWS GovCloud (non-DoD)**. Per-control partition
applicability is in [`partition_applicability.yml`](partition_applicability.yml)
and encoded as `tag applicable_partitions:`.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/cis-aws-foundations-baseline
cd cis-aws-foundations-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t aws:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

`--input-file` is **not optional** here, and it matters more than in most
profiles: four inputs describe the *shape* of your estate, and left at defaults
on an estate arranged differently they do not fail loudly — they assess the
wrong thing.

### Credentials

Standard AWS credential resolution. Read-only across the account surface:

```
iam:Get*  iam:List*  iam:GenerateCredentialReport  iam:GetCredentialReport
cloudtrail:DescribeTrails  cloudtrail:GetTrailStatus  cloudtrail:GetEventSelectors
config:Describe*  s3:GetBucket*  s3:ListAllMyBuckets  kms:DescribeKey
ec2:Describe*  logs:DescribeLogGroups  logs:DescribeMetricFilters
cloudwatch:DescribeAlarms  sns:ListSubscriptionsByTopic
securityhub:DescribeHub    organizations:ListAccounts   (see note)
```

`organizations:*` is only needed for the organizational modes. When the scan
runs from a member account, `aws_organizations_role_arn` is how it reaches them.

### What a first run looks like

Against a real single account, defaults except `aws_partition`:

**65 controls with results, 217 results — roughly 156 passed / 54 failed / 7 skipped.**

If you see far fewer, that is the signal to investigate. A run that assessed
nothing exits 0 and looks clean.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml). 27 inputs — the
widest surface in the estate, because CIS Foundations covers an *account* rather
than a service, and an account's arrangement cannot be guessed.

| Group | Inputs |
|---|---|
| **Required** | `aws_partition` |
| **Account shape** | `cloudtrail_mode`, `aws_config_mode`, `vpc_flow_logs_mode`, `iam_access_model` |
| **Organization context** | `aws_organizations_role_arn`, `log_archive_account_id`, the three `expected_*_destinations` |
| **Scoping** | `scan_regions`, `iam_service_account_usernames` |
| **Policy** | `root_mfa_requirement`, `root_user_recent_use_threshold_days`, `s3_mfa_delete_protection`, `security_hub_required`, `required_vpc_endpoints`, `vpc_peering_allowed_cidrs` |
| **Exceptions** | `s3_mfa_delete_excluded_buckets`, `c221_excluded_arns` |
| **Attestation** | the `*_base` URIs, two `*_attestation_uri` overrides, two staleness windows |

**The four account-shape inputs are the ones to get right first.** They describe
how your estate is arranged — one org trail or a trail per account, Identity
Center or long-lived IAM users. Wrong values do not error; they quietly assess
the wrong thing.

**`iam_service_account_usernames` is worth a minute.** Left empty, every IAM user
is treated as a human, which produces console-password and MFA findings against
programmatic accounts that cannot have a console password at all.

---

## Controls

70 controls following the CIS v7.0.0 numbering:

| Section | Assesses |
|---|---|
| 1 — Identity & Access | root usage and MFA, user MFA, key rotation, password policy, unused credentials |
| 2 — Storage | S3 public access and encryption, EBS and RDS encryption defaults |
| 3 — Logging | CloudTrail coverage, integrity validation, KMS encryption, Config, flow logs |
| 4 — Monitoring | metric filters and alarms for the account-level events CIS enumerates |
| 5 — Networking | default security group, NACLs, remote-access exposure |
| 6 — Extended | peering route least-access, VPC endpoints, Security Hub |

---

## Empty collections

Several controls loop over a collection and describe each member. If the account
holds none of that resource the loop never executes, so without care the control
registers no `describe` blocks and emits **zero results** — neither passed nor
Not Applicable, but *absent*. A control that asserts nothing while reporting
not-red is the failure this profile exists to catch, and it also breaks the
evidence pipeline: the HDF v3 schema requires at least one result per
requirement, so `hdf convert` refuses the whole document.

Those controls call `scoped_or_na` from
[`libraries/_scoped_collection.rb`](libraries/_scoped_collection.rb), which folds
emptiness into applicability and writes the `only_if` for them. An account
without the resource renders as **Not Applicable — a statement** — rather than as
silence.

The helper exists because expressing this inline cost every affected control the
same eight lines. Said once, each control keeps only what is specific to it:
which collection, why it might be out of scope, and what to assert.

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/cis-aws-foundations-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-account
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: cis-aws-foundations-v7.0.0
      profile_version: "0.1.0"
      inputs_file: inputs/mine.yml
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/cis-aws-foundations-baseline
    ref: v0.1.8
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-account
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: cis-aws-foundations-v7.0.0
      profile_version: "0.1.0"
      inputs_file: inputs/mine.yml
```

`target`, `boundary`, `aws_region`, `profile_name` and `profile_version` are
required and have no defaults. A missing one is rejected before the job starts —
GitHub refuses the `workflow_call`, GitLab refuses the `include` — rather than
running against the wrong account or filing the results under the wrong label.
`inputs_file` defaults to `inputs/example.yml`, which runs with example values,
so set it to your own copy. See [docs/ci-templates.md](docs/ci-templates.md) for
the full contract, including which secrets are genuinely optional.

An `include:` brings YAML and nothing else, which is why the logic lives in the
YAML rather than in a script an including project would never receive. The
templates are carried in this repository on purpose: clone it or include it and
you have the entire pipeline, with nothing else to install.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump. On 3.5.1, `@1` and `@2` are byte-identical.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.
An audit chain where every field is self-asserted is a story.

Schema authority: the shared evidence-store schema.

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: cis-aws-foundations-v7.0.0
    git: https://github.com/risk-sentinel/cis-aws-foundations-baseline.git
    tag: v0.1.6
```

Then `include_controls 'cis-aws-foundations-v7.0.0'` and supply your own inputs. Input overrides
reach the depended profile's controls, so your values win without editing
anything here.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real target before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
