# nc2-iam-preflight

Before you onboard Nutanix Cloud Clusters (NC2), ask the cloud itself which permissions you're missing.

A checklist says "you need Contributor". This tells you *"you are missing
`Microsoft.Authorization/roleAssignments/write`; ask for User Access Administrator on subscription X"*, and it
tells you before the onboarding wizard fails, not after.

> **Status: untested against live clouds.** The logic is covered by offline tests (16, all passing) against
> recorded response shapes. It has not yet been run in a real AWS, Azure or Google Cloud account.

## Run it

Open the cloud's own shell, signed in as **the person who will do the onboarding**, then:

```bash
git clone <this repo> && cd nc2-iam-preflight

python3 nc2_iam_preflight.py aws
python3 nc2_iam_preflight.py azure --subscription <SUBSCRIPTION_ID> [--app-id <NC2_APP_ID>]
python3 nc2_iam_preflight.py gcp --project <PROJECT_ID> [--console-sa <EMAIL>] [--nodes-sa <EMAIL>]
```

Add `--json` for machine-readable output. Exit code `0` = nothing missing, `1` = something MISSING,
`2` = something BLOCKED or not evaluable.

It is **read-only**: it calls each cloud's permission evaluator and reads IAM. It never creates, grants or
deletes anything. Python 3.9+, standard library only, plus the CLI every cloud shell already has.

Why not a utility VM: an IAM check has to run *as you*. A VM runs as its own identity and would report what the
VM may do, not what you lack.

## What it checks

| Cloud | A. Can I onboard? (you) | B. Does what I built match the guide? |
|---|---|---|
| **AWS** | `iam simulate-principal-policy` on your own principal for the CloudFormation + IAM actions the NC2 stack needs. SCP and permission-boundary denials are reported as **BLOCKED**, separately from MISSING. SSO / assumed-role sessions are mapped to the underlying role ARN. | Whether `Nutanix-Clusters-High-Nc2-Cluster-Role-Prod` and `…-Orchestrator-Role-Prod` already exist. |
| **Azure** | Can you register an app in Entra ID (tenant setting or directory role)? Do you hold `roleDefinitions/write` and `roleAssignments/write` on the subscription, via the effective-permissions API? Contributor lacks the latter; that is the most common failure. | With `--app-id`: the app's role assignments against every action and data action in Nutanix's `nc2-custom-role`. |
| **Google Cloud** | `testIamPermissions` for each setup step (enable the Compute Engine API, create custom roles, service accounts and keys, grant roles), plus the org policies no IAM grant can fix: `iam.disableServiceAccountKeyCreation` and `compute.vmCanIpForward`. | With `--console-sa` / `--nodes-sa`: the roles bound to each service account against Nutanix's 98 / 23 permissions. |

Statuses: **HAVE**, **MISSING** (an IAM grant fixes it), **BLOCKED** (a policy above IAM denies it; an org
admin has to change it), **UNKNOWN** (couldn't evaluate; never counted as a pass), **INFO**.

## Where the permission lists come from

Only public sources. Nothing here comes from customer-authenticated material.

| File | Origin | Source |
|---|---|---|
| `permissions/gcp-console-sa.json`, `gcp-nodes-sa.json` | Nutanix | NC2 on Google Cloud Deployment and User Guide, *Appendix: Google Cloud Service Accounts Role Permissions* |
| `permissions/azure-nc2-app.json` | Nutanix | NC2 on Azure guide, *Creating an Azure Custom Role* |
| `permissions/aws-onboarding-user-doc.json` | Nutanix | NC2 on AWS guide, *Requirements for NC2 on AWS* (names IAMFullAccess + AWSCloudFormationFullAccess and CreateRole) |
| Setup-step lists in `nc2_iam_preflight.py` (`AWS_SETUP_ACTIONS`, `AZ_SETUP_ACTIONS`, `GCP_SETUP`) | **Derived** | Each documented setup step mapped to the cloud vendor's permission for that operation. Labelled as derived in the code. |

Each JSON file records its source URL, the doc's *Last Updated* date and when it was fetched. To refresh:

```bash
node tools/fetch-sources.mjs          # snapshots the public pages into sources/ (git-ignored)
python3 tools/extract-permissions.py  # rebuilds permissions/*.json; fails if a list parses shorter than the doc states
```

**Doc note (2026-10-08):** the Google Cloud appendix says the NC2 console service account needs "97
permissions" and then lists 98 distinct ones. The copy-paste `gcloud iam roles create` command in the guide
has the same 98. This tool checks all 98 and records the stated count alongside.

## Known limits

- **Azure:** deny assignments aren't visible to the effective-permissions API, so an action shown as HAVE can
  still be blocked by one.
- **Google Cloud, check B:** counts only direct project-level bindings. Roles granted at folder/org level,
  through groups, or with conditions aren't counted, so a MISSING there may be a false alarm (the report says so).
- **AWS:** the setup action list is derived. If your organisation customises the NC2 CloudFormation template,
  the actions it needs may differ.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Offline: every cloud call is faked. They prove the matching and classification logic, not live behaviour.
