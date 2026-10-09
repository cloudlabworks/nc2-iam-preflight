#!/usr/bin/env python3
"""nc2-iam-preflight: before onboarding NC2, ask the cloud itself which permissions you are missing.

Run it in the cloud's own shell (AWS CloudShell, Azure Cloud Shell, Google Cloud Shell), signed in as the person
who will do the onboarding. It is read-only: it calls the clouds' permission evaluators and reads IAM, it never
creates, grants or deletes anything.

Two checks per cloud:
  A. Can I onboard?   The signed-in user, against the setup steps in the NC2 user guide.
  B. Does what I built match the guide?   The role / app / service accounts NC2 will use, against Nutanix's list.

    python3 nc2_iam_preflight.py aws
    python3 nc2_iam_preflight.py azure --subscription SUB_ID [--app-id APP_ID]
    python3 nc2_iam_preflight.py gcp --project PROJECT_ID [--console-sa EMAIL] [--nodes-sa EMAIL]

Exit code: 0 nothing missing, 1 something MISSING, 2 something BLOCKED or not evaluable.
Python 3.9+, standard library only. Needs the cloud's CLI (aws / az / gcloud), which every cloud shell has.
"""
import argparse, fnmatch, json, subprocess, sys, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PERMS = HERE / "permissions"

HAVE, MISSING, BLOCKED, UNKNOWN, INFO = "HAVE", "MISSING", "BLOCKED", "UNKNOWN", "INFO"


class CliError(RuntimeError):
    pass


def run(cmd):
    """Run a cloud CLI command and return parsed JSON. Tests replace this function."""
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise CliError((p.stderr or p.stdout).strip().splitlines()[-1] if (p.stderr or p.stdout).strip() else f"exit {p.returncode}")
    out = p.stdout.strip()
    return json.loads(out) if out else None


def load(name):
    return json.loads((PERMS / f"{name}.json").read_text())


class Report:
    def __init__(self, title):
        self.title, self.rows = title, []

    def add(self, check, item, status, detail=""):
        self.rows.append({"check": check, "item": item, "status": status, "detail": detail})

    def exit_code(self):
        s = {r["status"] for r in self.rows}
        return 2 if (BLOCKED in s or UNKNOWN in s) else 1 if MISSING in s else 0

    def print(self, as_json=False):
        if as_json:
            print(json.dumps({"title": self.title, "rows": self.rows, "exit": self.exit_code()}, indent=2))
            return
        print(f"\n{self.title}\n" + "=" * len(self.title))
        w = max([len(r["item"]) for r in self.rows] + [10])
        for check in dict.fromkeys(r["check"] for r in self.rows):
            print(f"\n[{check}]")
            for r in [r for r in self.rows if r["check"] == check]:
                print(f"  {r['status']:<8} {r['item']:<{w}}  {r['detail']}")
        counts = {k: sum(r["status"] == k for r in self.rows) for k in (HAVE, MISSING, BLOCKED, UNKNOWN)}
        print("\n" + "  ".join(f"{k}: {v}" for k, v in counts.items()))


# ---------------------------------------------------------------------------------------------------- AWS
# Nutanix (aws-onboarding-user-doc): run the CloudFormation template as a user with IAMFullAccess and
# AWSCloudFormationFullAccess, and CreateRole. Rather than look for those two policy names (a custom equivalent
# would fail), simulate the actions a CloudFormation stack that creates IAM roles, policies and instance profiles
# calls. This action list is DERIVED from the AWS resource-type reference, not published by Nutanix.
AWS_SETUP_ACTIONS = [
    "cloudformation:CreateStack", "cloudformation:DescribeStacks", "cloudformation:DescribeStackEvents",
    "cloudformation:UpdateStack", "cloudformation:DeleteStack", "cloudformation:CreateChangeSet",
    "cloudformation:DescribeChangeSet", "cloudformation:ExecuteChangeSet", "cloudformation:GetTemplateSummary",
    "iam:CreateRole", "iam:GetRole", "iam:DeleteRole", "iam:TagRole", "iam:UpdateAssumeRolePolicy",
    "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy",
    "iam:CreatePolicy", "iam:GetPolicy", "iam:CreatePolicyVersion", "iam:DeletePolicy",
    "iam:CreateInstanceProfile", "iam:GetInstanceProfile", "iam:AddRoleToInstanceProfile", "iam:PassRole",
]


def aws_principal_arn(caller_arn, get_role=None):
    """simulate-principal-policy needs an IAM user or role ARN. SSO and assumed-role sessions return an STS ARN;
    map it to the role, whose path (aws-reserved/sso.amazonaws.com/... for SSO) only get-role knows."""
    parts = caller_arn.split(":")
    if len(parts) < 6:
        raise ValueError(f"not an ARN: {caller_arn}")
    service, resource = parts[2], parts[5]
    if service == "iam" and resource == "root":
        return None  # the root user cannot be simulated
    if service == "iam":
        return caller_arn
    if service == "sts" and resource.startswith("assumed-role/"):
        role = resource.split("/")[1]
        if get_role:
            return get_role(role)
        return f"arn:{parts[1]}:iam::{parts[4]}:role/{role}"
    raise ValueError(f"unsupported caller type: {caller_arn}")


def aws_classify(result):
    dec = result.get("EvalDecision", "")
    org = (result.get("OrganizationsDecisionDetail") or {}).get("AllowedByOrganizations", True)
    pb = (result.get("PermissionsBoundaryDecisionDetail") or {}).get("AllowedByPermissionsBoundary", True)
    if dec == "allowed":
        return HAVE, ""
    if org is False:
        return BLOCKED, "denied by an Organizations SCP: an org admin has to change it, an IAM grant won't"
    if pb is False:
        return BLOCKED, "denied by a permissions boundary on your principal"
    if dec == "explicitDeny":
        return BLOCKED, "explicitly denied by a policy"
    return MISSING, "no policy grants it"


def check_aws(args):
    doc = load("aws-onboarding-user-doc")
    rep = Report("NC2 on AWS: IAM preflight")
    who = run(["aws", "sts", "get-caller-identity", "--output", "json"])
    rep.add("You", "signed in as", INFO, who["Arn"])
    try:
        arn = aws_principal_arn(who["Arn"], lambda r: run(["aws", "iam", "get-role", "--role-name", r, "--output", "json"])["Role"]["Arn"])
    except CliError as e:
        rep.add("A. Can I onboard?", "resolve your role", UNKNOWN, f"iam:GetRole failed ({e}); the simulator needs the role ARN")
        return rep
    if arn is None:
        rep.add("A. Can I onboard?", "root user", INFO, "root can do everything, but don't onboard as root: use an IAM user or role")
    else:
        try:
            res = run(["aws", "iam", "simulate-principal-policy", "--policy-source-arn", arn,
                       "--action-names", *AWS_SETUP_ACTIONS, "--output", "json"])
            for r in res["EvaluationResults"]:
                status, why = aws_classify(r)
                rep.add("A. Can I onboard?", r["EvalActionName"], status, why)
        except CliError as e:
            rep.add("A. Can I onboard?", "iam:SimulatePrincipalPolicy", UNKNOWN,
                    f"the simulator itself was refused ({e}). Ask for iam:SimulatePrincipalPolicy, or confirm by hand that you hold {', '.join(doc['managed_policies'])}")
    for role in doc["roles_created"]:
        try:
            run(["aws", "iam", "get-role", "--role-name", role, "--output", "json"])
            rep.add("B. Already onboarded?", role, INFO, "exists: the CloudFormation stack has run in this account")
        except CliError as e:
            msg = str(e)
            rep.add("B. Already onboarded?", role, INFO, "not created yet" if "NoSuchEntity" in msg else f"could not check ({msg})")
    rep.add("Source", "Nutanix requirement", INFO, f"{doc['statement']} ({doc['url']}, updated {doc['doc_last_updated']})")
    return rep


# -------------------------------------------------------------------------------------------------- Azure
def az_matches(pattern, action):
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def az_granted(required, permission_sets, data=False):
    """Azure semantics: an action is granted if one permission set allows it and that same set does not exclude it.
    A required action may itself be a wildcard (Microsoft.Compute/virtualMachines/*); a granted pattern covers it
    when the pattern matches the requirement string. Deny assignments are not visible here (see report note)."""
    allow, deny = ("dataActions", "notDataActions") if data else ("actions", "notActions")
    for ps in permission_sets:
        if any(az_matches(p, required) for p in ps.get(allow) or []) and not any(
                az_matches(n, required) or az_matches(required, n) for n in ps.get(deny) or []):
            return True
    return False


AZ_APP_DEV_ROLES = {"Application Administrator", "Cloud Application Administrator", "Application Developer",
                    "Global Administrator", "Hybrid Identity Administrator"}
# Check A for Azure is DERIVED from the NC2 guide's steps (create an app registration, create a custom role at
# the subscription, assign it to the app) mapped to Microsoft's permissions for those operations.
AZ_SETUP_ACTIONS = ["Microsoft.Authorization/roleDefinitions/write", "Microsoft.Authorization/roleAssignments/write"]


def check_azure(args):
    doc = load("azure-nc2-app")
    rep = Report("NC2 on Azure: IAM preflight")
    sub = args.subscription
    acct = run(["az", "account", "show", "--subscription", sub, "--output", "json"])
    rep.add("You", "signed in as", INFO, f"{acct['user']['name']} ({acct['user']['type']}) on subscription {acct['name']}")
    # A1: can this user create an app registration?
    try:
        pol = run(["az", "rest", "--method", "GET", "--url", "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"])
        allowed = (pol.get("defaultUserRolePermissions") or {}).get("allowedToCreateApps")
        roles = run(["az", "rest", "--method", "GET", "--url",
                     "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName"])
        names = {r.get("displayName") for r in roles.get("value", [])}
        held = sorted(names & AZ_APP_DEV_ROLES)
        if allowed or held:
            rep.add("A. Can I onboard?", "create an app registration (Entra ID)", HAVE,
                    "tenant lets all users register apps" if allowed else f"via directory role: {', '.join(held)}")
        else:
            rep.add("A. Can I onboard?", "create an app registration (Entra ID)", MISSING,
                    "tenant blocks app registration for users and you hold none of: " + ", ".join(sorted(AZ_APP_DEV_ROLES)) + ". Ask for Application Developer")
    except CliError as e:
        rep.add("A. Can I onboard?", "create an app registration (Entra ID)", UNKNOWN, f"Graph lookup failed ({e})")
    # A2: can this user create the custom role and assign it at the subscription?
    try:
        perms = run(["az", "rest", "--method", "GET", "--url",
                     f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"])
        sets = perms.get("value", [])
        hints = {"Microsoft.Authorization/roleAssignments/write": "Contributor does NOT include this. Ask for User Access Administrator or Owner on the subscription",
                 "Microsoft.Authorization/roleDefinitions/write": "needed to create nc2-custom-role. Owner or User Access Administrator have it"}
        for a in AZ_SETUP_ACTIONS:
            ok = az_granted(a, sets)
            rep.add("A. Can I onboard?", a, HAVE if ok else MISSING, "" if ok else hints[a])
    except CliError as e:
        rep.add("A. Can I onboard?", "effective permissions on the subscription", UNKNOWN, f"lookup failed ({e})")
    rep.add("A. Can I onboard?", "deny assignments", INFO, "not visible to this check; a deny assignment can still block an action listed as HAVE")
    # B: does the NC2 app's role cover Nutanix's custom role?
    if args.app_id:
        try:
            ras = run(["az", "role", "assignment", "list", "--assignee", args.app_id, "--scope", f"/subscriptions/{sub}",
                       "--include-inherited", "--output", "json"])
            sets = []
            for ra in ras:
                rd = run(["az", "role", "definition", "list", "--name", ra["roleDefinitionId"].split("/")[-1],
                          "--scope", f"/subscriptions/{sub}", "--output", "json"])
                for d in rd:
                    sets.extend(d.get("permissions") or [])
            rep.add("B. Does the NC2 app match the guide?", "role assignments found", INFO,
                    ", ".join(sorted({ra.get("roleDefinitionName", "?") for ra in ras})) or "none")
            for a in doc["actions"]:
                if not az_granted(a, sets):
                    rep.add("B. Does the NC2 app match the guide?", a, MISSING, "action")
            for a in doc["dataActions"]:
                if not az_granted(a, sets, data=True):
                    rep.add("B. Does the NC2 app match the guide?", a, MISSING, "data action")
            if not any(r["check"].startswith("B.") and r["status"] == MISSING for r in rep.rows):
                rep.add("B. Does the NC2 app match the guide?", f"all {len(doc['actions'])} actions + {len(doc['dataActions'])} data actions", HAVE)
        except CliError as e:
            rep.add("B. Does the NC2 app match the guide?", "role assignments", UNKNOWN, f"lookup failed ({e})")
    rep.add("Source", "Nutanix custom role", INFO, f"{doc['url']} (updated {doc['doc_last_updated']})")
    return rep


# ----------------------------------------------------------------------------------------------- Google Cloud
# Check A is DERIVED: each setup step in the NC2 guide mapped to the Google Cloud IAM permission it needs.
GCP_SETUP = [
    ("serviceusage.services.enable", "enable the Compute Engine API"),
    ("iam.roles.create", "create nc2_node_role and nc2_cluster_creation_custom_role"),
    ("iam.roles.get", "describe the custom roles (verification step)"),
    ("iam.serviceAccounts.create", "create the NC2 console service account"),
    ("iam.serviceAccounts.get", "read the service accounts"),
    ("iam.serviceAccountKeys.create", "create the JSON key the NC2 console signs in with"),
    ("resourcemanager.projects.getIamPolicy", "read the project's IAM policy"),
    ("resourcemanager.projects.setIamPolicy", "grant the custom roles to the service accounts"),
]
# Organization policies that no IAM grant can override.
GCP_ORG_CONSTRAINTS = {
    "constraints/iam.disableServiceAccountKeyCreation": "blocks the service account key the NC2 console needs",
    "constraints/compute.vmCanIpForward": "the guide requires IP forwarding to be allowed at the organization level",
}


def gcp_constraint_status(constraint, policy):
    """Interpret an effective org policy. Returns (status, detail)."""
    if not policy:
        return HAVE, "not set"
    if "booleanPolicy" in policy:
        return (BLOCKED, "enforced") if policy["booleanPolicy"].get("enforced") else (HAVE, "not enforced")
    lp = policy.get("listPolicy")
    if lp is not None:
        if lp.get("allValues") == "DENY":
            return BLOCKED, "denies all"
        if lp.get("allowedValues") or lp.get("deniedValues"):
            return UNKNOWN, "restricted to specific values; confirm the NC2 instances are allowed"
        return HAVE, "allows all"
    return HAVE, "no restriction"


def gcp_test_permissions(project, permissions, token):
    req = urllib.request.Request(
        f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:testIamPermissions",
        data=json.dumps({"permissions": permissions}).encode(), method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return set(json.load(r).get("permissions", []))


def gcp_role_permissions(role):
    if role.startswith("projects/") or role.startswith("organizations/"):
        d = run(["gcloud", "iam", "roles", "describe", role.split("/")[-1], f"--{role.split('/')[0][:-1]}={role.split('/')[1]}", "--format=json"])
    else:
        d = run(["gcloud", "iam", "roles", "describe", role, "--format=json"])
    return set(d.get("includedPermissions", []))


def gcp_sa_permissions(policy, email):
    """Permissions a service account holds through DIRECT project-level bindings. Inherited (folder/org), group
    and conditional bindings are not evaluated, so a MISSING here can be a false alarm: the report says so."""
    member = f"serviceAccount:{email}"
    roles = [b["role"] for b in policy.get("bindings", []) if member in b.get("members", []) and not b.get("condition")]
    held = set()
    for r in roles:
        held |= gcp_role_permissions(r)
    return roles, held


def check_gcp(args, token_fn=None, test_fn=None):
    rep = Report("NC2 on Google Cloud: IAM preflight")
    p = args.project
    acct = run(["gcloud", "config", "list", "--format=json"])
    rep.add("You", "signed in as", INFO, f"{(acct.get('core') or {}).get('account')} on project {p}")
    token = (token_fn or (lambda: subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True, text=True).stdout.strip()))()
    try:
        have = (test_fn or gcp_test_permissions)(p, [x for x, _ in GCP_SETUP], token)
        for perm, why in GCP_SETUP:
            rep.add("A. Can I onboard?", perm, HAVE if perm in have else MISSING, why)
    except Exception as e:  # urllib raises several types; any failure means we could not evaluate
        rep.add("A. Can I onboard?", "testIamPermissions", UNKNOWN, f"call failed ({e})")
    for c, why in GCP_ORG_CONSTRAINTS.items():
        try:
            pol = run(["gcloud", "resource-manager", "org-policies", "describe", c, f"--project={p}", "--effective", "--format=json"])
            status, detail = gcp_constraint_status(c, pol)
        except CliError as e:
            status, detail = UNKNOWN, f"could not read ({e})"
        rep.add("A. Org policy (no IAM grant fixes these)", c.split("/")[1], status, f"{detail}: {why}")
    try:
        svc = run(["gcloud", "services", "list", "--enabled", f"--project={p}", "--filter=config.name=compute.googleapis.com", "--format=json"])
        rep.add("A. Can I onboard?", "Compute Engine API", INFO, "enabled" if svc else "not enabled yet (you need serviceusage.services.enable)")
    except CliError as e:
        rep.add("A. Can I onboard?", "Compute Engine API", UNKNOWN, f"could not read ({e})")
    if args.console_sa or args.nodes_sa:
        try:
            policy = run(["gcloud", "projects", "get-iam-policy", p, "--format=json"])
        except CliError as e:
            rep.add("B. Do the service accounts match the guide?", "project IAM policy", UNKNOWN, f"could not read ({e})")
            return rep
        for email, listname in ((args.console_sa, "gcp-console-sa"), (args.nodes_sa, "gcp-nodes-sa")):
            if not email:
                continue
            doc = load(listname)
            label = "console SA" if listname == "gcp-console-sa" else "cluster-node SA"
            try:
                roles, held = gcp_sa_permissions(policy, email)
            except CliError as e:
                rep.add("B. Do the service accounts match the guide?", label, UNKNOWN, f"role lookup failed ({e})")
                continue
            rep.add("B. Do the service accounts match the guide?", f"{label} roles", INFO, ", ".join(roles) or "no direct project bindings")
            gaps = [x for x in doc["permissions"] if x not in held]
            for x in gaps:
                rep.add("B. Do the service accounts match the guide?", x, INFO if x in doc.get("optional", []) else MISSING,
                        f"{label}" + (" (optional per guide: only used to validate)" if x in doc.get("optional", []) else ""))
            if not [x for x in gaps if x not in doc.get("optional", [])]:
                rep.add("B. Do the service accounts match the guide?", f"{label}: all {len(doc['permissions'])}", HAVE)
            if gaps:
                rep.add("B. Do the service accounts match the guide?", f"{label} note", INFO,
                        "only direct project bindings are counted; folder/org, group and conditional grants are not")
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    sp = ap.add_subparsers(dest="cloud", required=True)
    sp.add_parser("aws")
    az = sp.add_parser("azure"); az.add_argument("--subscription", required=True); az.add_argument("--app-id")
    g = sp.add_parser("gcp"); g.add_argument("--project", required=True); g.add_argument("--console-sa"); g.add_argument("--nodes-sa")
    args = ap.parse_args(argv)
    try:
        rep = {"aws": check_aws, "azure": check_azure, "gcp": check_gcp}[args.cloud](args)
    except FileNotFoundError as e:
        print(f"error: {e.filename} not found. Run this in the cloud's shell, where its CLI is installed.", file=sys.stderr)
        return 2
    except CliError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    rep.print(args.json)
    return rep.exit_code()


if __name__ == "__main__":
    sys.exit(main())
