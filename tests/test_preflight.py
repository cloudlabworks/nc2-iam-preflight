"""Offline tests: every cloud call is replaced by a fake, so these run anywhere.
    python3 -m unittest discover -s tests -v
They prove the logic (matching, classification, ARN handling, org-policy reading) against recorded response
shapes. They do NOT prove the tool against a live cloud: that needs a run in each cloud's shell."""
import json, sys, types, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import nc2_iam_preflight as p  # noqa: E402

CONTRIBUTOR = {"actions": ["*"], "notActions": ["Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write",
               "Microsoft.Authorization/elevateAccess/Action", "Microsoft.Blueprint/blueprintAssignments/write",
               "Microsoft.Blueprint/blueprintAssignments/delete", "Microsoft.Compute/galleries/share/action"],
               "dataActions": [], "notDataActions": []}
OWNER = {"actions": ["*"], "notActions": [], "dataActions": [], "notDataActions": []}
UAA = {"actions": ["*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"], "notActions": [], "dataActions": [], "notDataActions": []}


def fake_run(table):
    def run(cmd):
        key = " ".join(cmd)
        for k, v in table.items():
            if k in key:
                if isinstance(v, Exception):
                    raise v
                return v
        raise AssertionError(f"unexpected command: {key}")
    return run


class AzureMatching(unittest.TestCase):
    def test_contributor_cannot_assign_roles(self):
        self.assertFalse(p.az_granted("Microsoft.Authorization/roleAssignments/write", [CONTRIBUTOR]))
        self.assertFalse(p.az_granted("Microsoft.Authorization/roleDefinitions/write", [CONTRIBUTOR]))
        self.assertTrue(p.az_granted("Microsoft.Compute/virtualMachines/write", [CONTRIBUTOR]))

    def test_owner_and_uaa_can(self):
        for s in (OWNER, UAA):
            self.assertTrue(p.az_granted("Microsoft.Authorization/roleAssignments/write", [s]))

    def test_contributor_plus_uaa_together(self):
        self.assertTrue(p.az_granted("Microsoft.Authorization/roleAssignments/write", [CONTRIBUTOR, UAA]))

    def test_wildcard_requirement_needs_covering_grant(self):
        need = "Microsoft.Compute/virtualMachines/*"
        self.assertTrue(p.az_granted(need, [{"actions": ["Microsoft.Compute/*"]}]))
        self.assertFalse(p.az_granted(need, [{"actions": ["Microsoft.Compute/virtualMachines/read"]}]))

    def test_case_insensitive(self):
        self.assertTrue(p.az_granted("microsoft.storage/storageaccounts/read", [{"actions": ["Microsoft.Storage/storageAccounts/*"]}]))

    def test_nutanix_custom_role_grants_itself(self):
        doc = p.load("azure-nc2-app")
        role = {"actions": doc["actions"], "notActions": [], "dataActions": doc["dataActions"], "notDataActions": []}
        self.assertTrue(all(p.az_granted(a, [role]) for a in doc["actions"]))
        self.assertTrue(all(p.az_granted(a, [role], data=True) for a in doc["dataActions"]))

    def test_contributor_lacks_storage_data_actions(self):
        doc = p.load("azure-nc2-app")
        self.assertFalse(any(p.az_granted(a, [CONTRIBUTOR], data=True) for a in doc["dataActions"]))


class AwsLogic(unittest.TestCase):
    def test_arn_forms(self):
        self.assertEqual(p.aws_principal_arn("arn:aws:iam::111122223333:user/alex"), "arn:aws:iam::111122223333:user/alex")
        self.assertIsNone(p.aws_principal_arn("arn:aws:iam::111122223333:root"))
        sso = "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_abc123/alex@example.com"
        seen = []
        got = p.aws_principal_arn(sso, lambda r: seen.append(r) or f"arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/{r}")
        self.assertEqual(seen, ["AWSReservedSSO_Admin_abc123"])
        self.assertIn("/aws-reserved/sso.amazonaws.com/", got)

    def test_classify(self):
        self.assertEqual(p.aws_classify({"EvalDecision": "allowed"})[0], p.HAVE)
        self.assertEqual(p.aws_classify({"EvalDecision": "implicitDeny"})[0], p.MISSING)
        self.assertEqual(p.aws_classify({"EvalDecision": "explicitDeny"})[0], p.BLOCKED)
        self.assertEqual(p.aws_classify({"EvalDecision": "implicitDeny", "OrganizationsDecisionDetail": {"AllowedByOrganizations": False}})[0], p.BLOCKED)
        self.assertEqual(p.aws_classify({"EvalDecision": "implicitDeny", "PermissionsBoundaryDecisionDetail": {"AllowedByPermissionsBoundary": False}})[0], p.BLOCKED)

    def test_check_aws_end_to_end(self):
        results = [{"EvalActionName": a, "EvalDecision": "implicitDeny" if a == "iam:PassRole" else "allowed"} for a in p.AWS_SETUP_ACTIONS]
        p.run = fake_run({
            "sts get-caller-identity": {"Arn": "arn:aws:sts::111122223333:assumed-role/Dev/alex"},
            "get-role --role-name Dev": {"Role": {"Arn": "arn:aws:iam::111122223333:role/Dev"}},
            "simulate-principal-policy": {"EvaluationResults": results},
            "get-role --role-name Nutanix": p.CliError("An error occurred (NoSuchEntity) when calling the GetRole operation"),
        })
        rep = p.check_aws(types.SimpleNamespace())
        missing = [r["item"] for r in rep.rows if r["status"] == p.MISSING]
        self.assertEqual(missing, ["iam:PassRole"])
        self.assertEqual(rep.exit_code(), 1)

    def test_simulator_refused_is_unknown_not_pass(self):
        p.run = fake_run({
            "sts get-caller-identity": {"Arn": "arn:aws:iam::111122223333:user/alex"},
            "simulate-principal-policy": p.CliError("AccessDenied: iam:SimulatePrincipalPolicy"),
            "get-role --role-name Nutanix": p.CliError("NoSuchEntity"),
        })
        rep = p.check_aws(types.SimpleNamespace())
        self.assertEqual(rep.exit_code(), 2)


class AzureEndToEnd(unittest.TestCase):
    def test_contributor_user_in_locked_tenant(self):
        p.run = fake_run({
            "account show": {"name": "Lab", "user": {"name": "alex@example.com", "type": "user"}},
            "authorizationPolicy": {"defaultUserRolePermissions": {"allowedToCreateApps": False}},
            "transitiveMemberOf": {"value": [{"displayName": "Reports Reader"}]},
            "Microsoft.Authorization/permissions": {"value": [CONTRIBUTOR]},
        })
        rep = p.check_azure(types.SimpleNamespace(subscription="0000", app_id=None))
        missing = {r["item"] for r in rep.rows if r["status"] == p.MISSING}
        self.assertEqual(missing, {"create an app registration (Entra ID)", "Microsoft.Authorization/roleAssignments/write",
                                   "Microsoft.Authorization/roleDefinitions/write"})

    def test_app_with_nutanix_role_passes(self):
        doc = p.load("azure-nc2-app")
        role = {"actions": doc["actions"], "notActions": [], "dataActions": doc["dataActions"], "notDataActions": []}
        p.run = fake_run({
            "account show": {"name": "Lab", "user": {"name": "alex@example.com", "type": "user"}},
            "authorizationPolicy": {"defaultUserRolePermissions": {"allowedToCreateApps": True}},
            "transitiveMemberOf": {"value": []},
            "Microsoft.Authorization/permissions": {"value": [OWNER]},
            "role assignment list": [{"roleDefinitionId": "/subscriptions/0000/providers/Microsoft.Authorization/roleDefinitions/abc", "roleDefinitionName": "nc2-custom-role"}],
            "role definition list": [{"permissions": [role]}],
        })
        rep = p.check_azure(types.SimpleNamespace(subscription="0000", app_id="app-1"))
        self.assertEqual(rep.exit_code(), 0)


class GcpLogic(unittest.TestCase):
    def test_constraints(self):
        self.assertEqual(p.gcp_constraint_status("c", {"booleanPolicy": {"enforced": True}})[0], p.BLOCKED)
        self.assertEqual(p.gcp_constraint_status("c", {"booleanPolicy": {}})[0], p.HAVE)
        self.assertEqual(p.gcp_constraint_status("c", {"listPolicy": {"allValues": "DENY"}})[0], p.BLOCKED)
        self.assertEqual(p.gcp_constraint_status("c", {"listPolicy": {"allowedValues": ["x"]}})[0], p.UNKNOWN)
        self.assertEqual(p.gcp_constraint_status("c", None)[0], p.HAVE)

    def test_lists_match_doc(self):
        self.assertEqual(len(p.load("gcp-nodes-sa")["permissions"]), 23)
        c = p.load("gcp-console-sa")
        self.assertEqual(len(c["permissions"]), 98)  # the guide states 97 and lists 98 (2026-10-08)
        self.assertEqual(c["doc_stated_count"], 97)
        self.assertEqual(set(c["optional"]), {"iam.roles.get", "resourcemanager.projects.getIamPolicy"})

    def test_check_gcp_key_creation_blocked(self):
        nodes = p.load("gcp-nodes-sa")["permissions"]
        p.run = fake_run({
            "config list": {"core": {"account": "alex@example.com"}},
            "iam.disableServiceAccountKeyCreation": {"booleanPolicy": {"enforced": True}},
            "compute.vmCanIpForward": {},
            "services list": [{"config": {"name": "compute.googleapis.com"}}],
            "get-iam-policy": {"bindings": [{"role": "projects/lab/roles/nc2_node_role", "members": ["serviceAccount:n@lab.iam.gserviceaccount.com"]}]},
            "roles describe nc2_node_role": {"includedPermissions": nodes[:-1]},
        })
        args = types.SimpleNamespace(project="lab", console_sa=None, nodes_sa="n@lab.iam.gserviceaccount.com")
        rep = p.check_gcp(args, token_fn=lambda: "t", test_fn=lambda proj, perms, tok: set(perms))
        blocked = [r["item"] for r in rep.rows if r["status"] == p.BLOCKED]
        missing = [r["item"] for r in rep.rows if r["status"] == p.MISSING]
        self.assertEqual(blocked, ["iam.disableServiceAccountKeyCreation"])
        self.assertEqual(missing, [nodes[-1]])
        self.assertEqual(rep.exit_code(), 2)


if __name__ == "__main__":
    unittest.main()
