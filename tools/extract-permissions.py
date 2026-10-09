#!/usr/bin/env python3
"""Extract the NC2 permission lists from the public doc snapshots in sources/ into permissions/*.json.

Every list carries its source URL, fetch time, actor (who needs it) and origin (nutanix | cloud-vendor | derived).
Counts the docs state are asserted, so a doc change fails loudly instead of silently shrinking a list.
    python3 tools/extract-permissions.py
"""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC, OUT = ROOT / "sources", ROOT / "permissions"


def page(name):
    text = (SRC / f"{name}.txt").read_text()
    url = re.search(r"^Source: (\S+)", text, re.M).group(1)
    fetched = re.search(r"^Fetched: (\S+)", text, re.M).group(1)
    updated = re.search(r"Last Updated: (\S+)", text)
    return text, {"url": url, "fetched": fetched, "doc_last_updated": updated.group(1) if updated else None}


def write(name, doc):
    (OUT / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n")
    print(f"ok   {name}: {len(doc.get('permissions', doc.get('actions', [])))}")


# --- Google Cloud: the appendix is the source of truth -------------------------------------------------
text, meta = page("gcp-appendix-role-permissions")
perm = re.compile(r"^([a-z]+(?:\.[A-Za-z]+){2,})$", re.M)
nodes_part = text.split("Service Account for Cluster Nodes", 1)[1].split("Service Account for NC2 Console", 1)[0]
console_part = text.split("Service Account for NC2 Console", 1)[1]
nodes = perm.findall(nodes_part)
console = perm.findall(console_part)
m_n = re.search(r"needs the following (\d+) permissions", nodes_part)
m_c = re.search(r"needs the following (\d+) permissions", console_part)
# The doc states a count for each list. Parsing fewer than stated means the parser lost lines: fail.
# Parsing more is recorded, not hidden: on 2026-10-08 the console list says 97 and lists 98 distinct permissions.
for label, got, m in (("cluster-node", nodes, m_n), ("console", console, m_c)):
    assert m, f"{label}: stated count not found"
    assert len(got) == len(set(got)), f"{label}: duplicate lines"
    assert len(got) >= int(m.group(1)), f"{label} list: doc says {m.group(1)}, parsed only {len(got)}"
    if len(got) != int(m.group(1)):
        print(f"WARN {label} list: doc states {m.group(1)}, lists {len(got)} distinct permissions")
OPTIONAL = {"iam.roles.get", "resourcemanager.projects.getIamPolicy"}  # gcp-sa-nc2-console: "optional ... used to validate"
write("gcp-nodes-sa", {"cloud": "gcp", "actor": "service-account:cluster-nodes", "origin": "nutanix", **meta,
                       "doc_stated_count": int(m_n.group(1)),
                       "permissions": sorted(set(nodes)), "optional": []})
write("gcp-console-sa", {"cloud": "gcp", "actor": "service-account:nc2-console", "origin": "nutanix", **meta,
                         "doc_stated_count": int(m_c.group(1)),
                         "permissions": sorted(set(console)), "optional": sorted(OPTIONAL & set(console))})


# The procedure pages carry a copy-paste `gcloud iam roles create` command; diff it against the appendix.
def gcloud_perms(name):
    t, _ = page(name)
    cmd = t.split("gcloud iam roles create", 1)[1]
    cmd = cmd.split("--permissions=", 1)[1]
    end = re.search(r"\n\s*\n|\nIn this command|\nWhen using", cmd)
    cmd = cmd[: end.start()] if end else cmd
    return set(p for p in re.split(r"[,\\\s]+", cmd) if re.fullmatch(r"[a-z]+(?:\.[A-Za-z]+){2,}", p))


diffs = {}
for name, appendix in (("gcp-sa-nc2-console", set(console)), ("gcp-sa-cluster-nodes", set(nodes))):
    cmd = gcloud_perms(name)
    diffs[name] = {"in_appendix_not_in_gcloud_command": sorted(appendix - cmd),
                   "in_gcloud_command_not_in_appendix": sorted(cmd - appendix), "gcloud_command_count": len(cmd)}
(OUT / "gcp-doc-consistency.json").write_text(json.dumps(diffs, indent=2) + "\n")
print("ok   gcp-doc-consistency:", {k: (len(v["in_appendix_not_in_gcloud_command"]), len(v["in_gcloud_command_not_in_appendix"])) for k, v in diffs.items()})

# --- Azure: the custom role JSON on the custom-role page -----------------------------------------------
text, meta = page("azure-custom-role")
blob = text[text.index("{"):]
depth, end = 0, 0
for i, ch in enumerate(blob):
    depth += ch == "{"; depth -= ch == "}"
    if depth == 0:
        end = i + 1; break
role = json.loads(blob[:end])["properties"]["permissions"][0]
write("azure-nc2-app", {"cloud": "azure", "actor": "app-registration:nc2", "origin": "nutanix", **meta,
                        "actions": role["actions"], "notActions": role["notActions"],
                        "dataActions": sorted(set(role["dataActions"])), "notDataActions": role["notDataActions"]})

# --- AWS: the doc names managed policies, not actions --------------------------------------------------
text, meta = page("aws-requirements")
assert "IAMFullAccess" in text and "AWSCloudFormationFullAccess" in text and "CreateRole" in text
write("aws-onboarding-user-doc", {"cloud": "aws", "actor": "onboarding-user", "origin": "nutanix", **meta,
                                  "statement": "sign in with a user role that has the IAMFullAccess and AWSCloudFormationFullAccess permissions; must have CreateRole access",
                                  "managed_policies": ["IAMFullAccess", "AWSCloudFormationFullAccess"],
                                  "roles_created": ["Nutanix-Clusters-High-Nc2-Cluster-Role-Prod", "Nutanix-Clusters-High-Nc2-Orchestrator-Role-Prod"],
                                  "permissions": []})
sys.exit(0)
