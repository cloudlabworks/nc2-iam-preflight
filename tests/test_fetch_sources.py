"""tools/pending-replies.mjs: a reply id read from the DevTools socket only reaches a callback the script registered.
Runs the module under node; skipped where node is not installed."""
import shutil, subprocess, unittest
from pathlib import Path

MODULE = (Path(__file__).resolve().parent.parent / "tools" / "pending-replies.mjs").as_uri()

SCRIPT = """
import assert from "node:assert/strict";
const { createPending } = await import(process.argv[1]);
const p = createPending(); const got = [];
p.add(1, (m) => got.push(m));
assert.equal(p.settle({ id: 1, result: "ok" }), true);
assert.deepEqual(got, [{ id: 1, result: "ok" }]);
assert.equal(p.settle({ id: 1, result: "again" }), false);
for (const id of [999, "__proto__", "constructor", "toString", "hasOwnProperty", undefined, null])
  assert.equal(p.settle({ id, method: "Page.loadEventFired" }), false);
assert.equal(p.settle({ method: "Network.requestWillBeSent" }), false);
assert.equal(p.settle(null), false);
assert.equal(got.length, 1); assert.equal(p.size, 0);
console.log("PASS");
"""


@unittest.skipUnless(shutil.which("node"), "node not installed")
class PendingReplies(unittest.TestCase):
    def test_unknown_and_prototype_ids_are_ignored(self):
        r = subprocess.run(["node", "--input-type=module", "-e", SCRIPT, MODULE], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("PASS", r.stdout)


if __name__ == "__main__":
    unittest.main()
