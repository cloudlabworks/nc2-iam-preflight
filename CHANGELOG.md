# Changelog

## [0.1.0]

First PyPI release.

- `pip install nc2-iam-preflight` installs the `nc2-iam-preflight` command. Standard library only.
- The code is now a package (`nc2_iam_preflight/`) with the permission lists inside it, so they ship in the wheel.
  From a git clone without installing, run `python3 -m nc2_iam_preflight`.
- Status unchanged: covered by offline tests against recorded response shapes, not yet run against live clouds.
