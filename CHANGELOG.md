# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- README: PyPI version, Python versions and CI badges.

## [0.1.0] - 2026-11-03

First PyPI release. Status unchanged: covered by offline tests against recorded response shapes, not yet run against live clouds.

### Added

- `pip install nc2-iam-preflight` installs the `nc2-iam-preflight` command. Standard library only.

### Changed

- The code is now a package (`nc2_iam_preflight/`) with the permission lists inside it, so they ship in the wheel. From a git clone without installing, run `python3 -m nc2_iam_preflight`.

[Unreleased]: https://github.com/cloudlabworks/nc2-iam-preflight/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cloudlabworks/nc2-iam-preflight/releases/tag/v0.1.0
