# Security policy

hatch-pep770 writes a CycloneDX SBOM into wheels, from a hatchling build hook or from a command that rewrites a wheel
another build backend built, and renders or validates that SBOM. This policy says how to report a security problem and
how we decide whether a report is one.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use
[GitHub's private vulnerability reporting](https://github.com/tox-dev/hatch-pep770/security/advisories/new). If neither
works for you, email [gaborjbernat@gmail.com](mailto:gaborjbernat@gmail.com).

Include what the attacker controls and what they gain, the steps or a proof of concept, and the versions and platform
you tested. Write the report yourself; unreviewed tool or model output takes longer to triage.

## What to expect

Volunteers maintain hatch-pep770, with no on-call rotation. We aim to acknowledge a report within **5 working days** and
assess it within **15 working days**. Fixes are developed in a private fork attached to the draft advisory, ship in a
new release, and the advisory, with a CVE requested through GitHub, goes out with that release. The default embargo is
**90 days** from the report; we agree any change with the reporter. We credit reporters in the advisory under the name
they choose, or not at all. There is no bug bounty.

## Supported versions

Only the latest release receives fixes. Confirm the problem reproduces on it before reporting.

## Vulnerability or bug

A report is a vulnerability when an attacker who controls only an input that the [threat model](THREAT_MODEL.md) lists
as untrusted breaks a guarantee hatch-pep770 makes. A report that first needs control of something the threat model
trusts, such as the project source, its `pyproject.toml` or the build environment, is a bug: we fix it in the open and
publish no advisory. Classify by who supplies the dangerous input, not by how bad the outcome sounds.

**In scope**

- A bundled wheel, or an SBOM given to `hatch-pep770 spdx` or `validate`, that makes hatch-pep770 write outside its
  output file or the wheel it rewrites, or run code.
- An SBOM that misstates what a wheel holds in a way its inputs cannot explain, such as a wrong hash.

**Out of scope**

- Anything hatchling's own build trusts.
- Vulnerabilities in the packages an SBOM lists; report those to their projects.

If you cannot tell which side a finding falls on, report it privately and we will decide.
