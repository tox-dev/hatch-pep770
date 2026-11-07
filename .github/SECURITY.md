# Security policy

hatch-pep770 is a hatchling build hook that writes a CycloneDX SBOM into wheels, plus a command line tool that renders
that SBOM as SPDX and validates it. This policy says how to report a security problem and how we decide whether a report
is one.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use
[GitHub's private vulnerability reporting](https://github.com/tox-dev/hatch-pep770/security/advisories/new). If you do
not have a GitHub account, email [gaborjbernat@gmail.com](mailto:gaborjbernat@gmail.com).

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

The build hook runs inside a project's own build, with the trust that build already has: the project source, its
`pyproject.toml`, its build requirements and the build environment are trusted. A report that needs control of one of
those is a bug: we fix it in the open and publish no advisory.

**In scope**

- A wheel bundled as a data file, or an SBOM given to `hatch-pep770 spdx` or `validate`, that makes the tool write
  outside its output file or the wheel's `.dist-info/sboms/` directory, or run code.
- An SBOM that misstates what the wheel contains in a way the project's own inputs cannot explain, such as a wrong hash.

**Out of scope**

- Anything hatchling's own build trusts.
- Vulnerabilities in the packages the SBOM lists; report those to their projects.

If you cannot tell which side a finding falls on, report it privately and we will decide.
