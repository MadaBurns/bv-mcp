# Anthropic OSS Scanner enrollment

This directory holds the two files Anthropic's opt-in
[OSS Scanner](https://red.anthropic.com/oss-scanner/) reads from the repository:

- `Dockerfile` — builds the project with network access, after which the
  scanner's agents audit the image **offline**. Everything the tests need must
  already be in the image. Verify locally with
  `docker build -f .oss-scanner/Dockerfile -t bv-mcp-oss-scanner .` and then
  `docker run --rm --network none bv-mcp-oss-scanner node scripts/vitest-filter-workerd.mjs run`.
- `threat_model.md` — where untrusted input enters, what matters, the severity
  rubric, and the deliberate behaviours the scanner should not report. Edit it
  between scans to steer the reports; no PR upstream is needed for that.

The enrollment itself is a `project.yaml` in
[anthropics/oss-scanner](https://github.com/anthropics/oss-scanner) under
`projects/<name>/`, opened as a PR by a core maintainer (Anthropic verifies
maintainer status and acceptance is case by case). The config that points at
this directory:

```yaml
repo: https://github.com/MadaBurns/bv-mcp#main
primary_contact: security@blackveilsecurity.com
homepage: https://blackveilsecurity.com
disabled: false
dockerfile: .oss-scanner/Dockerfile
threat_model: .oss-scanner/threat_model.md
```

Reports arrive by email, unreviewed by a human, with no disclosure clock
attached. Treat them like any other private vulnerability report under
`SECURITY.md`. When a report leads to a fix, credit it in the commit message:

> Discovered by Anthropic's OSS Scanner, as vulnerability `ANT-2026-XXXXXXXX`.

To pause reports, PR `disabled: true` into the upstream `project.yaml`; to
withdraw, PR the deletion of the `projects/<name>/` directory.
