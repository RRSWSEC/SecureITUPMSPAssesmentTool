# Security Policy

## Authorized Use

This project is for owned labs, internal environments, and explicitly authorized client systems. Do not use it against systems where you do not have written permission.

The collector and platform must not be extended with exploit payloads, credential theft, brute forcing, persistence, destructive actions, or unauthorized scanning.

## Reporting Security Issues

Please report suspected vulnerabilities privately to the project maintainers before public disclosure. Include:

- Affected component and version or commit.
- Reproduction steps.
- Impact and likely scope.
- Any safe proof-of-concept data needed to validate the issue.

Do not include secrets, client data, or unauthorized third-party evidence in reports.

## Evidence Handling

Collector output should preserve operational evidence without collecting passwords, tokens, private keys, browser data, cookies, or other secrets. If sensitive data is accidentally imported, remove the affected database and files from the environment and rotate any exposed credentials.

## Default Safety Controls

- Public IP scanning is disabled by default.
- Network discovery requires explicit authorization flags.
- CIDR scopes are validated and broad scopes are rejected.
- Import uploads are size-limited and schema-validated.
- Important actions are written to the audit log.
