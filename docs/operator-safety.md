# Operator Safety

## Scope Verification Checklist

- Confirm the client name and assessment purpose.
- Record authorized CIDRs and domains before collection.
- Confirm the requested-by contact and operator.
- Confirm the assessment start time and operator notes.
- Run dry-run mode before any network discovery.

## Client Authorization Checklist

- Written authorization covers the target networks and collection window.
- Public IP testing is explicitly authorized before `--allow-public-scope` is used.
- Contacts understand that results are risk indicators and compliance-support evidence, not certification.
- Data handling expectations are agreed before import or report delivery.

## Safe Scanning Defaults

- Default collector behavior is local inventory/import only.
- Ping sweep and TCP connect checks require `--authorized`, `--scope`, and explicit scan flags.
- TCP checks are limited to a small allowlisted port set.
- Rate limiting is enabled by default.
- Broad networks and default routes are rejected.

## What Not To Scan

- Third-party networks without written authorization.
- Personal devices outside the approved scope.
- Public IP addresses unless explicitly approved.
- Cloud tenants, SaaS services, or identity providers without a separate written scope.

## Public IP Restrictions

Public IP ranges are blocked unless `--allow-public-scope` is provided. Treat that flag as a written-authorization checkpoint, not a convenience option.

## Evidence Handling

- Do not collect passwords, tokens, private keys, browser data, cookies, or credential stores.
- Store collector JSON and reports in the approved client evidence location.
- Preserve audit logs for imports, scope changes, report exports, and finding status changes.
- Remove stale local exports after client delivery according to retention policy.

## Cleanup Steps

- Confirm collector output location.
- Delete unneeded local collector JSON files.
- Review imported scope records for accuracy.
- Export final reports from the platform and archive according to client policy.
