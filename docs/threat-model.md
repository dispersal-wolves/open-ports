# Threat model

## Protects against

Inventories local TCP and UDP listeners, records a baseline, and compares later scans. It does not probe remote systems.

## Trust boundaries

- The local operator and operating system are trusted.
- Input files, log lines, repository content, and command output are untrusted.
- Webhook destinations are contacted only when explicitly configured.
- Elevated privileges are never assumed to imply consent for unrelated changes.

## Non-goals

- Exploitation, persistence, credential collection, or access to third-party systems.
- Replacing operating-system security controls or professional incident response.
- Claiming that a clean report proves a host is uncompromised.

## Sensitive data

Generated reports can contain paths, usernames, process names, or network bindings. They are ignored by Git where the tool creates them. Review reports before sharing them.
