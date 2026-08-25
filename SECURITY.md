# Security Policy

aivyx-confine is a library, not a standalone application — it provides
OS-level process confinement (Landlock + seccomp-bpf) that both
`aivyx` and `aivyx-coder` depend on for their own default-on process
confinement. A confinement bypass here is a real, high-value finding
even though this repo has no application-level attack surface of its
own — it's the primitive two other products' own security boundaries
rest on.

This is not a bug bounty program.

## Reporting a vulnerability

Email **jccorbett67@gmail.com** with details. This repo is currently
private, so GitHub Security Advisories' private vulnerability
reporting isn't available yet (GitHub only offers it on public
repositories) — it will be added as a second channel if this repo
goes public. We aim to resolve or provide a remediation plan for a
confirmed vulnerability within 90 days of the report, or coordinate a
later disclosure date directly with the reporter if a fix genuinely
needs longer. Credit is offered in release notes at the reporter's
preference.
