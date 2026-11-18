# Security Policy

## Supported Versions

OpenABE has no binary releases: security fixes land on `master`. Keys generated with 1.x are not
compatible with 2.x, because of the RELIC 0.7.0 upgrade.

| Version          | Supported          |
| ---------------- | ------------------ |
| 2.0.x (`master`) | :white_check_mark: |
| 1.0.x            | :x:                |

The upstream project, [zeutro/openabe](https://github.com/zeutro/openabe), is maintained separately.
If a flaw affects it too, please say so in your report so we can coordinate.

## Reporting a Vulnerability

**Please do not open a public issue, pull request or discussion for a security problem.**

Report it privately through
[GitHub Security Advisories](https://github.com/Claudiocli/openabe/security/advisories/new)
("Report a vulnerability" in the Security tab). Only the maintainers can see the report.

Please include the affected component (library, CLI, Python bindings), the commit you tested
(`git rev-parse --short HEAD`), your OS and compiler versions, steps to reproduce, and what an
attacker gains. Use throwaway test keys: **never send real keys or master secret parameters**.

What to expect, as good-faith targets from a volunteer project:

- an acknowledgement within 7 days;
- an assessment of validity and severity within 14 days;
- updates in the advisory thread as the work progresses.

If the report is accepted, we agree a disclosure date with you, fix the issue on `master`, and credit
you in the published advisory unless you prefer to stay anonymous. If we cannot fix a confirmed issue
within 90 days, we will tell you and discuss publishing the details anyway, so that users can protect
themselves. If the report is declined, we explain why in the advisory and leave it open for you to
respond.

Out of scope: vulnerabilities in dependencies (OpenSSL, RELIC, GMP, GoogleTest), which belong to
their own maintainers; attacks that assume the attacker already holds the master secret parameters or
a key satisfying the policy; and the documented properties listed in
[Known Limitations](https://github.com/Claudiocli/openabe/wiki/Known-Limitations), such as the
~100-bit security level of BN-254, the absence of key revocation and the lack of post-quantum
security. A concrete attack that performs better than the published bounds **is** in scope, so please
report it.

There is no bug bounty for this project.
