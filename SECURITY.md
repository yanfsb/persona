# Security policy

Persona is a release candidate, not a sandbox or security boundary. It only guards explicitly managed, supported paths; direct native binaries and hostile same-user processes can bypass it. Do not rely on it as the sole protection for production credentials or publishing.

## Reporting a vulnerability

Do not report suspected vulnerabilities in a public issue or pull request. Use GitHub's **Report a vulnerability** control on this repository's Security/Advisories page to submit a private report. This channel must be enabled by the repository maintainer before public launch. If the private reporting control is unavailable, do not post exploit details publicly; contact the maintainer through an already-known private channel, if one exists.

Include affected Persona version/commit, platform, impact and a minimal reproduction where safe. Use synthetic identities and redact paths, repository names, tokens, private keys, account identifiers and other secrets. Never attach credential-store files or unredacted logs.

## Response expectations and scope

The project is maintained by one maintainer. Reports are reviewed best-effort; there is no response or remediation SLA and no guaranteed supported-version window. The current candidate is the only release under consideration; support duration for future releases will be stated in their notes. Do not publicly disclose a vulnerability before coordinating with the maintainer.

The GitHub private-reporting channel and its notifications must be enabled and verified before the repository is made public. An existing `SECURITY.md` file alone does not enable or monitor that channel.
