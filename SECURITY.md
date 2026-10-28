# Security policy

## Supported versions

Only the latest release of Binary Inspector gets security fixes.

## Reporting a vulnerability

Please don't open a public issue for a security problem. Report it privately through GitHub:
the repository's **Security** tab > **Report a vulnerability**. Include the version, what you
did, what happened, and a file or steps that reproduce it if you can.

You'll get an acknowledgement within 7 days, and a fix or a decision within 30 days for
confirmed issues. Credit is given in the release notes unless you'd rather stay anonymous.

## Scope

In scope above all: anything that makes the inspector execute, load or modify the file it inspects, or a crafted PE file that crashes it, hangs it or exhausts memory despite the parser limits. Also the CLI, the sandbox-report importer and the optional external-tool integration.
