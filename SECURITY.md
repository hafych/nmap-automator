# Security policy

## Supported version

Security fixes are applied to the current `main` branch. Use the latest release or commit and
keep Python, Nmap, the container base image, and Python dependencies updated.

## Reporting a vulnerability

Please report vulnerabilities privately through the repository's GitHub Security Advisories
page. Include the affected version, impact, reproduction steps, and any proposed mitigation.
Do not open a public issue containing working exploit details or credentials.

If private reporting is unavailable, open a minimal issue asking the maintainer for a secure
contact channel without disclosing the vulnerability.

## Deployment baseline

- Keep `API_AUTH_REQUIRED=true` and use a randomly generated token.
- For multi-token deploys, set `LEGACY_RESULTS_SHARED=false` so pre-ownership result files
  are not visible to every operator.
- Bind to loopback unless a trusted reverse proxy or firewall restricts access.
- Never publish `.env`, Fernet keys, API tokens, Telegram credentials, decrypted results, or
  assessment artifacts.
- Keep target-size, concurrency, rate, and timeout limits appropriate for the authorized
  environment.
- Run the default non-root container and add network privileges only when an authorized scan
  profile requires them.
- Treat generated recon commands as operator-reviewed suggestions, not autonomous actions.
- Back up the Fernet key separately from encrypted results and rotate API credentials after
  suspected exposure.
