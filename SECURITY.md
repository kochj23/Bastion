# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.2.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Email: kochj23 (via GitHub)
3. Include: description, steps to reproduce, potential impact

We aim to respond within 48 hours and provide a fix within 7 days for critical issues.

## Responsible Use

Bastion is a penetration testing tool designed for **authorized security testing only**. Users must:

- Have written authorization before testing any network or system
- Only test systems you own or have explicit permission to test
- Follow all applicable laws and regulations
- Report discovered vulnerabilities responsibly to affected parties

**Unauthorized use of penetration testing tools is illegal.** The developers are not responsible for misuse.

## Security Features

- **Ethical Safeguards**: Built-in authorization checks and scope limits
- **Keychain Storage**: API keys stored in macOS Keychain
- **Audit Logging**: All scan activities logged for accountability
- **Scope Enforcement**: Tests limited to defined target ranges
- **No Telemetry**: Zero analytics or data collection

## Best Practices

- Never hardcode credentials or API keys
- Report suspicious behavior immediately
- Keep dependencies updated
- Review all code changes for security implications
