# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ZkPatternMatcher, please report it privately.

**Email:** teycir@pxdmail.net

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response Time:**
- Initial response: Within 48 hours
- Status update: Within 7 days
- Fix timeline: Depends on severity

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Considerations

ZkPatternMatcher includes built-in protections against:
- **ReDoS attacks:** Regex complexity limited to 200 characters
- **YAML bombs:** File size limited to 1MB, line count limited to 10,000
- **Memory exhaustion:** File size limited to 10MB, match count limited to 10,000
- **Resource exhaustion:** Pattern count limited to 1,000

These limits are hardcoded and cannot be bypassed.

## Disclosure Policy

- Security issues will be disclosed after a fix is available
- Credit will be given to reporters (unless anonymity is requested)
- CVEs will be requested for critical vulnerabilities
