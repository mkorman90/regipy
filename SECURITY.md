# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 6.x.x   | ✅         |
| < 6.0   | ❌         |

## Reporting a Vulnerability

Please report vulnerabilities via [GitHub Security Advisories](https://github.com/mkorman90/regipy/security/advisories/new).

## Supply Chain Security

This project implements several supply chain security measures:

- **SBOM**: Each release includes a [CycloneDX](https://cyclonedx.org/) Software Bill of Materials (`sbom.json`, `sbom.xml`) attached to the GitHub release
- **Dependency Scanning**: [pip-audit](https://github.com/pypa/pip-audit) runs on every CI build to detect known vulnerabilities
- **Dependabot**: Automated dependency updates are enabled for both Python packages and GitHub Actions
- **Trusted Publishing**: PyPI releases use [trusted publishing](https://docs.pypi.org/trusted-publishers/) via GitHub Actions OIDC
