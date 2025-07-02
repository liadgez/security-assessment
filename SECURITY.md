# Security Policy

## Supported Versions

This project is actively maintained and security updates are provided for the latest version.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please follow these steps:

1. **Do not open a public issue** for security vulnerabilities
2. Send details to the repository owner via private communication
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fix (if available)

## Security Best Practices

When contributing to this project:

- Never commit sensitive information (API keys, passwords, tokens)
- Use environment variables for configuration
- Keep dependencies up to date
- Follow secure coding practices
- Use the provided `.env.example` as a template

## Automated Security

This repository includes:

- Automated vulnerability scanning via GitHub Actions
- Dependency security checks
- Secret detection in commits
- Regular security audits

## Environment Configuration

1. Copy `.env.example` to `.env`
2. Fill in your actual configuration values
3. Never commit `.env` files to the repository
4. Use strong, unique values for secrets and API keys

## Contact

For security concerns, please contact the repository maintainers.
