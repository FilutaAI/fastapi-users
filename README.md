# filuta_fastapi_users

<!--TOC-->

- [filuta_fastapi_users](#filuta_fastapi_users)
  - [Differences from original fastapi-users](#differences-from-original-fastapi-users)
  - [Development](#development)
    - [Environment Setup](#environment-setup)
    - [Running tests and checks](#running-tests-and-checks)

<!--TOC-->


This repo contains package **filuta_fastapi_users**.

Filuta fork of fastapi-users to include OTP natively

Work in progress, stay tuned for the news!

Feel free to use [mermaid](https://mermaid.js.org/) for diagramming and charting!

```mermaid
flowchart LR
    A --> B
```
---

## Differences from original fastapi-users
- **Native OTP (One-Time Password) Support**: Built-in support for OTP flows (email-based).
- **Python 3.14+ Only**: This fork exclusively targets and supports Python 3.14 and newer.
- **Enhanced Scopes**: Includes additional user roles like `poweruser` and fine-grained `authorized` checks.

## Development

### Environment Setup

To create or update the environment:
```bash
make venv
```
This uses `mamba` (or `conda`) to create the environment as defined in `environment.yml`.

### Running tests and checks
We use `tox` for all automation tasks.

To run everything (tests, pre-commit, security-check, docs):
```bash
tox
```

To run only specific environments:
```bash
# Run pre-commit hooks
tox -e pre-commit

# Run security checks
tox -e security-check

# Run tests (using install env)
tox -e install
```
