# Saarthi Dataset Policy

## Purpose

This policy defines the quality, safety, licensing, and provenance
requirements for Saarthi training and evaluation data.

## Accepted Data

Data may be included when it is:

- Created specifically for the Saarthi project.
- Publicly available under a compatible license.
- Derived from documentation whose license permits the intended use.
- Sanitized and approved internal material.
- Reviewed by a qualified security practitioner.

## Prohibited Data

Do not include:

- Customer names, domains, IP addresses, credentials, or tokens.
- Confidential penetration testing reports without explicit permission.
- Personal data or private communications.
- Unlicensed copied articles, books, courses, or paid content.
- Unverified vulnerability claims.
- Fabricated scan output or exploitation evidence.
- Real production secrets or session identifiers.

## Quality Requirements

Every record must:

- Have a unique identifier.
- Match the current JSON Schema.
- Contain a clear instruction.
- Provide a technically accurate response.
- Separate observations from assumptions.
- Avoid claiming that an action succeeded without evidence.
- Include source and license information.
- Include the required safety metadata.
- Be reviewed before entering the final training dataset.

## Security Requirements

Examples must be written for:

- Authorized security assessments.
- Controlled lab environments.
- Defensive validation.
- Security education and research.
- Secure architecture review.
- Professional security reporting.

Examples should prefer non-destructive validation methods.

## Sanitization

Before accepting internal material:

1. Remove customer and organization names.
2. Replace real domains and IP addresses with reserved examples.
3. Remove credentials, tokens, cookies, and API keys.
4. Remove employee and customer personal data.
5. Remove confidential screenshots and file paths.
6. Confirm that the sanitized example remains technically accurate.

## Reserved Example Values

Use values such as:

- `example.com`
- `api.example.com`
- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`
- `TEST_USER`
- `REDACTED_TOKEN`

## Review States

- `reviewed: false` means the record cannot enter training.
- `reviewed: true` means a human reviewer approved the record.
- Evaluation records should be reviewed independently where possible.

## Data Splitting

Records describing the same scenario must not appear across multiple
splits.

Recommended initial split:

- Training: 80 percent
- Validation: 10 percent
- Test: 10 percent

The final test set must remain separate from training and prompt
development.

## Versioning

Dataset changes must be committed to Git with clear messages.

Breaking schema changes require a new schema version.
