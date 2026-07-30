# Saarthi AI VAPT Product Scope

## Mission

Saarthi AI is an offensive-security assistant and assessment agent for
authorized Vulnerability Assessment and Penetration Testing engagements.

## Supported Inputs

Saarthi will accept:

- Web application URLs
- API base URLs
- OpenAPI and Postman specifications
- Individual IP addresses
- Approved CIDR ranges
- Android APK files
- iOS IPA files

## Assessment Workflow

1. Receive the target and engagement configuration.
2. Confirm authorization and scope.
3. Classify the asset type.
4. Create an assessment plan.
5. Request approval for active or intrusive actions.
6. Execute approved security tools through controlled wrappers.
7. Parse and preserve tool output.
8. Distinguish observations from suspected weaknesses.
9. Validate findings using evidence.
10. Generate a professional VAPT report.

## Assessment Outputs

Saarthi should produce:

- Assessment plan
- Asset inventory
- Attack-surface summary
- Tool execution records
- Supporting evidence
- Confirmed findings
- Rejected false positives
- Risk ratings
- Remediation recommendations
- Executive and technical reports

## Execution Principles

- Explicit authorization is required.
- Scope exclusions must always be enforced.
- Active testing requires engagement-level approval.
- Intrusive testing requires explicit approval.
- Destructive testing is disabled by default.
- Commands must run through validated tool wrappers.
- Tool results must never be fabricated.
- Scanner output alone does not prove a vulnerability.
- Confirmed findings must reference reproducible evidence.

## MVP Priority

1. Web applications
2. APIs
3. Individual IP addresses and small CIDR ranges
4. Android applications
5. iOS applications
6. Active Directory and cloud environments
