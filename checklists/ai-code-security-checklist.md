# AI Code Security Checklist for Organizations

## Overview

This checklist helps organizations implement security controls for AI-generated code. Use this as a foundation for your AI code security policy.

---

## Executive Summary Checklist

```
┌─────────────────────────────────────────────────────────────────┐
│              ORGANIZATIONAL AI CODE SECURITY                    │
├─────────────────────────────────────────────────────────────────┤
│  □ Policy defined for AI code generation tools                 │
│  □ Approved AI tools catalog published                         │
│  □ Mandatory code review requirements in place                 │
│  □ SAST/DAST integrated in CI/CD pipeline                      │
│  □ Secret scanning blocking commits                            │
│  □ Dependency scanning active                                  │
│  □ Developer training completed                                │
│  □ Incident response plan includes AI code                     │
│  □ Metrics tracking AI code vulnerabilities                    │
│  □ Regular security assessments scheduled                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1. Policy & Governance

### 1.1 AI Tool Usage Policy
- [ ] Define which AI code generation tools are approved
- [ ] Publish approved tool catalog (block shadow AI at proxy)
- [ ] Establish when AI tools can/cannot be used
- [ ] Define data that cannot be shared with AI tools
- [ ] Require acceptance of AI tool terms of service

**Policy Template:**
```markdown
## AI Code Generation Policy

### Approved Tools
- GitHub Copilot (Enterprise license required)
- Amazon CodeWhisperer (with security training)

### Prohibited Uses
- Generating code with proprietary algorithms
- Sharing customer data with AI tools
- Using AI for security-critical code without review

### Requirements
- All AI-generated code must be flagged in commits
- Minimum 2 human reviewers for AI code
- SAST scan must pass before merge
```

### 1.2 Code Attribution
- [ ] Require tagging AI-generated code in commits
- [ ] Track percentage of AI-generated code
- [ ] Maintain audit trail for compliance

**Git Commit Convention:**
```
feat: add user authentication [AI-ASSISTED]

- Generated initial structure with Copilot
- Human reviewed and modified validation logic
- Security scan passed

AI-Tool: GitHub Copilot
Reviewer: @security-team
```

---

## 2. Development Process Controls

### 2.1 Code Review Requirements
- [ ] Minimum 2 human reviewers for AI-generated code
- [ ] At least 1 reviewer with security training
- [ ] Dedicated review checklist for AI code
- [ ] Block merge without review approval

**Research shows:** Developers using AI are more confident but produce less secure code. Human review catches what AI misses.

### 2.2 Review Scope
- [ ] Review covers security-critical sections
- [ ] Input validation reviewed in detail
- [ ] Authentication/authorization logic verified
- [ ] Error handling checked for information leakage
- [ ] Dependencies verified (anti-slopsquatting)

### 2.3 Iteration Limits
- [ ] Maximum 3 consecutive AI iterations before human review
- [ ] Reset iteration count after human intervention
- [ ] Document significant AI-assisted refactoring

**Research shows:** 37.6% increase in critical vulnerabilities after 5 AI iterations without human review.

---

## 3. CI/CD Security Controls

### 3.1 Static Application Security Testing (SAST)
- [ ] SAST tool integrated in pipeline
- [ ] Pipeline fails on critical/high vulnerabilities
- [ ] Custom rules for AI-common vulnerabilities
- [ ] Regular rule updates

**Recommended Tools:**
- Semgrep (customizable, fast)
- Snyk Code (AI-trained detection)
- CodeQL (deep analysis)

**CI/CD Integration:**
```yaml
# GitHub Actions example
security-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/owasp-top-ten
    - name: Fail on findings
      if: steps.semgrep.outputs.findings != '0'
      run: exit 1
```

### 3.2 Secret Scanning
- [ ] Pre-commit hooks block secrets
- [ ] CI/CD scans for leaked credentials
- [ ] Historical git scanning enabled
- [ ] Alerts sent to security team

**AI Risk:** AI commonly suggests hardcoded credentials as examples.

### 3.3 Dependency Scanning
- [ ] SCA tool integrated in pipeline
- [ ] Block merge on critical vulnerabilities
- [ ] Verify packages exist before install
- [ ] Lock files required and validated

**Anti-Slopsquatting Check:**
```bash
# Add to CI pipeline
#!/bin/bash
for pkg in $(jq -r '.dependencies | keys[]' package.json); do
  if ! npm view "$pkg" > /dev/null 2>&1; then
    echo "ERROR: Package '$pkg' does not exist!"
    exit 1
  fi
done
```

### 3.4 Dynamic Application Security Testing (DAST)
- [ ] DAST integrated for web applications
- [ ] Regular automated scans scheduled
- [ ] API security testing included
- [ ] Results tracked and remediated

---

## 4. Developer Training

### 4.1 Required Training Topics
- [ ] AI code security risks awareness
- [ ] Secure prompting techniques
- [ ] Common AI-generated vulnerabilities
- [ ] Code review for AI output
- [ ] Using security tools effectively

### 4.2 Training Schedule
- [ ] Initial training for all developers
- [ ] Refresher training annually
- [ ] Updates when new AI tools adopted
- [ ] Incident-triggered training as needed

### 4.3 Secure Prompting Guidelines
Teach developers these techniques:

| Technique | Example |
|-----------|---------|
| Explicit security | "Write secure code that validates all input" |
| CWE-specific | "Prevent SQL injection (CWE-89)" |
| Constraint | "Do not use eval(), exec(), or os.system()" |
| Defense layers | "Include input validation, output encoding, and error handling" |
| Review request | "Review this code for security issues and suggest improvements" |

---

## 5. Metrics & Monitoring

### 5.1 Key Metrics to Track
- [ ] Percentage of code that is AI-generated
- [ ] Vulnerability rate in AI vs human code
- [ ] Time to remediate AI code vulnerabilities
- [ ] Number of blocked commits (secrets, vulns)
- [ ] Code review coverage for AI code

**Dashboard Example:**
| Metric | Target | Current |
|--------|--------|---------|
| AI code with review | 100% | 98% |
| Critical vulns in AI code | 0 | 2 |
| Mean time to remediate | <24h | 18h |
| Secret commits blocked | 100% | 100% |

### 5.2 Alerting
- [ ] Alert on critical vulnerability in AI code
- [ ] Alert on blocked secret commit
- [ ] Alert on dependency vulnerability
- [ ] Weekly summary to security team

### 5.3 Reporting
- [ ] Monthly security posture report
- [ ] AI code vulnerability trends
- [ ] Compliance status for AI policies
- [ ] Training completion rates

---

## 6. Incident Response

### 6.1 AI Code Incident Playbook
- [ ] Include AI code scenarios in IR plan
- [ ] Define escalation for AI-introduced vulns
- [ ] Establish rollback procedures
- [ ] Document lessons learned process

**Incident Categories:**
| Type | Response |
|------|----------|
| Leaked secret in AI code | Rotate immediately, audit access |
| Exploited vulnerability | Patch, investigate impact |
| Supply chain (slopsquatting) | Remove package, scan for malware |
| Data exfiltration via AI tool | Revoke access, assess exposure |

### 6.2 Post-Incident Review
- [ ] Identify if AI contributed to incident
- [ ] Review prompts used (if available)
- [ ] Update training based on findings
- [ ] Improve detection for similar issues

---

## 7. Vendor & Tool Assessment

### 7.1 AI Tool Evaluation Criteria
Before adopting an AI coding tool, evaluate:

- [ ] Data handling and privacy policy
- [ ] Code/prompt retention policies
- [ ] Security certifications (SOC 2, etc.)
- [ ] Incident history and disclosure practices
- [ ] Enterprise security features
- [ ] Integration with security tools

### 7.2 Ongoing Vendor Management
- [ ] Monitor vendor security advisories
- [ ] Track CVEs affecting AI tools
- [ ] Review vendor security updates
- [ ] Annual vendor security assessment

**Recent AI Tool CVEs (2025):**
- GitHub Copilot: CVE-2025-64660, CVE-2025-53773
- Cursor: CVE-2025-49150, CVE-2025-54130, CVE-2025-61590
- OpenAI Codex CLI: CVE-2025-61260

---

## 8. Compliance Considerations

### 8.1 Regulatory Alignment
- [ ] AI code policy aligns with data protection laws
- [ ] GDPR considerations for AI tool data sharing
- [ ] Industry-specific requirements addressed
- [ ] Audit trail maintained for compliance

### 8.2 Standards Mapping
| Standard | AI Code Considerations |
|----------|----------------------|
| SOC 2 | Code review controls, vulnerability management |
| ISO 27001 | Secure development policy, supplier management |
| PCI DSS | Secure coding, code review, vulnerability scanning |
| HIPAA | Data handling, access controls, audit trails |

### 8.3 AI-Specific Regulations
- [ ] Monitor EU AI Act requirements
- [ ] Track emerging AI governance frameworks
- [ ] Document AI use for regulatory inquiries

---

## 9. Implementation Roadmap

### Phase 1: Foundation (Month 1-2)
- [ ] Draft AI code security policy
- [ ] Inventory current AI tool usage
- [ ] Implement basic SAST in CI/CD
- [ ] Enable secret scanning

### Phase 2: Enhancement (Month 3-4)
- [ ] Roll out developer training
- [ ] Add dependency scanning
- [ ] Implement code attribution
- [ ] Establish metrics baseline

### Phase 3: Maturity (Month 5-6)
- [ ] Full CI/CD security integration
- [ ] Automated compliance reporting
- [ ] Incident response testing
- [ ] Continuous improvement process

---

## 10. Quick Reference: Policy Requirements

### Minimum Viable Policy
```
1. All AI-generated code requires human review
2. SAST scan must pass before merge
3. No secrets in code (blocked by CI)
4. Dependencies must be verified
5. Security training required annually
```

### Recommended Additions
```
6. Tag AI-generated code in commits
7. Maximum 3 AI iterations before review
8. Security reviewer for critical paths
9. DAST for web applications
10. Monthly security metrics review
```

---

## References

- [AI-Generated Code Security Checklist: 7 Policies for CISOs](https://www.opsmx.com/blog/ai-generated-code-security-checklist-7-policies-every-ciso-needs/)
- [Generative AI Security Policy Templates](https://www.sentinelone.com/cybersecurity-101/data-and-ai/generative-ai-security-policy/)
- [Governance and Security for AI Agents](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ai-agents/governance-security-across-organization)
- [AI Compliance in 2026](https://www.wiz.io/academy/ai-compliance)
