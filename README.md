# AI Code Security

> **The definitive resource on security vulnerabilities in AI-generated code.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Last Updated](https://img.shields.io/badge/Last%20Updated-January%202026-blue.svg)]()

---

## The Problem

AI code generation tools (GitHub Copilot, ChatGPT, Claude, etc.) are revolutionizing software development. But there's a critical issue:

> **35-48% of AI-generated code contains security vulnerabilities.**

Even more concerning: developers using AI assistants are **more confident** about their code's security while producing **less secure** output.

---

## Key Statistics

| Finding | Source |
|---------|--------|
| **35.8%** of Copilot code has security weaknesses | ACM TOSEM 2025 |
| **45%** of AI code fails security tests | Veracode 2025 |
| **40%** of Copilot programs exploitable | NYU Study |
| **20%** of AI-suggested packages don't exist | Slopsquatting Research |
| **24+ CVEs** in AI coding tools in 2025 alone | IDEsaster Research |
| **37.6%** increase in vulns after 5 AI iterations | Academic Study 2025 |

---

## What's In This Repository

### 📚 Research

| Document | Description |
|----------|-------------|
| [RESEARCH.md](./RESEARCH.md) | Comprehensive findings with all sources |
| [research/ai-generated-vulnerabilities.md](./research/ai-generated-vulnerabilities.md) | Deep dive into specific vulnerability types |
| [research/real-world-incidents.md](./research/real-world-incidents.md) | Documented CVEs and security incidents |
| [research/academic-studies.md](./research/academic-studies.md) | Peer-reviewed research summary |

### 🛠️ Tools

| Document | Description |
|----------|-------------|
| [tools/security-tools-comparison.md](./tools/security-tools-comparison.md) | SAST, DAST, SCA tool comparison |

### ✅ Checklists

| Document | Description |
|----------|-------------|
| [checklists/code-review-checklist.md](./checklists/code-review-checklist.md) | Review checklist for AI-generated code |
| [checklists/ai-code-security-checklist.md](./checklists/ai-code-security-checklist.md) | Organizational policy checklist |

### 🔍 Examples

| Document | Description |
|----------|-------------|
| [examples/common-vulnerabilities.md](./examples/common-vulnerabilities.md) | Vulnerable patterns with secure alternatives |

---

## Quick Start

### For Developers

1. **Read the vulnerability examples** in [examples/common-vulnerabilities.md](./examples/common-vulnerabilities.md)
2. **Use the code review checklist** from [checklists/code-review-checklist.md](./checklists/code-review-checklist.md)
3. **Verify all AI-suggested packages** before installing (slopsquatting prevention)
4. **Never trust AI output** without security review

### For Security Teams

1. **Review the comprehensive research** in [RESEARCH.md](./RESEARCH.md)
2. **Implement the organizational checklist** from [checklists/ai-code-security-checklist.md](./checklists/ai-code-security-checklist.md)
3. **Select appropriate tools** using [tools/security-tools-comparison.md](./tools/security-tools-comparison.md)
4. **Train developers** on AI code security risks

### For CISOs

1. **Understand the risk landscape** from research documents
2. **Implement policy controls** using organizational checklist
3. **Require SAST/DAST** in CI/CD pipelines
4. **Track metrics** on AI-generated code vulnerabilities

---

## Top 5 AI Code Vulnerabilities

| Rank | CWE | Vulnerability | Prevalence |
|------|-----|---------------|------------|
| 1 | CWE-89 | SQL Injection | ~25% of DB code |
| 2 | CWE-78 | OS Command Injection | Common in scripts |
| 3 | CWE-79 | Cross-Site Scripting (XSS) | 20-30% of web code |
| 4 | CWE-798 | Hard-coded Credentials | 10-15% |
| 5 | CWE-327 | Insecure Cryptography | 25-40% of crypto code |

---

## Why AI Generates Insecure Code

1. **Training data contains vulnerable code** - Legacy patterns, Stack Overflow answers
2. **Optimized for functionality, not security** - "Working" trumps "secure"
3. **Missing context** - Can't see full application architecture
4. **No explicit security prompting** - Default prompts don't mention security
5. **Confidence paradox** - Developers trust AI too much

---

## 2025 CVEs in AI Coding Tools

### IDEsaster Disclosure (December 2025)
- **24+ CVEs** across GitHub Copilot, Cursor, Windsurf, and others
- Attack types: Prompt injection, data exfiltration, code execution
- See [research/real-world-incidents.md](./research/real-world-incidents.md) for details

### Key CVEs
| CVE | Tool | Impact |
|-----|------|--------|
| CVE-2025-53773 | GitHub Copilot | Sensitive file exfiltration |
| CVE-2025-64660 | GitHub Copilot | Config override for RCE |
| CVE-2025-61590 | Cursor | Code execution via prompt injection |
| CVE-2025-61260 | OpenAI Codex CLI | Command injection |

---

## Recommended Security Stack

### Minimum (Free)
```
SAST: Semgrep + Bandit (Python)
Secrets: GitHub Secret Scanning + TruffleHog
SCA: Dependabot
DAST: OWASP ZAP
```

### Enterprise
```
SAST: Snyk Code or Checkmarx
Secrets: GitGuardian Enterprise
SCA: Snyk Open Source
DAST: Burp Enterprise
Custom: Semgrep rules for AI patterns
```

---

## Key Mitigation Strategies

### Prompting
- Use **Recursive Criticism and Improvement (RCI)** technique
- Include **CWE-specific** security requirements
- Always add "validate all input" to prompts

### Process
- **2+ human reviewers** for all AI-generated code
- **Maximum 3 AI iterations** before human review
- **Tag AI-generated code** in commits

### Technical
- **SAST in CI/CD** - Block on critical vulnerabilities
- **Secret scanning** - Block commits with credentials
- **Dependency verification** - Validate packages exist

---

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

Areas needing contributions:
- Language-specific vulnerability examples
- Additional tool comparisons
- Case studies and incident reports
- Translations

---

## Sources

### Academic Research
- [Stanford: "Do Users Write More Insecure Code with AI Assistants?"](https://arxiv.org/abs/2211.03622)
- [NYU: "Asleep at the Keyboard?"](https://arxiv.org/abs/2108.09293)
- [ACM TOSEM: "Security Weaknesses of Copilot-Generated Code"](https://dl.acm.org/doi/10.1145/3716848)

### Industry Reports
- [Veracode GenAI Code Security Report 2025](https://www.veracode.com/blog/genai-code-security-report/)
- [IDEsaster Research - 30+ AI IDE Vulnerabilities](https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html)

### Standards
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)

See [RESEARCH.md](./RESEARCH.md) for complete source list.

---

## License

MIT License - See [LICENSE](./LICENSE) for details.

---

## Stay Updated

⭐ **Star this repo** to stay updated on AI code security research.

🔔 **Watch** for notifications on new CVEs and incidents.

---

*Last updated: January 2026*
