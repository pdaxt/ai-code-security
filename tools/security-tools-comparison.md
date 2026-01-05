# Security Tools for AI-Generated Code

## Overview

This document provides a comprehensive comparison of security tools that can detect vulnerabilities in AI-generated code, with specific attention to tools that address AI-specific concerns.

---

## Tool Categories

### SAST (Static Application Security Testing)
Analyze source code without execution to find vulnerabilities.

### DAST (Dynamic Application Security Testing)
Test running applications to find vulnerabilities.

### SCA (Software Composition Analysis)
Identify vulnerabilities in third-party dependencies.

### Secret Scanning
Detect exposed credentials, API keys, and tokens.

---

## SAST Tools Comparison

### Tier 1: Enterprise Solutions

#### Snyk Code
**Best for:** AI-trained detection, IDE integration

| Feature | Details |
|---------|---------|
| Languages | 15+ including Python, JS, Java, Go |
| AI Features | Trained on millions of repos |
| IDE Support | VS Code, IntelliJ, PyCharm |
| CI/CD | GitHub Actions, GitLab CI, Jenkins |
| Pricing | Free (100 tests/mo) → Enterprise |

**Strengths:**
- AI-powered scanning learns from real-world code
- Real-time feedback as you code
- Extensive support for LLM-related libraries (OpenAI, Hugging Face)
- Low false positive rate

**Weaknesses:**
- Full features require paid plans
- Some advanced rules enterprise-only

**[snyk.io/product/snyk-code](https://snyk.io/product/snyk-code/)**

---

#### Semgrep
**Best for:** Custom rules, CI/CD integration

| Feature | Details |
|---------|---------|
| Languages | 30+ languages |
| Rule System | YAML-based, highly customizable |
| Open Source | Yes (core engine) |
| AI Features | Noise filtering, reachability analysis |
| Pricing | Free → Team → Enterprise |

**Strengths:**
- Semantic pattern matching (understands code structure)
- Incredibly fast processing
- Up to 98% false positive reduction with AI filtering
- Can write custom rules for AI-specific patterns

**Weaknesses:**
- Requires tuning for best results
- SAST-only (no DAST)

**Custom Rule for AI Code:**
```yaml
rules:
  - id: ai-generated-unsanitized-input
    patterns:
      - pattern: |
          $USER_INPUT = request.$METHOD(...)
          ...
          $DB.execute($QUERY.format($USER_INPUT))
    message: "Potential SQL injection - common in AI-generated code"
    severity: ERROR
```

**[semgrep.dev](https://semgrep.dev/)**

---

#### SonarQube
**Best for:** Code quality + security combined

| Feature | Details |
|---------|---------|
| Languages | 30+ languages |
| Deployment | Self-hosted or Cloud |
| Quality Focus | Yes (combines quality + security) |
| IDE Plugin | SonarLint for real-time |
| Pricing | Free Community → Enterprise |

**Strengths:**
- Blocks merges if vulnerabilities introduced
- Combines code quality with security
- Deep static analysis engine
- Large rule database

**Weaknesses:**
- Can be resource-intensive
- Advanced security rules require paid tiers

**[sonarqube.org](https://www.sonarqube.org/)**

---

#### Checkmarx
**Best for:** Enterprise-scale security programs

| Feature | Details |
|---------|---------|
| Languages | 25+ languages |
| SAST | Yes |
| DAST | Yes (Checkmarx DAST) |
| SCA | Yes (Checkmarx SCA) |
| Pricing | Enterprise |

**Strengths:**
- Comprehensive platform (SAST + DAST + SCA)
- Excellent enterprise support
- Detailed vulnerability explanations
- Compliance reporting

**Weaknesses:**
- Expensive
- Complex setup

---

### Tier 2: Open Source / Free Options

#### CodeQL (GitHub)
**Best for:** Deep data flow analysis, free for open source

| Feature | Details |
|---------|---------|
| Languages | C/C++, C#, Go, Java, JS, Python, Ruby |
| Owner | GitHub/Microsoft |
| Deployment | GitHub Actions or CLI |
| Pricing | Free for public repos |

**Strengths:**
- Deep semantic analysis
- Data flow tracking across functions
- Free for open source
- Community-contributed queries

**Weaknesses:**
- Learning curve for custom queries
- Requires GitHub integration for best experience

**Example Query for AI Code:**
```ql
import python

from Call call, Name name
where
  call.getFunc().(Attribute).getName() = "execute" and
  call.getArg(0).(BinaryExpr).getOp() instanceof Mod
select call, "Potential SQL injection via string formatting"
```

---

#### Bandit (Python)
**Best for:** Python-specific security scanning

| Feature | Details |
|---------|---------|
| Language | Python only |
| Open Source | Yes |
| Speed | Very fast |
| Pricing | Free |

**Strengths:**
- Purpose-built for Python security
- Very low overhead
- Easy CI/CD integration
- Active community

**Weaknesses:**
- Python only
- May miss complex vulnerabilities

```bash
# Install and run
pip install bandit
bandit -r ./your_code/ -f json -o results.json
```

---

#### ESLint Security Plugins (JavaScript)
**Best for:** JavaScript/TypeScript security linting

| Plugin | Focus |
|--------|-------|
| eslint-plugin-security | General security |
| eslint-plugin-security-node | Node.js specific |
| eslint-plugin-xss | XSS prevention |

```json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"]
}
```

---

## DAST Tools

### OWASP ZAP
**Best for:** Free, comprehensive web app scanning

| Feature | Details |
|---------|---------|
| Type | DAST |
| Open Source | Yes |
| Automation | API, CI/CD integration |
| Pricing | Free |

**Strengths:**
- Industry standard for DAST
- Active development
- Large plugin ecosystem
- Excellent for API testing

**[zaproxy.org](https://www.zaproxy.org/)**

---

### Burp Suite
**Best for:** Professional penetration testing

| Feature | Details |
|---------|---------|
| Type | DAST + Manual testing |
| Versions | Community (free), Pro, Enterprise |
| Automation | Yes (Pro/Enterprise) |

**Strengths:**
- Industry standard for pentesters
- Powerful manual testing capabilities
- Extensive extension ecosystem

**Weaknesses:**
- Full features require paid license
- Steeper learning curve

---

## Secret Scanning Tools

### GitGuardian
**Best for:** Comprehensive secret detection

| Feature | Details |
|---------|---------|
| Detection | 350+ secret types |
| Pre-commit | Yes |
| CI/CD | Yes |
| Historical | Scans git history |
| Pricing | Free tier → Enterprise |

**AI-Specific Value:**
AI tools commonly suggest code with hardcoded secrets. GitGuardian catches these before they reach production.

**[gitguardian.com](https://www.gitguardian.com/)**

---

### GitHub Secret Scanning
**Best for:** GitHub-native detection

| Feature | Details |
|---------|---------|
| Integration | Native to GitHub |
| Push Protection | Blocks secrets at push |
| AI Enhancement | Copilot-powered generic detection |
| Pricing | Free (public), GHAS (private) |

**Features:**
- Scans entire git history
- Partner program alerts token issuers
- Push protection prevents commits
- AI detects unstructured secrets (passwords)

---

### TruffleHog
**Best for:** Deep git history scanning

| Feature | Details |
|---------|---------|
| Open Source | Yes |
| Scanning | Git history, S3, filesystem |
| Verification | Validates if secrets are active |
| Pricing | Free (CLI), Enterprise |

```bash
# Scan git repo
trufflehog git https://github.com/org/repo --only-verified
```

---

## SCA (Dependency Scanning)

### Dependabot (GitHub)
**Best for:** Automated dependency updates

| Feature | Details |
|---------|---------|
| Integration | Native to GitHub |
| Alerts | Vulnerability notifications |
| Updates | Automated PRs |
| Pricing | Free |

**AI-Specific Value:**
Catches when AI suggests vulnerable dependency versions.

---

### Snyk Open Source
**Best for:** Deep dependency analysis

| Feature | Details |
|---------|---------|
| Languages | All major ecosystems |
| Database | Proprietary vulnerability DB |
| Fix PRs | Automated remediation |
| Pricing | Free tier → Enterprise |

---

### npm audit / pip-audit
**Best for:** Quick checks in CI

```bash
# npm
npm audit --json

# pip
pip-audit --format json
```

---

## AI-Specific Tools

### Tools That Address AI Code Concerns

| Tool | AI-Specific Feature |
|------|---------------------|
| Snyk Code | Trained on real code, including AI-generated patterns |
| Semgrep | Custom rules for AI-common vulnerabilities |
| GitGuardian | Catches AI-suggested hardcoded secrets |
| Dependabot | Validates AI-suggested dependencies exist |

### Package Validation (Anti-Slopsquatting)
No dedicated tools yet, but recommended workflow:

```bash
# Before installing AI-suggested package:
# 1. Check if it exists
npm info <package-name>

# 2. Check download stats (low = suspicious)
npm view <package-name> --json | jq '.downloads'

# 3. Check when it was created (new = suspicious)
npm view <package-name> time.created
```

---

## Integration Matrix

| Tool | GitHub | GitLab | Bitbucket | Azure DevOps | Jenkins |
|------|--------|--------|-----------|--------------|---------|
| Snyk | ✅ | ✅ | ✅ | ✅ | ✅ |
| Semgrep | ✅ | ✅ | ✅ | ✅ | ✅ |
| SonarQube | ✅ | ✅ | ✅ | ✅ | ✅ |
| CodeQL | ✅ | ❌ | ❌ | ❌ | ⚠️ |
| GitGuardian | ✅ | ✅ | ✅ | ✅ | ✅ |
| OWASP ZAP | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Recommended Stack by Organization Size

### Startup / Small Team (Free)
```
SAST: Semgrep (free) + Bandit (Python)
Secrets: GitHub Secret Scanning + TruffleHog
SCA: Dependabot
DAST: OWASP ZAP
```

### Mid-Size Company
```
SAST: Snyk Code (Team)
Secrets: GitGuardian
SCA: Snyk Open Source
DAST: OWASP ZAP + periodic Burp
```

### Enterprise
```
SAST: Checkmarx or Snyk Enterprise
Secrets: GitGuardian Enterprise
SCA: Snyk or Black Duck
DAST: Burp Enterprise + OWASP ZAP
Additional: Custom Semgrep rules
```

---

## CI/CD Pipeline Example

```yaml
# GitHub Actions example
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      # SAST with Semgrep
      - uses: returntocorp/semgrep-action@v1
        with:
          config: p/security-audit

      # Secret Scanning
      - uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified

      # Dependency Check
      - name: npm audit
        run: npm audit --audit-level=high

      # CodeQL (if enabled)
      - uses: github/codeql-action/analyze@v2
```

---

## Tool Selection Decision Tree

```
Start
  │
  ├─ Budget: $0?
  │   └─ Semgrep + Bandit + GitHub native tools
  │
  ├─ Need IDE integration?
  │   └─ Snyk Code (has SonarLint-like real-time)
  │
  ├─ Need custom rules for AI patterns?
  │   └─ Semgrep (YAML rules)
  │
  ├─ Need SAST + DAST + SCA in one?
  │   └─ Checkmarx or Snyk Platform
  │
  └─ GitHub-native preferred?
      └─ CodeQL + Dependabot + Secret Scanning
```

---

## References

- [OWASP Source Code Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [Best SAST Tools of 2025](https://www.stackhawk.com/blog/best-sast-tools-comparison/)
- [Top Code Vulnerability Scanners 2026](https://www.aikido.dev/blog/top-code-vulnerability-scanners)
- [GitHub Security Features](https://docs.github.com/en/code-security/getting-started/github-security-features)
