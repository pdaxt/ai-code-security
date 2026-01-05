# AI Code Security: Comprehensive Research Findings

> Last Updated: January 2026

## Table of Contents
- [Executive Summary](#executive-summary)
- [The Scale of the Problem](#the-scale-of-the-problem)
- [Key Research Studies](#key-research-studies)
- [Common Vulnerability Patterns](#common-vulnerability-patterns)
- [Attack Vectors](#attack-vectors)
- [2025 CVEs and Incidents](#2025-cves-and-incidents)
- [Why AI Generates Insecure Code](#why-ai-generates-insecure-code)
- [Mitigation Strategies](#mitigation-strategies)
- [Sources](#sources)

---

## Executive Summary

AI-generated code presents significant security risks that organizations must address proactively. Research consistently shows that **35-48% of AI-generated code contains security vulnerabilities**, with developers using AI assistants paradoxically being **more confident** about their code's security while producing **less secure** output.

### Key Statistics
| Metric | Finding | Source |
|--------|---------|--------|
| Vulnerability rate | 35.8% of Copilot code has security weaknesses | ACM TOSEM 2025 |
| Security test failures | 45% of AI code fails security tests | Veracode 2025 |
| Java failure rate | 72% security failure rate for Java tasks | Veracode 2025 |
| Package hallucinations | 20% of suggested packages don't exist | Slopsquatting Research |
| CVEs in AI tools | 24+ CVEs assigned to AI coding tools | IDEsaster Research 2025 |

---

## The Scale of the Problem

### AI Tool Usage is Exploding
- GitHub Copilot: 1.8+ million paid subscribers
- ChatGPT: Used by millions of developers for code generation
- Claude, CodeWhisperer, Tabnine: Growing enterprise adoption

### Security is Not Keeping Pace
A large-scale analysis of 7,703 files from public GitHub repositories explicitly attributed to AI tools found:
- **4,241 CWE instances** across 77 distinct vulnerability types
- **ChatGPT** generated 91.52% of analyzed AI-attributed code
- **Python** had highest vulnerability rates (16.18%-18.50%)
- **JavaScript** had moderate rates (8.66%-8.99%)
- **TypeScript** had lowest rates (2.50%-7.14%)

---

## Key Research Studies

### Stanford Study: "Do Users Write More Insecure Code with AI Assistants?"
**Authors:** Neil Perry, Megha Srivastava, Deepak Kumar, Dan Boneh
**Published:** ACM CCS 2023

**Key Findings:**
- Participants with AI assistant access wrote **significantly less secure code**
- Users with AI assistants were **more confident** their code was secure
- Particularly significant vulnerabilities in **string encryption** and **SQL injection** tasks
- Study involved 47 participants (undergrads, grad students, industry professionals)

> "Code-generating systems are currently not a replacement for human developers. Developers using them to complete tasks outside of their own areas of expertise should be concerned."

### NYU Study: "Asleep at the Keyboard?"
**Published:** August 2021

**Key Findings:**
- Given 89 scenarios, **40% of Copilot-generated programs** had exploitable vulnerabilities
- Follow-up study "Security Implications of Large Language Model Code Assistants" confirmed findings

### ACM TOSEM 2025: Security Weaknesses of Copilot-Generated Code
**Key Findings:**
- Analyzed 733 code snippets from real GitHub projects
- **29.5% of Python** snippets had security weaknesses
- **24.2% of JavaScript** snippets had security weaknesses
- Another analysis found **35.8%** vulnerability rate regardless of language

### Veracode GenAI Code Security Report 2025
**Key Findings:**
- Tested 100+ LLMs across Java, Python, C#, JavaScript
- **45% of code samples failed** security tests
- Introduced **OWASP Top 10 vulnerabilities**
- **Java was riskiest** at 72% failure rate

---

## Common Vulnerability Patterns

### Top 5 CWEs in AI-Generated Code
| CWE | Name | CVSS | Description |
|-----|------|------|-------------|
| CWE-89 | SQL Injection | High | Unsanitized input in SQL queries |
| CWE-78 | OS Command Injection | High | Unsanitized input in system commands |
| CWE-79 | Cross-Site Scripting (XSS) | Medium-High | Unsanitized output in web pages |
| CWE-94 | Code Injection | High | Unsanitized input executed as code |
| CWE-259/798 | Hard-coded Credentials | High | Embedded secrets in code |

### Why These Are Common
1. **Missing input sanitization** is the #1 flaw in AI-generated code
2. AI omits validation unless **explicitly prompted**
3. Training data contains legacy code with bad practices
4. AI prioritizes functionality over security
5. Context window limitations prevent architectural understanding

### Authentication & Cryptography Issues
- **Timing attack vulnerabilities** in authentication logic
- Use of **deprecated cryptographic algorithms** (MD5, SHA1)
- **Incorrect implementation** of secure algorithms
- **Hardcoded configuration values** including API keys, database strings

---

## Attack Vectors

### 1. Slopsquatting (Package Hallucination Hijacking)
**How it works:**
1. AI suggests importing a package that doesn't exist
2. Attacker registers the hallucinated package name
3. Developer trusts AI and installs the malicious package
4. Attacker gains code execution in developer's environment

**Research findings:**
- 16 LLMs tested generated **576,000 code samples**
- **20% of suggested packages didn't exist** (205,000 unique names)
- **43% of hallucinations were repeatable** across runs
- GPT-4 hallucinates **4x less** than open-source models

**Real-world impact:**
- Alibaba published code with hallucinated dependencies
- Package was later registered and downloaded thousands of times

### 2. Prompt Injection in AI Coding Tools
**"Rules File Backdoor" Attack (2025):**
- Attackers inject hidden malicious instructions into config files
- Cursor, GitHub Copilot, and others vulnerable
- Hidden Unicode text used to disguise malicious prompts

**Attack consequences:**
- Data exfiltration to attacker-controlled domains
- Code execution via workspace configuration manipulation
- Full control over Copilot's suggestions

### 3. Supply Chain Attacks via AI Tools
**CamoLeak Vulnerability (GitHub Copilot):**
- CVSS 9.6 critical vulnerability
- Silent exfiltration of secrets and source code from private repos
- Attackers could control Copilot's responses
- Suggest malicious code or links to developers

---

## 2025 CVEs and Incidents

### IDEsaster: 30+ Vulnerabilities Across AI IDEs
**Researcher:** Ari Marzouk
**Affected Tools:** Cursor, Windsurf, Kiro.dev, GitHub Copilot, Zed.dev, Roo Code, Junie, Cline, Gemini CLI, Claude Code

#### Configuration Override / Code Execution
| CVE | Tool | Attack |
|-----|------|--------|
| CVE-2025-64660 | GitHub Copilot | Prompt injection to edit workspace config |
| CVE-2025-61590 | Cursor | Prompt injection for code execution |
| CVE-2025-58372 | Roo Code | Settings override via prompt injection |

#### Data Exfiltration
| CVE | Tool | Attack |
|-----|------|--------|
| CVE-2025-53773 | GitHub Copilot | Read sensitive files, leak via JSON schemas |
| CVE-2025-54130 | Cursor | Data exfiltration to attacker domains |
| CVE-2025-53097 | Roo Code | Sensitive file access |
| CVE-2025-58335 | JetBrains Junie | Data leak via prompt injection |
| CVE-2025-49150 | Cursor | File read and exfiltration |

#### Other Notable CVEs
| CVE | Tool | Issue |
|-----|------|-------|
| CVE-2025-61260 | OpenAI Codex CLI | Command injection |
| CVE-2025-23254 | NVIDIA TensorRT-LLM | Arbitrary code execution via deserialization |

### Vendor Responses
- **GitHub:** Implemented warnings for hidden Unicode text
- **AWS:** Released advisory AWS-2025-019
- **Anthropic (Claude Code):** Addressed via security documentation
- **CrowdStrike:** Reported threat actors exploiting Langflow AI

---

## Why AI Generates Insecure Code

### 1. Training Data Problems
- Trained on massive codebases including **legacy, vulnerable code**
- Security best practices underrepresented in training data
- Popular patterns (Stack Overflow) often lack security context

### 2. Optimization for Functionality
- Models optimized to produce **working code**, not secure code
- Security is a constraint, not the primary objective
- "Correct" in training often means "runs without errors"

### 3. Context Limitations
- Limited context window prevents architectural understanding
- Cannot see entire application security posture
- Missing knowledge of deployment environment

### 4. Lack of Security Prompting
- Default prompts don't mention security
- Models apply **inconsistent checks** even when prompted
- Simple "write secure code" often insufficient

### 5. Iterative Degradation
- **37.6% increase in critical vulnerabilities** after 5 iterations
- Each LLM iteration can introduce new flaws
- "Improvement" iterations don't improve security

### 6. Confidence Paradox
- Developers using AI are **more confident** about security
- But they produce **less secure code**
- False confidence reduces manual review diligence

---

## Mitigation Strategies

### Prompting Techniques
| Technique | Description | Effectiveness |
|-----------|-------------|---------------|
| Recursive Criticism & Improvement (RCI) | Multi-pass review process | Most effective |
| CWE-Specific Prompts | Add security cues for specific CWEs | High |
| Zero-Shot Chain-of-Thought | Step-by-step reasoning about security | Medium-High |
| Persona-Based Prompting | "Act as a security expert" | Medium |
| Naive-Secure Prompt | Simply add "secure" to instructions | Low-Medium |

### Organizational Policies
1. **Mandatory code review**: At least 2 human checks for all AI-generated code
2. **Automated scanning**: SAST/DAST in CI/CD pipeline
3. **Block on vulnerabilities**: No merge if critical/high CVEs detected
4. **Tag AI-generated code**: Mark commits for audit trails
5. **SBOM generation**: Every build produces Software Bill of Materials
6. **Approved tool catalog**: Block shadow AI at proxy layer
7. **Maximum 3 consecutive LLM iterations** before human review

### Technical Controls
- **Secret scanning**: Block commits with embedded credentials
- **Dependency verification**: Validate packages before installation
- **Input sanitization**: Treat all AI output as untrusted
- **Output encoding**: Escape AI output before rendering
- **Sandboxing**: Isolate AI-generated code execution
- **Immutable logs**: Record all AI requests for audit

### Developer Training
- Security-focused prompting techniques
- Recognizing common AI code vulnerabilities
- Understanding AI limitations
- Manual review best practices

---

## Sources

### Academic Papers
- [Do Users Write More Insecure Code with AI Assistants?](https://arxiv.org/abs/2211.03622) - Stanford, ACM CCS 2023
- [Security Weaknesses of Copilot-Generated Code in GitHub Projects](https://dl.acm.org/doi/10.1145/3716848) - ACM TOSEM 2025
- [Security Vulnerabilities in AI-Generated Code: Large-Scale Analysis](https://arxiv.org/html/2510.26103)
- [Prompting Techniques for Secure Code Generation](https://dl.acm.org/doi/10.1145/3722108) - ACM TOSEM
- [Large Language Models and Code Security: Systematic Literature Review](https://arxiv.org/html/2412.15004v2)

### Industry Research
- [Veracode GenAI Code Security Report 2025](https://www.veracode.com/blog/genai-code-security-report/)
- [GitHub Copilot Security Review 2025](https://blueradius.io/github-copilot-security-review-2025/)
- [The Most Common Security Vulnerabilities in AI-Generated Code](https://www.endorlabs.com/learn/the-most-common-security-vulnerabilities-in-ai-generated-code) - Endor Labs
- [IDEsaster Research: 30+ Flaws in AI Coding Tools](https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html) - The Hacker News

### Slopsquatting Research
- [Slopsquatting: When AI Agents Hallucinate Malicious Packages](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/slopsquatting-when-ai-agents-hallucinate-malicious-packages) - Trend Micro
- [AI Hallucinations Create "Slopsquatting" Supply Chain Threat](https://www.infosecurity-magazine.com/news/ai-hallucinations-slopsquatting/) - Infosecurity Magazine

### OWASP Resources
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/)
- [OWASP LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [Improper Output Handling (LLM05)](https://auth0.com/blog/owasp-llm05-improper-output-handling/)

### Vendor Documentation
- [GitHub Security Features](https://docs.github.com/en/code-security/getting-started/github-security-features)
- [Snyk Code SAST](https://snyk.io/product/snyk-code/)
- [Semgrep App Security Platform](https://semgrep.dev/)

### News & Analysis
- [AI coding tools exploded in 2025. The first security exploits show what could go wrong](https://fortune.com/2025/12/15/ai-coding-tools-security-exploit-software/) - Fortune
- [LLMs' AI-Generated Code Remains Wildly Insecure](https://www.darkreading.com/application-security/llms-ai-generated-code-wildly-insecure) - Dark Reading
- [Critical Vulnerabilities Found in GitHub Copilot, Gemini CLI, Claude](https://gbhackers.com/ai-developer-tools/) - GBHackers
