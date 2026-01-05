# Real-World AI Code Security Incidents

## Overview

This document catalogs confirmed security incidents, vulnerabilities, and exploits related to AI code generation tools. These aren't theoretical risks - they're documented breaches and CVEs affecting production systems.

---

## 2025 Incidents and CVEs

### IDEsaster: Mass Vulnerability Disclosure (December 2025)

**Researcher:** Ari Marzouk
**Impact:** 24+ CVEs across 10+ AI coding tools
**Affected:** Millions of developers

#### Summary
Security researcher Ari Marzouk discovered over 30 security flaws across major AI-powered IDEs through 6 months of research. The vulnerabilities, collectively named "IDEsaster," affect tools used by millions of developers worldwide.

#### Affected Tools
- GitHub Copilot
- Cursor
- Windsurf
- Kiro.dev
- Zed.dev
- Roo Code
- JetBrains Junie
- Cline
- Gemini CLI
- Claude Code

#### CVE Details

**Remote Code Execution via Config Override:**
| CVE | Tool | CVSS | Description |
|-----|------|------|-------------|
| CVE-2025-64660 | GitHub Copilot | High | Prompt injection to modify workspace settings |
| CVE-2025-61590 | Cursor | High | Prompt injection enabling code execution |
| CVE-2025-58372 | Roo Code | High | Settings override via injection |

**Data Exfiltration:**
| CVE | Tool | CVSS | Description |
|-----|------|------|-------------|
| CVE-2025-53773 | GitHub Copilot | High | Sensitive file read + JSON schema leak |
| CVE-2025-54130 | Cursor | High | Data exfil to attacker domains |
| CVE-2025-53097 | Roo Code | Medium | Unauthorized file access |
| CVE-2025-58335 | JetBrains Junie | Medium | Prompt injection data leak |
| CVE-2025-49150 | Cursor | High | File read and exfiltration |

**Command Injection:**
| CVE | Tool | CVSS | Description |
|-----|------|------|-------------|
| CVE-2025-61260 | OpenAI Codex CLI | High | Command injection flaw |

---

### CamoLeak: GitHub Copilot Critical Vulnerability (June 2025)

**CVSS:** 9.6 (Critical)
**Discoverer:** Legit Security
**Impact:** All GitHub Copilot Chat users

#### Attack Chain
1. Attacker crafts malicious repository or file
2. Victim opens repo in VS Code with Copilot
3. Hidden instructions trigger Copilot to:
   - Exfiltrate secrets from private repos
   - Suggest malicious code
   - Redirect to attacker-controlled URLs

#### Exploitation Requirements
- Victim must have GitHub Copilot Chat active
- Attacker needs victim to open malicious content
- No user interaction required beyond opening file

#### Vendor Response
GitHub implemented warnings for hidden Unicode text in files and patched the underlying vulnerability.

---

### Rules File Backdoor Attack (2025)

**Discovered by:** Pillar Security
**Affected Tools:** Cursor, GitHub Copilot, others

#### Attack Mechanism
Attackers discovered they could inject malicious instructions into configuration files (like `.cursorrules` or `.github/copilot-instructions.md`) using hidden Unicode characters.

#### Impact
- Silent modification of AI-generated code
- Injection of backdoors in seemingly normal suggestions
- Supply chain compromise through shared config files

#### Real-World Exploitation
Configuration files are commonly shared:
- Committed to repositories
- Shared in tutorials
- Distributed in boilerplate templates

A single malicious config file could affect thousands of projects.

---

### Langflow AI Exploitation (2025)

**Reported by:** CrowdStrike
**Type:** Unauthenticated Code Injection

#### Summary
CrowdStrike observed multiple threat actors exploiting an unauthenticated code injection vulnerability in Langflow AI to:
- Gain credentials
- Deploy malware
- Establish persistence

This represents one of the first documented cases of AI development tools being actively exploited in the wild by threat actors.

---

### NVIDIA TensorRT-LLM Vulnerability (April 2025)

**CVE:** CVE-2025-23254
**Type:** Insecure Deserialization
**Impact:** Arbitrary code execution

#### Details
A critical vulnerability in NVIDIA's TensorRT-LLM framework allowed attackers with local access to:
- Execute arbitrary code
- Access sensitive information
- Tamper with data

The vulnerability stemmed from insecure deserialization of model files.

---

### ChatGPT Prompt Injection Data Leak (March 2025)

**Type:** Prompt Injection
**Impact:** User data disclosure

#### Summary
Attackers exploited a prompt injection vulnerability in ChatGPT that caused it to disclose sensitive user data by embedding malicious prompts designed to bypass safety mechanisms.

This incident highlighted that even well-defended consumer AI products remain vulnerable to sophisticated prompt injection attacks.

---

## 2024 Incidents

### Alibaba Slopsquatting Incident

**Type:** Package Hallucination Exploitation
**Impact:** Supply chain compromise

#### Summary
Alibaba published source code that incorporated a software package previously hallucinated by generative AI. A threat actor:
1. Noticed the recurring hallucination pattern
2. Registered the fake package name on npm
3. The package was downloaded thousands of times

This was one of the first documented cases of a major company falling victim to slopsquatting.

---

### Academic Study: Package Hallucination Scale

**Researchers:** Multiple academic institutions
**Published:** 2024

#### Findings
Researchers tested 16 code-generation LLMs with 576,000 code samples:
- **205,000 unique hallucinated package names** (20% of suggestions)
- **43% were repeatable** across multiple runs
- Open-source models hallucinate **4x more** than GPT-4

This research demonstrated that package hallucination is not an edge case but a systematic problem across all AI code generation tools.

---

## Pre-2024 Foundational Incidents

### GitHub Copilot Secret Leakage (2023)

**Discovered by:** GitGuardian
**Type:** Training Data Leakage

#### Summary
Research showed GitHub Copilot could suggest code containing:
- Real API keys from training data
- Database connection strings
- Private tokens and credentials

While not a "vulnerability" in the traditional sense, this demonstrated the risk of AI tools trained on public code repositories that inadvertently contained secrets.

---

### Stanford User Study Findings (2022-2023)

**Study:** "Do Users Write More Insecure Code with AI Assistants?"

While not an "incident," this research documented that AI assistants were causing developers to introduce more vulnerabilities:
- Significant increase in **SQL injection** vulnerabilities
- Significant increase in **string encryption** flaws
- Developers were **more confident** while writing **less secure** code

---

## Attack Pattern Analysis

### Most Common Exploitation Methods

| Attack Type | Frequency | Severity | Ease of Exploitation |
|-------------|-----------|----------|---------------------|
| Prompt Injection | Very High | High | Easy |
| Configuration Poisoning | High | Critical | Medium |
| Package Hallucination | High | High | Easy |
| Data Exfiltration | Medium | High | Medium |
| RCE via Deserialization | Low | Critical | Hard |

### Threat Actor Motivations

1. **Supply Chain Compromise**
   - Target development environments
   - Inject backdoors at code generation
   - Affect downstream users

2. **Data Theft**
   - Source code exfiltration
   - Credential harvesting
   - Intellectual property theft

3. **Malware Distribution**
   - Slopsquatting packages
   - Trojanized dependencies
   - Cryptominers in dev environments

---

## Lessons Learned

### For Developers
1. **Never trust AI output blindly** - Always review suggested code
2. **Verify all packages** - Check that suggested dependencies exist
3. **Use secret scanning** - Catch leaked credentials before commit
4. **Review config files** - Check for hidden characters before using shared configs

### For Organizations
1. **Implement SAST/DAST** - Automated scanning catches AI-introduced flaws
2. **Require code review** - Human oversight remains essential
3. **Monitor for anomalies** - Watch for unusual data exfiltration patterns
4. **Keep tools updated** - AI tool vendors are actively patching

### For Tool Vendors
1. **Implement prompt injection defenses**
2. **Add hidden character warnings**
3. **Validate suggestions against known vulnerabilities**
4. **Provide transparency about AI limitations**

---

## Timeline

```
2021 Aug - NYU "Asleep at the Keyboard?" study published
2022 Nov - Stanford study shows AI increases vulnerabilities
2023     - GitGuardian reveals Copilot can leak secrets
2024     - Alibaba slopsquatting incident
2024     - Large-scale package hallucination research published
2025 Mar - ChatGPT prompt injection data leak
2025 Apr - NVIDIA TensorRT-LLM CVE
2025 Jun - CamoLeak (GitHub Copilot CVSS 9.6)
2025     - Pillar Security discovers "Rules File Backdoor"
2025     - CrowdStrike reports Langflow exploitation
2025 Dec - IDEsaster: 24+ CVEs disclosed
```

---

## References

- [Critical Vulnerabilities Found in AI Developer Tools](https://gbhackers.com/ai-developer-tools/)
- [CamoLeak: Critical GitHub Copilot Vulnerability](https://www.legitsecurity.com/blog/camoleak-critical-github-copilot-vulnerability-leaks-private-source-code)
- [New Vulnerability in GitHub Copilot and Cursor](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [AI coding tools exploded in 2025](https://fortune.com/2025/12/15/ai-coding-tools-security-exploit-software/)
- [Slopsquatting: When AI Agents Hallucinate](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/slopsquatting-when-ai-agents-hallucinate-malicious-packages)
