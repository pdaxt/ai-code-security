# AI-Generated Code Review Checklist

## Overview

This checklist is designed specifically for reviewing AI-generated code. Research shows that AI assistants produce code with **35-48% vulnerability rates**, making thorough review essential.

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI CODE REVIEW QUICK CHECK                   │
├─────────────────────────────────────────────────────────────────┤
│  □ INPUT VALIDATION    - Is ALL user input sanitized?          │
│  □ OUTPUT ENCODING     - Is output escaped for context?        │
│  □ AUTHENTICATION      - Are auth checks present?              │
│  □ AUTHORIZATION       - Are permissions verified?             │
│  □ SECRETS             - Any hardcoded credentials?            │
│  □ DEPENDENCIES        - Do all packages actually exist?       │
│  □ ERROR HANDLING      - Are errors handled safely?            │
│  □ CRYPTOGRAPHY        - Using modern algorithms?              │
│  □ SQL/COMMANDS        - Parameterized queries?                │
│  □ FILE OPERATIONS     - Path traversal protected?             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Detailed Review Checklist

### 1. Input Validation & Sanitization

**Why:** Missing input sanitization is the #1 flaw in AI-generated code.

- [ ] All user inputs are validated before use
- [ ] Input length limits are enforced
- [ ] Input type/format is verified
- [ ] Special characters are properly escaped
- [ ] Allowlists used instead of blocklists where possible

**AI-Specific Concerns:**
- AI often omits validation entirely unless explicitly prompted
- AI may use regex patterns that are bypassable
- AI may validate client-side but not server-side

**Red Flags in AI Code:**
```python
# BAD: Direct use of user input
query = f"SELECT * FROM users WHERE id = {user_id}"
os.system(f"ping {hostname}")
eval(user_input)
```

---

### 2. Output Encoding

**Why:** AI-generated code frequently causes XSS through improper output handling.

- [ ] HTML output is properly escaped
- [ ] JavaScript strings are safely encoded
- [ ] URL parameters are encoded
- [ ] SQL output used in queries is parameterized
- [ ] Content-Type headers are set correctly

**AI-Specific Concerns:**
- AI doesn't understand rendering context
- AI may use template engines incorrectly
- AI may mark content as "safe" inappropriately

**Red Flags:**
```javascript
// BAD: Unescaped output
res.send(`<h1>Welcome, ${username}</h1>`);
element.innerHTML = userContent;
```

---

### 3. Authentication

- [ ] Authentication is required for protected resources
- [ ] Password comparison uses constant-time functions
- [ ] Session tokens are properly generated
- [ ] Multi-factor authentication supported where needed
- [ ] Account lockout after failed attempts

**AI-Specific Concerns:**
- AI often generates authentication with timing vulnerabilities
- AI may suggest weak password requirements
- AI may store passwords in reversible format

**Red Flags:**
```python
# BAD: Timing attack vulnerability
if user.password == input_password:  # Use constant-time compare
    return True
```

---

### 4. Authorization

- [ ] Authorization checks on every protected action
- [ ] IDOR (Insecure Direct Object Reference) prevented
- [ ] Role-based access properly implemented
- [ ] Privilege escalation paths reviewed
- [ ] Default deny policy implemented

**AI-Specific Concerns:**
- AI often omits authorization entirely
- AI may check authentication but not authorization
- AI may have inconsistent authorization across endpoints

**Red Flags:**
```python
# BAD: Missing authorization
@app.route('/api/user/<user_id>/delete')
def delete_user(user_id):
    # No check if current user can delete this user!
    User.delete(user_id)
```

---

### 5. Secrets & Credentials

- [ ] No hardcoded passwords, API keys, or tokens
- [ ] Secrets loaded from environment variables
- [ ] Configuration files don't contain secrets
- [ ] Secrets not logged or exposed in errors
- [ ] Secret scanning enabled in CI/CD

**AI-Specific Concerns:**
- AI commonly suggests hardcoded example credentials
- AI may leak training data containing real secrets
- Developers may forget to replace AI-suggested placeholders

**Red Flags:**
```python
# BAD: Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgresql://admin:password@localhost/db"
JWT_SECRET = "supersecret"
```

---

### 6. Dependency Verification

- [ ] All imported packages actually exist
- [ ] Package names are spelled correctly
- [ ] Packages are from official sources
- [ ] Dependency versions don't have known vulnerabilities
- [ ] Lock files are used and committed

**AI-Specific Concerns:**
- **20% of AI-suggested packages don't exist** (slopsquatting risk)
- AI may suggest deprecated or abandoned packages
- AI may suggest packages with known vulnerabilities

**Verification Steps:**
```bash
# Check if package exists
npm info <package-name>
pip show <package-name>

# Check for vulnerabilities
npm audit
pip-audit
```

---

### 7. SQL & Database Operations

- [ ] Parameterized queries used (not string formatting)
- [ ] ORM used correctly with safe query builders
- [ ] Database user has minimal necessary permissions
- [ ] Connection strings don't contain credentials
- [ ] Sensitive data is encrypted at rest

**AI-Specific Concerns:**
- AI defaults to string formatting for SQL
- AI may use ORM but with raw query methods
- AI may suggest queries vulnerable to blind SQL injection

**Red Flags:**
```python
# BAD: String formatting
db.execute(f"SELECT * FROM users WHERE id = {id}")
db.execute("SELECT * FROM users WHERE id = " + id)
db.execute("SELECT * FROM users WHERE id = %s" % id)

# GOOD: Parameterized
db.execute("SELECT * FROM users WHERE id = ?", (id,))
```

---

### 8. Command Execution

- [ ] User input never directly in shell commands
- [ ] `shell=False` used with subprocess
- [ ] Command arguments properly escaped
- [ ] Allowlist of permitted commands where needed
- [ ] Commands run with minimal privileges

**AI-Specific Concerns:**
- AI often uses `os.system()` instead of `subprocess`
- AI may forget `shell=False`
- AI may concatenate user input into commands

**Red Flags:**
```python
# BAD
os.system(f"ping {hostname}")
subprocess.call(f"ls {directory}", shell=True)

# GOOD
subprocess.run(['ping', '-c', '1', validated_hostname], shell=False)
```

---

### 9. File Operations

- [ ] Path traversal attacks prevented
- [ ] File types validated (not just extension)
- [ ] Upload size limits enforced
- [ ] Uploaded files stored outside web root
- [ ] File permissions properly set

**AI-Specific Concerns:**
- AI rarely validates file paths
- AI may trust user-provided filenames
- AI may store files in accessible locations

**Red Flags:**
```python
# BAD: Path traversal
filename = request.args.get('file')
return send_file(f'/uploads/{filename}')  # ../../etc/passwd

# GOOD
from werkzeug.utils import secure_filename
safe_name = secure_filename(filename)
```

---

### 10. Cryptography

- [ ] Modern algorithms used (not MD5, SHA1 for security)
- [ ] Proper key sizes (RSA 2048+, AES 256)
- [ ] IVs/nonces are random and unique
- [ ] Keys not hardcoded
- [ ] Using well-tested libraries (not custom crypto)

**AI-Specific Concerns:**
- AI frequently suggests MD5 or SHA1
- AI may use ECB mode for block ciphers
- AI may hardcode IVs or use predictable values
- AI may implement crypto incorrectly even with good algorithms

**Red Flags:**
```python
# BAD
hashlib.md5(password).hexdigest()
cipher = AES.new(key, AES.MODE_ECB)  # ECB is insecure
iv = b'0000000000000000'  # Hardcoded IV

# GOOD
bcrypt.hashpw(password, bcrypt.gensalt())
cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))
```

---

### 11. Error Handling

- [ ] Errors don't expose internal details
- [ ] Stack traces not shown to users
- [ ] Errors logged with sufficient detail (internally)
- [ ] Fail-secure behavior (deny on error)
- [ ] Rate limiting on error-triggering endpoints

**AI-Specific Concerns:**
- AI often returns exception messages to users
- AI may log sensitive data in error messages
- AI may fail-open instead of fail-secure

**Red Flags:**
```python
# BAD
except Exception as e:
    return jsonify({'error': str(e)})  # Exposes internals

# GOOD
except Exception as e:
    logger.error(f"Error: {e}", exc_info=True)
    return jsonify({'error': 'An error occurred'}), 500
```

---

### 12. Logging & Monitoring

- [ ] Sensitive data not logged (passwords, tokens, PII)
- [ ] Security events logged (auth failures, access denied)
- [ ] Logs stored securely
- [ ] Log injection prevented
- [ ] Monitoring alerts configured

---

## Review Process

### Before Review
1. [ ] Identify which code is AI-generated (check commits, comments)
2. [ ] Note the prompts used (if available)
3. [ ] Understand the intended functionality

### During Review
1. [ ] Run through this checklist systematically
2. [ ] Use SAST tools to catch automated issues
3. [ ] Focus extra attention on security-critical sections
4. [ ] Document all findings

### After Review
1. [ ] Ensure all critical/high issues are fixed
2. [ ] Verify fixes don't introduce new issues
3. [ ] Update security documentation if needed
4. [ ] Consider adding tests for security requirements

---

## Severity Classification

| Severity | Description | Action Required |
|----------|-------------|-----------------|
| Critical | Exploitable vulnerability, high impact | Block merge, fix immediately |
| High | Likely exploitable, significant impact | Block merge, fix before release |
| Medium | Potentially exploitable, moderate impact | Fix in current sprint |
| Low | Defense in depth issue | Fix when convenient |
| Info | Best practice deviation | Consider fixing |

---

## Common AI Code Smells

Watch for these patterns that often indicate AI-generated code:

1. **Generic variable names** - `data`, `result`, `response`
2. **Overly verbose comments** - Explaining obvious code
3. **Inconsistent error handling** - Some paths handled, others not
4. **Mixed patterns** - Different approaches in similar code
5. **Example placeholder values** - `example.com`, `your-api-key`
6. **Missing edge cases** - Happy path only
7. **Outdated patterns** - Deprecated APIs or syntax

---

## Quick Commands for Reviewers

```bash
# Find hardcoded secrets (basic)
grep -rn "password\|secret\|api_key\|token" --include="*.py"

# Find SQL injection patterns
grep -rn "execute.*%" --include="*.py"
grep -rn "execute.*f\"" --include="*.py"

# Find command injection patterns
grep -rn "os.system\|subprocess.*shell=True" --include="*.py"

# Find dangerous functions
grep -rn "eval\|exec\|pickle.loads" --include="*.py"

# Run Bandit (Python)
bandit -r ./src/ -f json

# Run Semgrep
semgrep --config p/security-audit ./src/
```

---

## References

- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
