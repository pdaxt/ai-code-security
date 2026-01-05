# AI-Generated Code Vulnerabilities: Deep Dive

## Overview

This document provides an in-depth analysis of specific vulnerabilities commonly found in AI-generated code, with examples and remediation guidance.

---

## Top Vulnerability Categories

### 1. Injection Vulnerabilities

#### SQL Injection (CWE-89)
**Prevalence:** Found in 15-25% of AI-generated database code

**Why AI generates this:**
- Training data contains legacy code patterns
- AI prioritizes functionality over security
- Prompt rarely specifies "use parameterized queries"

**Example - Vulnerable AI Output:**
```python
# BAD: AI-generated code
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)
```

**Secure Version:**
```python
# GOOD: Parameterized query
def get_user(username):
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (username,))
```

#### OS Command Injection (CWE-78)
**Prevalence:** Common in system administration scripts

**Example - Vulnerable AI Output:**
```python
# BAD: AI-generated code
def ping_host(hostname):
    os.system(f"ping -c 1 {hostname}")
```

**Secure Version:**
```python
# GOOD: Use subprocess with shell=False
import subprocess
import shlex

def ping_host(hostname):
    # Validate hostname format first
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError("Invalid hostname")
    subprocess.run(['ping', '-c', '1', hostname], shell=False)
```

---

### 2. Cross-Site Scripting (CWE-79)

**Prevalence:** Found in 20-30% of AI-generated web code

**Why AI generates this:**
- AI doesn't understand rendering context
- Template engines not always suggested
- Output encoding rarely prompted

**Example - Vulnerable AI Output:**
```javascript
// BAD: AI-generated code
app.get('/search', (req, res) => {
    res.send(`<h1>Results for: ${req.query.q}</h1>`);
});
```

**Secure Version:**
```javascript
// GOOD: Use proper escaping
const escapeHtml = require('escape-html');

app.get('/search', (req, res) => {
    const safeQuery = escapeHtml(req.query.q);
    res.send(`<h1>Results for: ${safeQuery}</h1>`);
});
```

---

### 3. Hard-coded Credentials (CWE-259/798)

**Prevalence:** Found in 10-15% of AI-generated code

**Why AI generates this:**
- Training data contains example code with placeholders
- AI provides "working" examples with fake credentials
- Developers may forget to replace them

**Example - Vulnerable AI Output:**
```python
# BAD: AI-generated code
DATABASE_URL = "postgresql://admin:password123@localhost:5432/mydb"
API_KEY = "sk-1234567890abcdef"
```

**Secure Version:**
```python
# GOOD: Use environment variables
import os

DATABASE_URL = os.environ.get('DATABASE_URL')
API_KEY = os.environ.get('API_KEY')

if not DATABASE_URL or not API_KEY:
    raise EnvironmentError("Required environment variables not set")
```

---

### 4. Insecure Cryptography

**Prevalence:** Found in 25-40% of AI-generated crypto code

**Common issues:**
- Use of MD5 or SHA1 for password hashing
- ECB mode for block ciphers
- Hard-coded initialization vectors
- Insufficient key sizes

**Example - Vulnerable AI Output:**
```python
# BAD: AI-generated code
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```

**Secure Version:**
```python
# GOOD: Use bcrypt or argon2
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)
```

---

### 5. Missing Authentication/Authorization

**Prevalence:** Common when AI generates API endpoints

**Example - Vulnerable AI Output:**
```python
# BAD: AI-generated code - no auth check
@app.route('/api/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    return jsonify({'status': 'deleted'})
```

**Secure Version:**
```python
# GOOD: Proper auth and authorization
from functools import wraps

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/api/users/<user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    return jsonify({'status': 'deleted'})
```

---

### 6. Insecure Deserialization (CWE-502)

**Prevalence:** Common in Python and Java code

**Example - Vulnerable AI Output:**
```python
# BAD: AI-generated code
import pickle

def load_data(data):
    return pickle.loads(data)  # Arbitrary code execution possible
```

**Secure Version:**
```python
# GOOD: Use safe formats like JSON
import json

def load_data(data):
    return json.loads(data)

# If you MUST use pickle, use restricted unpickler
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow safe classes
        safe_classes = {'collections': {'OrderedDict'}}
        if module in safe_classes and name in safe_classes[module]:
            return getattr(__import__(module), name)
        raise pickle.UnpicklingError(f"Forbidden: {module}.{name}")
```

---

### 7. Path Traversal (CWE-22)

**Prevalence:** Common in file handling code

**Example - Vulnerable AI Output:**
```python
# BAD: AI-generated code
@app.route('/files/<filename>')
def serve_file(filename):
    return send_file(f'/uploads/{filename}')
```

**Secure Version:**
```python
# GOOD: Validate and sanitize paths
import os
from werkzeug.utils import secure_filename

UPLOAD_DIR = '/uploads'

@app.route('/files/<filename>')
def serve_file(filename):
    # Sanitize filename
    safe_name = secure_filename(filename)

    # Construct and validate path
    file_path = os.path.join(UPLOAD_DIR, safe_name)
    real_path = os.path.realpath(file_path)

    # Ensure path is within allowed directory
    if not real_path.startswith(os.path.realpath(UPLOAD_DIR)):
        abort(403)

    if not os.path.exists(real_path):
        abort(404)

    return send_file(real_path)
```

---

### 8. Improper Error Handling

**Prevalence:** Very common - AI often omits error handling

**Example - Vulnerable AI Output:**
```python
# BAD: AI-generated code - exposes internal details
@app.route('/api/data')
def get_data():
    try:
        result = database.query("SELECT * FROM sensitive_data")
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)})  # Leaks internal info
```

**Secure Version:**
```python
# GOOD: Generic errors to users, detailed logs internally
import logging

logger = logging.getLogger(__name__)

@app.route('/api/data')
def get_data():
    try:
        result = database.query("SELECT * FROM sensitive_data")
        return jsonify(result)
    except DatabaseError as e:
        logger.error(f"Database error: {e}", exc_info=True)
        return jsonify({'error': 'Database unavailable'}), 503
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500
```

---

## Language-Specific Concerns

### Python
- Unsafe `pickle` usage
- `eval()` and `exec()` with user input
- Missing `shell=False` in subprocess
- Insecure random number generation (`random` vs `secrets`)

### JavaScript/TypeScript
- `eval()` and `new Function()`
- Prototype pollution
- Missing CSP headers
- Insecure regex (ReDoS)

### Java
- XML External Entity (XXE) in parsers
- Unsafe reflection
- SQL injection in JDBC
- Insecure object serialization

### Go
- Template injection
- Command injection via `os/exec`
- Race conditions
- Improper TLS configuration

---

## Detection Tools

### Static Analysis
| Tool | Languages | AI-Specific Features |
|------|-----------|---------------------|
| Semgrep | Multi | Custom rules for AI patterns |
| CodeQL | Multi | Deep data flow analysis |
| Snyk Code | Multi | AI-trained detection |
| Bandit | Python | Security-focused linting |
| ESLint Security | JS/TS | Security plugin rules |

### Dynamic Analysis
| Tool | Type | Use Case |
|------|------|----------|
| OWASP ZAP | DAST | Web application scanning |
| Burp Suite | DAST | Manual + automated testing |
| sqlmap | Specialized | SQL injection testing |

---

## Remediation Priority Matrix

| Vulnerability | CVSS Range | Fix Priority | Effort |
|---------------|------------|--------------|--------|
| SQL Injection | 8.0-10.0 | Critical | Low |
| Command Injection | 8.0-10.0 | Critical | Low |
| Hard-coded Secrets | 7.0-9.0 | High | Low |
| XSS | 6.0-8.0 | High | Medium |
| Insecure Crypto | 5.0-8.0 | High | Medium |
| Path Traversal | 5.0-7.0 | Medium | Low |
| Missing Auth | 7.0-9.0 | High | Medium |
| Error Disclosure | 3.0-5.0 | Low | Low |

---

## References

- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
