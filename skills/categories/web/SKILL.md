---
name: web
description: Use when the challenge target is an HTTP service, API, or web app and likely involves auth/session flaws, injection, access control bypass, SSRF, deserialization, template injection, path traversal, or insecure file handling.
---

# CTF Web

Use this skill for browser/API challenges and web service exploitation.

## 1. Recon First

- Identify stack/framework from headers, errors, responses.
- Crawl endpoints and static assets.
- Enumerate auth flows, roles, and session mechanics.

Quick commands:
```bash
curl -i http://TARGET/
curl -i http://TARGET/robots.txt
curl -i http://TARGET/sitemap.xml
```

## 2. Input Surface Mapping

Capture all user-controlled inputs:
- Query params
- JSON body keys
- Path segments
- Headers/cookies
- Uploaded file names and content

Then test one vector at a time.

## 3. High-Value Web Classes

- SQL injection
- SSTI
- Command injection
- Path traversal / local file read
- IDOR / broken access control
- JWT/signature/alg confusion
- SSRF
- Prototype pollution (JS backends)

## 4. Session/Auth Checks

- Weak/resettable secrets
- Predictable tokens
- Missing authorization checks across endpoints
- Role changes accepted from client-controlled fields

## 5. File Upload and Parsing

- Try extension/content-type confusion
- Test archive extraction path traversal
- Inspect parser behavior for zip/tar/image/document handlers
- Verify whether uploaded paths can escape intended root

## 6. Structured Workflow

1. Confirm vulnerable endpoint behavior with minimal payload
2. Build deterministic PoC
3. Escalate impact toward flag/data access
4. Extract flag with reproducible steps

## 7. Evidence Quality

- Save requests/responses and payloads in `output/`.
- Record exact endpoint + method + payload + result.
- Avoid noisy brute force if a logic flaw is evident.
