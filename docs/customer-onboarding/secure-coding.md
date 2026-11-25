# Secure Application Coding Guidance

WAF protection is **defense-in-depth**, not a substitute for secure application code. Use these practices in your origin applications:

1. **SQL Injection:** Always use parameterized queries / prepared statements. Never concatenate user input into SQL strings.
2. **Cross-Site Scripting (XSS):** Apply context-aware output encoding, sanitize rich HTML with a vetted library, and enforce a strict `Content-Security-Policy` (CSP).
3. **Path Traversal:** Never pass raw user filenames into filesystem APIs. Canonicalize paths and verify they remain inside an allowlisted base directory.
4. **Authentication & Authorization:** Enforce object-level authorization (IDOR checks) on every API handler, hash passwords with Argon2id/bcrypt, and rate-limit login/OTP flows.
5. **Dependency Patching:** Keep frameworks, runtime libraries, and OS packages patched against known CVEs.
