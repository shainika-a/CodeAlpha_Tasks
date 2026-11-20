# Secure Coding Review Report

## Scope and method
Application: a small, deliberately vulnerable Flask web application with a SQLite-backed credential check and a greeting endpoint. Language: Python 3. Scope: `vulnerable_app.py`, with remediation reviewed in `remediated_app.py`. This is an educational specimen, not an audit of a third-party service. All credentials and data are fictional.

Method: manual source inspection and data-flow analysis. Trace untrusted form/query inputs into SQL and HTML, inspect password persistence, and review startup configuration. Runtime exploitation and automated scans were not performed. The supplied regression tests are a validation plan, not recorded passing results.

## Findings summary
| ID | Finding | Severity | Classification | Review status |
| --- | --- | --- | --- | --- |
| F01 | SQL injection in credential lookup | High | CWE-89 | Confirmed in source; fix implemented |
| F02 | Plaintext password storage and shared demo password | High | CWE-256 / CWE-798 | Confirmed in source; fix implemented |
| F03 | Reflected cross-site scripting in greeting | Medium | CWE-79 | Confirmed in source; fix implemented |
| F04 | Debugger enabled at startup | Medium locally; potentially High if exposed | CWE-489 | Confirmed in source; fix implemented |

Severity reflects this application's context and potential impact, not a calculated CVSS score. Localhost binding limits exposure; it does not make insecure patterns suitable for production. Fixed means the source changes are present, not that runtime validation is complete.

## F01: SQL injection
**Location:** `login()` in `vulnerable_app.py`, the f-string assigned to `query`, then `db.execute(query)`.

**Data flow:** HTTP form username/password → string interpolation → executable SQL. User data can change query structure instead of remaining a value.

**Impact:** an attacker able to reach this endpoint could bypass the credential check or cause database query errors. This example returns a successful JSON response; it does not create an authenticated session, so a session takeover is not claimed.

**Remediation:** use `WHERE username = ?` with a parameter tuple; fetch the password hash and check it separately. Do not attempt to solve injection by stripping quote characters or relying only on input validation.

**Validation:** `test_sql_injection_does_not_bypass_login` submits a local test string and expects 401. `test_valid_credentials_still_work` checks that the fix preserves valid login behavior. Tests provided, not yet executed.

## F02: Insecure password storage
**Location:** `init_db()` in the vulnerable file, the password column and the inserted shared demo credential; `login()` compares the submitted password in SQL.

**Impact:** anyone who obtains the database can read passwords directly. A reused hardcoded credential gives every copy of the specimen the same known password. Database disclosure itself was not demonstrated.

**Remediation:** `generate_password_hash()` stores a salted password hash; `check_password_hash()` verifies a candidate. The corrected app prompts for a local dummy password at first startup instead of embedding one. It uses a separate database to avoid mistaking legacy plaintext values for hashes. A real migration must remove old plaintext copies and force password resets where exposure is possible. Do not use reversible encryption or a fast unsalted hash for passwords.

**Validation:** `test_password_not_stored_as_plaintext` checks the stored value differs and still verifies correctly. The test fixture directly seeds a hash; separately check the first-start password prompt and database on your laptop. No production database migration is included.

## F03: Reflected XSS
**Location:** `greet()` in the vulnerable file, `return f"<h1>Hello, {name}</h1>"`.

**Data flow:** URL query parameter → HTML response without escaping. Flask serves a returned string as HTML, so user-supplied markup can be interpreted by the browser.

**Impact:** if someone can persuade a victim to visit a crafted greeting URL, injected markup/script could execute in that application's origin. This specimen has no session cookie; theft of a session is not asserted.

**Remediation:** pass the name as data into a constant Jinja template: `render_template_string("<h1>Hello, {{ name }}</h1>", name=name)`. Autoescaping handles this HTML text context. Never interpolate the input into template source and never mark it safe. The added restrictive Content Security Policy is defense in depth, not a substitute for escaping.

**Validation:** `test_html_is_escaped` checks that a script-tag test value is escaped in the response. A browser check remains necessary to confirm rendered behavior.

## F04: Debug mode
**Location:** the vulnerable file's `app.run(..., debug=True)`.

**Impact:** debug tracebacks can expose implementation details; an exposed interactive debugger is unsafe. The current loopback-only binding reduces remote exposure. Exposure on a public interface, proxy, tunnel or shared host would increase risk; it was not demonstrated here.

**Remediation:** explicit `debug=False`, retain loopback binding for the local demonstration, and use an appropriate production WSGI server for any actual deployment. Do not enable Flask debug mode through environment variables or CLI flags in production.

**Validation:** inspect the corrected startup block and check `app.debug` in the regression suite. The test-client check does not exercise startup itself; manually start the corrected file and confirm there is no active debugger.

## Additional hardening implemented
- Request-body size limit and input-length checks to constrain oversized input.
- Generic invalid-credentials responses.
- `nosniff`, restrictive CSP and no-store response headers.
- Separate demo databases and ignored database files.

## Remaining work before production
The corrected specimen is not a complete production login service. Add rate limits, abuse monitoring, secure event logging without secrets, HTTPS, dependency scanning and tested version locking. Mitigate timing-based account enumeration if relevant; the current unknown-user path skips password hashing. If adding sessions, protect state-changing actions against CSRF, configure secure cookies, implement session lifecycle controls and apply authorization to protected routes. The current endpoint creates no session and performs no authenticated state change. Provision secrets outside source if future features require them. Review CSP if adding scripts, forms or other assets.

## Verification record
| Check | Status |
| --- | --- |
| Manual source inspection | Completed |
| Source remediation review | Completed |
| Python execution and regression tests | Not run in preparation environment |
| Bandit static analysis | Optional commands supplied; not run |
| Browser verification | Not run |

Record the date, Python/dependency versions, actual test output and any remaining failures after running locally. Do not describe fixes as fully verified until those checks pass.

## Secure coding practices
Treat external data as untrusted; parameterize SQL; encode output for its context; hash passwords with a maintained password-hashing function; disable debug features in deployment; enforce bounded input; minimize information in error responses; keep dependencies updated; review security-sensitive changes; test both attack resistance and normal behavior.

## References
- Python sqlite3 parameter substitution: https://docs.python.org/3/library/sqlite3.html
- Werkzeug password hashing: https://werkzeug.palletsprojects.com/en/stable/utils/
- Flask web security: https://flask.palletsprojects.com/en/stable/web-security/
- Flask debugger guidance: https://flask.palletsprojects.com/en/stable/debugging/

Sources consulted 19 November 2026.
