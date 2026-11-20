# Secure Coding Review

A manual security audit of a small Python Flask credential-checking and greeting application. Includes the deliberately vulnerable specimen, a remediated version, an audit report and security regression tests.

## Files
- `vulnerable_app.py`: local review specimen with intentional flaws.
- `remediated_app.py`: fixes for the documented findings.
- `AUDIT_REPORT.md`: scope, evidence, impact, recommendations and validation plan.
- `test_security.py`: regression tests for the corrected code.
- `requirements.txt`: application dependencies.
- `.gitignore`: excludes local databases, environments and generated reports.

## Windows setup
Open PowerShell in this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe remediated_app.py
```

Set a dummy password when prompted on first startup. Open http://127.0.0.1:5001/greet?name=Student to view the greeting. The database is initialized by running the file directly.

In another terminal, use a dummy password matching the one you set:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5001/login -Method Post -Body @{username='student'; password='YourDummyPasswordHere'}
```

The /login endpoint only checks credentials and returns JSON. It does not create a session or implement a complete authentication system.

## Run regression tests
Stop the server with Ctrl+C if using the same terminal, then run:

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_security.py
```

Tests use Flask's local test client and a temporary database. They do not send traffic to external systems.

## Optional static analysis
The submitted audit uses manual source inspection, which meets the task's method requirement. To supplement it with your own real tool output:

```powershell
.\.venv\Scripts\python.exe -m pip install bandit
.\.venv\Scripts\python.exe -m bandit vulnerable_app.py remediated_app.py -f json -o bandit-report.json
```

Bandit can exit nonzero when it finds issues. Review its output; static analysis does not prove absence of vulnerabilities and may not flag plaintext password storage or application-specific flaws. Do not invent scan results.

## Local comparison
If you need to demonstrate the original behavior, run `vulnerable_app.py` with the virtual-environment Python and use port 5000. Its dummy account is student / DemoPassword123!. Keep it bound to localhost and do not deploy the vulnerable version.

## GitHub
Upload the source files, requirements, tests, report, README and .gitignore. Do not upload databases or real passwords. This is a code review project, not a GitHub Pages website.

## Validation status
The code has been manually reviewed. Runtime tests and Bandit were not executed in the preparation environment because it lacked working Python. Run the supplied commands on your laptop and record actual results before claiming successful tests in your submission.
