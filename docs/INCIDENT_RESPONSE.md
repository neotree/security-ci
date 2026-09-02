# CI security finding incident response

When **PR Malware Gate**, Gitleaks, OSV, Semgrep, CodeQL, the dependency audit, or the post-build scanner fails:

1. Do **not** run the branch locally in an IDE, and do not install its dependencies with lifecycle scripts enabled.
2. Do not add a `security-reviewed:<sha>` label merely to make the pipeline green. That label is for legitimate security-control changes, not finding suppression.
3. Inspect the finding from the GitHub Actions log using the file/rule name, and from the uploaded `*-report` artifact on the run (JSON + SARIF, retained 14 days). Findings also appear in the repository's **Security → Code scanning** tab. The custom scanner intentionally does not print suspect payload contents or secrets.
4. For a malware/obfuscation finding, review the entire PR diff and Git history, not only the flagged line. Check configuration/entry-point files, `.vscode`, assets/fonts, package manifests, lockfiles, and workflow files.
5. If malware may have executed on a developer workstation or runner, rotate credentials/tokens that were accessible to that environment, invalidate sessions, and rebuild from a known-clean state.
6. If Git history was force-pushed or rewritten unexpectedly, compare against a known trusted remote/commit and audit repository events.
7. Remove malicious dependencies/artifacts, regenerate the lockfile from trusted manifests, and rerun the full CI suite.
8. For dependency vulnerabilities, upgrade or remove the affected package.

Never "fix" a red security gate by disabling the scanner in the same pull request.

## Triaging a suspected false positive

The scanner distinguishes *blocking* findings (CRITICAL/HIGH) from *advisory* ones (MEDIUM/LOW/INFO). Advisory findings are printed and annotated but do not fail the build; they need no exception.

For a blocking finding you believe is wrong:

1. **Prefer fixing the code.** Most blocking rules describe a pattern that is genuinely worth avoiding.
2. **If the rule itself is wrong**, fix the rule in `security/scan_repo.py` and add a regression test to `security/tests/`. A rule that misfires once will misfire again for someone else.
3. **If the risk is real but accepted**, add a declarative exception to `security/policy.json`:

   ```json
   {
     "rule": "DYNAMIC_CODE_EXECUTION",
     "paths": ["app/(ops)/conditional-exp/_eval.ts"],
     "reason": "Why this is acceptable, and what would remove the need for it.",
     "expires": "2027-03-01"
   }
   ```

   Exceptions are validated on every run. An entry without a meaningful `reason`, without an `expires` date, or naming a non-exemptible rule is itself a **critical** finding. An expired entry stops suppressing and raises `EXCEPTION_EXPIRED`, which is the intended prompt to re-review the risk rather than let it drift indefinitely.

   An exception **downgrades** a finding to INFO and annotates it with the reason. It never deletes it, so the accepted risk stays visible in every report.

4. Some rules can never be excepted — direct evidence of compromise (`POLINRIDER_IOC`, `KNOWN_MALICIOUS_PACKAGE`, `DOWNLOAD_EXECUTE`, `DECODE_AND_EXECUTE`), and the controls that keep the gate honest (`SECURITY_CONTROL_CHANGE`, `UNPINNED_ACTION`, `SYMLINK`, …). See `NON_EXEMPT_RULES` in `security/scan_repo.py`. Attempting to except one is reported as `EXCEPTION_INVALID`.

Because exceptions live under `security/`, changing them is itself a security-control change and requires Code Owner review plus a commit-bound `security-reviewed:<head-sha7>` label.
