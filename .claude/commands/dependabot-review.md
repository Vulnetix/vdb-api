# Dependabot Security Alert Review

You are helping review and resolve Dependabot security alerts for this repository.

## Your Task

1. **Fetch Dependabot Alerts**: Use `gh api` to get the list of open Dependabot security alerts:
   - Endpoint: `/repos/:owner/:repo/dependabot/alerts`
   - Filter for state=open
   - Parse the JSON response to extract alert details

2. **For Each Alert** (process one at a time):

   a. **Display Alert Information**:
      - Alert number and severity
      - Vulnerable package name and current version
      - CVE/GHSA identifier
      - Vulnerability description
      - Recommended fixed version(s)

   b. **Check Current Status in yarn.lock**:
      - Read `yarn.lock` to verify the actual installed version
      - Check if the package has already been updated to a safe version
      - **If already resolved**:
        - Explain in detail why (package version in yarn.lock is already patched)
        - Automatically dismiss the alert with a comprehensive rationale
        - **REQUIRED**: Always include a detailed dismissed_comment explaining:
          - Current version in yarn.lock
          - Why this version is not vulnerable
          - The vulnerability that was addressed
        - Use: `gh api --method PATCH /repos/:owner/:repo/dependabot/alerts/{alert_number} -f state=dismissed -f dismissed_reason=no_bandwidth -f dismissed_comment="Package already updated to safe version X.Y.Z in yarn.lock, which addresses CVE-XXXX-YYYY by [specific fix]. Alert is stale."`
      - **If not resolved**: Continue to step c

   c. **Attempt Resolution** (if package needs updating):
      - Try `yarn upgrade <package>` or `yarn upgrade <package>@<safe-version>` to update
      - Run `yarn install` to ensure lock file is updated
      - Verify the update by checking `yarn.lock` again
      - Confirm the new version addresses the vulnerability
      - If update succeeds, proceed to validation (step d)
      - **If update fails or no patch available**: Proceed to step e for deep analysis

   d. **Validation** (after successful update):
      - Check if tests exist and offer to run them
      - Verify the application still builds (`yarn build` or similar)
      - Look for any breaking changes in the package's changelog if the update is major/minor
      - If validation passes, mark as resolved

   e. **Deep CVE Analysis** (if yarn update cannot resolve):
      - Extract CVE identifier from the alert (e.g., CVE-2024-1234)
      - Use MITRE CVE API to fetch detailed vulnerability information:
        - Endpoint: `https://cveawg.mitre.org/api/cve/{CVE_ID}`
        - Extract: Description, CVSS score, affected versions, references
      - Use NVD API for additional context:
        - Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE_ID}`
      - **Enter Planning Mode** using the Task tool with subagent_type=Plan:
        - Analyze the CVE details thoroughly
        - Identify root cause and attack vectors
        - Research workarounds, patches, or alternative approaches
        - Check if this is a transitive dependency issue
        - Investigate if parent packages need updating
        - Determine if code changes are needed to mitigate
        - Provide actionable recommendations

   f. **Report Results**:
      - Summarize what was done
      - Indicate if the vulnerability is resolved
      - **If resolved by update**:
        - **REQUIRED**: Always provide a detailed rationale including:
          - What vulnerability was fixed (CVE/GHSA ID)
          - Version upgraded from and to
          - What the fix addresses
        - Provide the dismiss command: `gh api --method PATCH /repos/:owner/:repo/dependabot/alerts/{alert_number} -f state=dismissed -f dismissed_reason=fix_started -f dismissed_comment="Fixed by upgrading from version A.B.C to X.Y.Z, which addresses CVE-XXXX-YYYY by [specific vulnerability description]. Verification: [build/test results]."`
      - **If stale/already fixed**:
        - Auto-dismiss with detailed reason explaining:
          - Current installed version
          - Why the alert is no longer applicable
          - What changed since the alert was opened
      - **If not resolved**:
        - Explain why (no patch available, breaking changes, transitive dependency)
        - Provide CVE analysis summary
        - Suggest next steps from planning mode analysis
        - If manual dismissal is needed, always provide rationale

3. **After Each Alert**:
   - Ask the user if they want to continue to the next alert
   - Keep track of which alerts have been processed
   - Provide a summary at the end

## Important Notes

- **ALWAYS provide a detailed rationale when dismissing alerts** - never dismiss without explanation
- Process alerts **one at a time** to avoid overwhelming changes
- Always verify changes against `yarn.lock` as the **source of truth**
- Auto-dismiss stale alerts that are already resolved in yarn.lock (with detailed rationale)
- Be cautious with major version updates - flag these for manual review
- If a package can't be updated directly (transitive dependency), use `yarn why <package>` to identify the parent package
- For complex cases with no clear patch, use the Task tool with Plan mode for deep analysis
- Do not automatically commit changes - let the user review first
- Use the TodoWrite tool to track progress through multiple alerts

## Dismissal Reasons

**CRITICAL**: Every dismissal MUST include a detailed `dismissed_comment` explaining the rationale.

Use these standard GitHub dismissal reasons:
- `fix_started` - When you've applied an update that fixes the issue
  - Rationale must include: versions changed, CVE addressed, verification performed
- `no_bandwidth` - When alert is stale/already fixed
  - Rationale must include: current version, why it's safe, when/how it was fixed
- `tolerable_risk` - When risk is acceptable (use sparingly and only with approval)
  - Rationale must include: detailed risk assessment, why it's acceptable, mitigations in place
- `inaccurate` - When Dependabot alert is incorrect
  - Rationale must include: why the alert is wrong, evidence supporting this

**Never dismiss an alert without a comprehensive rationale.**

## Example gh API Commands

```bash
# List open alerts with details
gh api /repos/:owner/:repo/dependabot/alerts --jq '.[] | select(.state=="open") | {number, security_advisory: {ghsa_id, cve_id, severity, summary}, security_vulnerability: {package: .package.name, vulnerable_version_range, first_patched_version}}'

# Get specific alert details
gh api /repos/:owner/:repo/dependabot/alerts/{alert_number}

# Dismiss an alert (stale/already fixed)
gh api --method PATCH /repos/:owner/:repo/dependabot/alerts/{alert_number} -f state=dismissed -f dismissed_reason=no_bandwidth -f dismissed_comment="Package already at safe version 2.3.4 in yarn.lock. This version addresses CVE-2024-1234 by implementing input sanitization. Alert is stale as the upgrade occurred in commit abc123."

# Dismiss an alert (fixed by upgrade)
gh api --method PATCH /repos/:owner/:repo/dependabot/alerts/{alert_number} -f state=dismissed -f dismissed_reason=fix_started -f dismissed_comment="Fixed by upgrading package-name from 1.2.3 to 1.2.5, which addresses CVE-2024-5678 by patching the XSS vulnerability in render function. Verified: yarn build passed, all tests passing."
```

## CVE Research Commands

```bash
# Fetch CVE details from MITRE
curl -s "https://cveawg.mitre.org/api/cve/CVE-2024-1234" | jq '.cveMetadata, .containers.cna.descriptions, .containers.cna.affected'

# Fetch CVE details from NVD
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1234" | jq '.vulnerabilities[0].cve'
```

Start by fetching the current repository information and then retrieve the open Dependabot alerts.
