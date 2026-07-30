# Spring Boot Exposure Scanner v1.9.0 Fixed

Built as a Manifest V3 Chrome extension.

## Dataset
- Uploaded source: springboot_extended.txt
- Source lines: 1064
- Non-comment active entries: 946
- Unique active entries used by the scanner: 915
- The complete source wordlist is preserved in `wordlist.txt` and embedded into `wordlist.js`.

## Modes
- Automatic scan: Smart priority by default.
- Manual Scan Priority: probes a prioritized subset.
- Full wordlist: scans the bundled dataset with template expansion and deduplication.

## Detection
The scanner combines:
- HTTP status and content type
- Spring Boot / Actuator JSON signatures
- environment/config/bean/mapping/thread dump signatures
- Prometheus and OpenAPI/Swagger signatures
- Jolokia signatures
- passive DOM/resource fingerprinting

## Safety
The uploaded wordlist includes state-changing HTTP methods and advanced bypass strings.
For safety and reliability, the scanner only EXECUTES GET, HEAD and OPTIONS. The original
entries remain bundled verbatim for auditability. State-changing methods are not sent.

Large or high-impact response classes (e.g. heapdump/logfile) are read as a capped stream
and aborted once the configured body limit is reached.

## Install locally
1. Extract the ZIP.
2. Open `chrome://extensions`.
3. Enable Developer mode.
4. Click "Load unpacked".
5. Select the extracted folder.

Requires an HTTP(S) page as the active tab.

## Notes
Host permissions are intentionally broad so the service worker can perform cross-origin
fetches against the active HTTP(S) host. Restrict the installed extension to authorized
targets and bug-bounty scope.

Extension architecture follows Manifest V3: service worker + content script + local assets.


## v1.9.0 reliability fix

The original implementation could silently report zero findings when service-worker
`fetch()` failed. The fixed version:
- probes same-origin targets through the active tab's content-script bridge;
- falls back to service-worker `fetch()` for other origins/ports;
- records transport errors instead of silently dropping them;
- inspects the currently visible page and creates a finding when it is itself an
  accessible Spring Boot/Actuator/management endpoint.

This is particularly important for HTTPS pages that the browser can already display
but which may not be reproducible by an independent extension-network request.


## v1.9.0 Browser probe

When passive fingerprinting suggests Spring Boot, the scanner force-prioritizes a core
smoke-test set including `/actuator`, `/actuator/health`, `/actuator/env`, `/actuator/beans`,
`/actuator/mappings`, `/actuator/metrics`, `/actuator/prometheus`, Swagger/OpenAPI paths,
and common root aliases.

For same-origin HTTPS targets, the scanner now has a third transport:
**content-script fetch -> invisible same-origin iframe/browser navigation -> service-worker fetch**.

The iframe/browser navigation path exists specifically to handle cases where the active
Chrome tab can render a target after the user has accepted its TLS certificate but an
independent extension network fetch cannot reproduce the connection.


## v1.9.0 — Technology Detection Alert

The complete bundled wordlist is preserved unchanged.

A lightweight passive technology detector now runs automatically on every HTTP(S) page
covered by the content script. It checks for strong Spring Boot indicators including:
- Whitelabel Error Page
- Spring Boot default error fallback text
- Spring Boot default error response format
- `org.springframework.boot`
- `org.springframework.web`
- visible `Spring Boot` markers
- SpringDoc / Swagger markers
- `/actuator` references
- Actuator-style `_links` JSON
- common Spring Framework runtime markers

When a strong fingerprint is found, the page receives a small red **SPRING BOOT DETECTED**
alert in the top-right corner and the extension toolbar badge changes to `SB` on a red
background.

The alert is intentionally passive: it does not make requests merely to display the
technology alert. Endpoint scanning remains controlled by the existing automatic/manual
scan settings.


## v1.9.0 — UI + sensitive data detection

### UI
- Popup font-size setting: Small / Medium / Large / Extra large.
- Red Spring Boot in-page alert now dismisses immediately on pointer/click.
- Popup includes a separate Secrets / Sensitive Configuration panel.

### Sensitive-data detector
The scanner can inspect text captured from endpoint responses and flag patterns such as:
- AWS access key IDs / secret-like configuration
- GitHub tokens
- Slack tokens
- PEM private-key markers
- JWTs
- Bearer / Basic authorization credentials
- Database URLs containing credentials
- password / secret / token / client-secret configuration
- Spring datasource credentials
- cloud credential configuration

Raw secret values are not displayed in the popup. Matches are redacted to a short
prefix/suffix and shown only as evidence context.

Heapdump/logfile/env/configprops/Jolokia-style paths receive a larger but still capped
response sample for secret scanning. Binary content is not fully downloaded.


## v1.9.0 — Toolbar-only UI

The large scanner popup has been removed from the extension action.

- Clicking the extension icon no longer opens the large scanner panel.
- Spring Boot technology detection is represented by a red `SB` toolbar badge.
- The badge clears while a new page is loading and returns when Spring Boot is detected.
- Extension options remain accessible from `chrome://extensions` -> Details -> Extension options.
- Font sizing is an explicit `fontSizePx` setting from 10–24 px.
- The complete endpoint wordlist and sensitive-data scanner remain intact.


## v1.9.0 — Mini toolbar popup

The extension action now opens a compact 340px popup rather than the previous large dashboard.

The compact popup shows:
- Spring Boot / unknown status
- current target
- finding count
- critical finding count
- secret count
- scan progress
- Scan Priority
- Full Wordlist
- Stop
- Settings
- Export JSON

The red `SB` toolbar badge remains the persistent technology indicator outside the popup.


## v1.9.0 — Modern full dashboard

The action popup has been redesigned as a scrollable modern dashboard instead of the
minimal UI.

It exposes:
- technology status, confidence and detection signals;
- active target, origin and protocol;
- automatic scan toggle and Smart/Full mode;
- Priority and Full Wordlist scan controls;
- live progress and phase;
- severity statistics;
- wordlist/request/transport diagnostics;
- detection-signal evidence;
- complete finding cards with status, method, content-type, timing, transport and excerpt;
- redacted secret/sensitive-configuration findings;
- current-page passive evidence;
- JSON/CSV export and settings access.

The full uploaded wordlist remains bundled unchanged.


## v1.9.0 — Font scaling fixed

The UI font-size preference now controls every explicit popup font-size declaration, not
only inherited body text. The settings page also uses explicit DOM references and shows
a live preview.

Default UI size is 16 px. Supported range: 12–24 px.

The popup width is 620 px and its scroll viewport is 900 px so larger typography remains
usable without losing the modern dashboard layout.
