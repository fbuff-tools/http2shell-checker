# HTTP2Shell checker (CVE-2026-111497)

Check whether Node.js, Bun, Python Brotli packages or the Brotli library on your servers are affected by **HTTP2Shell**, also called **Node2Shell** (CVE-2026-111497), and which version fixes it.

**Paste a version in the browser instead:** https://fbuff.com/tools/http2shell-checker/ (runs locally, nothing is uploaded)

## What it is

HTTP2Shell is an out-of-bounds write in Google's Brotli decoder, versions 1.0.3 to 1.2.0. Any program that decompresses attacker-supplied Brotli data with an affected decoder can crash, leak memory or possibly run code. Google rates it 9.2 (critical) on CVSS 4.0. Despite the name, it is a bug in the Brotli decoder, not in the HTTP/2 protocol, and it is not limited to Node.js.

You are exposed if your software decodes Brotli from an untrusted source:

- **Inbound:** a server decompresses request bodies sent with `Content-Encoding: br` (for example Express 5, whose body-parser 2.x decodes `br` by default).
- **Outbound:** an HTTP client decodes `br` responses from servers you don't control (Node.js and Bun `fetch()`, Python requests, urllib3, httpx and aiohttp when a Brotli package is installed).

## Fixed versions

| Software | Fixed in |
|---|---|
| Node.js 22 / 24 / 26 | 22.23.4 / 24.22.1 / 26.12.1 |
| Node.js 20, 23, 25 and older | No fix (end of life) |
| Bun | 1.4.4 |
| Python Brotli / brotlicffi | 1.2.1 / 1.2.1.0 |
| Google Brotli library | 1.0.10, 1.1.1, 1.2.1 |
| Debian 12 / 13 (libbrotli1) | 1.0.9-2+deb12u1 / 1.1.0-2+deb13u1 |

## Check from the command line

```sh
curl -fsSLO https://raw.githubusercontent.com/fbuff-tools/http2shell-checker/main/check.sh
sh check.sh
```

The script reads `node --version`, `bun --version`, `pip show Brotli brotlicffi` and the Debian `libbrotli1` package, prints a verdict for each, and exits with 1 if anything needs updating, so it can fail a CI job. It only reads versions; nothing is sent or changed. Read it before running it: it is about 90 lines of `sh`.

Run it inside each container image, CI runner and serverless runtime, not only on the host. A tag such as `node:24` does not tell you the patch number.

## If you can't update yet

- Reject requests whose `Content-Encoding` contains `br` at the reverse proxy, or turn off request decompression (`express.json({ inflate: false })`).
- For outbound requests to untrusted URLs, turn off automatic decompression (Bun: `fetch(url, { decompress: false })`), or uninstall Brotli and brotlicffi in Python.

These reduce the risk; they do not replace the update.

## Sources

- [Node.js October 2026 security releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [CVE-2026-111497](https://www.cve.org/CVERecord?id=CVE-2026-111497)
- [Google Brotli releases](https://github.com/google/brotli/releases)
- [GHSA-9v8h-qqgm-4m35 (Python Brotli, brotlicffi)](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)
- [Bun advisory GHSA-663w-cv8g-jj2p](https://github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p)
- [Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497)

Related: [PHP2Shell checker](https://github.com/fbuff-tools/php2shell-checker) for CVE-2026-109618 / CVE-2026-109619 in PHP.

Information as of October 24, 2026. MIT license. Made by [fbuff](https://fbuff.com).
