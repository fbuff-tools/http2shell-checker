# HTTP2Shell checker (CVE-2026-111497)

Understand and check **HTTP2Shell**, also called **Node2Shell** (CVE-2026-111497): an out-of-bounds write in Google's Brotli decoder that reaches Node.js, Bun, Python, .NET and more. Find out where your software decodes Brotli without asking, and which version fixes it.

**Paste a version in the browser instead:** https://fbuff.com/tools/http2shell-checker/ (runs locally, nothing is uploaded)

## What causes it

Brotli is the compression behind `Content-Encoding: br`. A Brotli stream is cut into blocks; the stream says up front how many *block types* it uses, and can then tell the decoder to switch from one type to another. A stream that declares a single block type and then asks to switch is simply broken.

The decoder (`c/dec/decode.c`, Brotli 1.0.3 to 1.2.0) handled that case wrongly. The block-switch step only returned true or false, and the caller read *false* as "I need more input" instead of "this data is invalid". The streaming decoder kept waiting and kept appending each new input byte to an **eight-byte internal buffer**, past its end and into neighbouring memory (CWE-252 unchecked return value, CWE-787 out-of-bounds write). Attacker-chosen bytes written into neighbouring memory are how a crash becomes code execution.

Think of a clerk who finds a form that makes no sense, says "I'll wait for the rest", and keeps stapling every page that arrives into a folder with room for one.

**The fix** (Brotli commit `0ed4268`, released in 1.0.10, 1.1.1 and 1.2.1) makes the decoder stop with a format error on that switch; Node.js exposes it as `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`. Google rates it 9.2 (CVSS 4.0); Node.js rates it high. Despite the name, it has nothing to do with the HTTP/2 protocol.

## Where your software decodes Brotli without asking

- **Incoming requests.** Express 5 decodes Brotli request bodies through body-parser 2.x (`inflate` is on by default). Sysdig and Semgrep also list Koa (`co-body`, `@koa/bodyparser`, `koa-body`), Egg, Strapi and Fastify with `@fastify/compress`. A bare Node.js HTTP server and Express 4 do not decode Brotli bodies. nginx and Apache `mod_brotli` only compress responses.
- **Outgoing requests.** HTTP clients decode `br` responses on their own: Node.js `fetch()` does it whenever the response says `Content-Encoding: br`, even if you asked for `identity`; so do Bun `fetch()` and Python requests, urllib3, httpx and aiohttp when a Brotli package is installed. Webhooks, link previews and scrapers fetch URLs that others choose.
- **Elsewhere.** JFrog reached the same decoder from .NET (`HttpClient` automatic decompression, ASP.NET Core request decompression), FFmpeg through JPEG XL images, Apache Arrow and ClickHouse. Microsoft shipped an emergency .NET update.

## Is it being exploited?

Imperva got code execution on the official Node.js 24.22.0 image after several attempts and confirmed 24.22.1 rejects the same input. Most public proofs of concept only crash the process. Reports differ on real attacks: BleepingComputer said on October 26 that none were known; Sysdig wrote on October 28 that ELLIO had confirmed exploitation on October 26. Treat it as exploited.

## Fixed versions

| Software | Fixed in |
|---|---|
| Node.js 22 / 24 / 26 | 22.23.4 / 24.22.1 / 26.12.1 |
| Node.js 20, 23, 25 and older | No fix (end of life) |
| Bun | 1.4.4 |
| Python Brotli / brotlicffi | 1.2.1 / 1.2.1.0 |
| Google Brotli library | 1.0.10, 1.1.1, 1.2.1 |
| Debian 12 / 13 (libbrotli1) | 1.0.9-2+deb12u1 / 1.1.0-2+deb13u1 |

Node.js normally bundles its own Brotli, so updating the system library does not fix it (Debian's `nodejs` package is the exception: it uses the system `libbrotli1`). Bun binaries built with `bun build --compile` stay vulnerable until rebuilt.

## Check from the command line

```sh
curl -fsSLO https://raw.githubusercontent.com/fbuff-tools/http2shell-checker/main/check.sh
sh check.sh
```

The script reads `node --version`, `bun --version`, `pip show Brotli brotlicffi` and the Debian `libbrotli1` package, prints a verdict for each, and exits with 1 if anything needs updating, so it can fail a CI job. It only reads versions; nothing is sent or changed. Read it before running it: it is about 90 lines of `sh`.

Run it inside each container image, CI runner and serverless runtime, not only on the host. A tag such as `node:24` does not tell you the patch number.

## Ways to protect your apps

1. **Patch.** Update the runtime or package, restart every process, rebuild and redeploy images on a patched base image.
2. **Close the inbound path.** Reject requests whose `Content-Encoding` contains `br` at the reverse proxy, or turn off request decompression (`express.json({ inflate: false })`, which also rejects gzip bodies: test clients first).
3. **Close the outbound path.** Removing `br` from `Accept-Encoding` is not enough; a malicious server can send Brotli anyway. Turn off decompression for untrusted URLs (Bun: `fetch(url, { decompress: false })`) or uninstall Brotli and brotlicffi in Python until you update.
4. **Limit the damage and watch.** Run Node.js as an unprivileged user, keep secrets out of its environment, and alert when a Node or Python process crashes during decompression and then starts a shell or opens an unexpected connection.

Steps 2-4 reduce the risk; they do not replace the update.

## Sources

- [Node.js October 2026 security releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [CVE-2026-111497](https://www.cve.org/CVERecord?id=CVE-2026-111497)
- [JFrog: Brotli2Shell, beyond Node2Shell and HTTP2Shell](https://research.jfrog.com/post/brotli2shell-beyond-node2shell-and-http2shell/)
- [Imperva: Node2Shell, from Brotli data to remote code execution](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)
- [Sysdig: Detecting the Node.js Brotli RCE](https://www.sysdig.com/blog/node2shell-cve-2026-111497-detecting-the-node-js-brotli-rce)
- [BleepingComputer: HTTP2Shell triggers emergency patches](https://www.bleepingcomputer.com/news/security/critical-http2shell-brotli-vulnerability-triggers-emergency-patches/)
- [Google Brotli releases](https://github.com/google/brotli/releases)
- [GHSA-9v8h-qqgm-4m35 (Python Brotli, brotlicffi)](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)
- [Bun advisory GHSA-663w-cv8g-jj2p](https://github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p)
- [Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497)

Related: [PHP2Shell checker](https://github.com/fbuff-tools/php2shell-checker), [KSMBD checker](https://github.com/fbuff-tools/ksmbd-checker), [CVE-2026-98432 checker](https://github.com/fbuff-tools/cve-2026-98432-checker).

Information as of October 30, 2026. MIT license. Made by [fbuff](https://fbuff.com).
