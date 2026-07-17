# Cros OSINT Tool 8.0 — Complete Guide

## Starting the tool

Double-click **OPEN THIS - Cros OSINT Tool.cmd** on the Desktop. The local desktop app opens with a searchable index of every workflow. Click anywhere on a tool card to launch that exact tool in its own result window. Choose **Terminal Mode** when you want the original wings and number menus; in terminal mode, press `Ctrl+C` to stop the current session.

Desktop app controls:

- Press `Ctrl+K` to open global tool search.
- Use **Overview**, **Tool Index**, **Defense**, **Guide**, and **Sources** as full clickable navigation tabs.
- Select **Learn** on any tool card to open that tool's in-app lesson. The lesson covers purpose, requirements, safe steps, result interpretation, sources, and related tools.
- The **Guide** tab stays inside Cros. Use **Guided Paths** for complete investigations and **Sources** for official references. Mark lessons as learned to save local progress.
- Filter by OSINT, Advanced, Security, Local, Saved, or Recent workflows. Use **Save** on a card to build a personal tool shelf.
- Select the centered C emblem to spread the animated CROS wings and open the Wing Deck shortcuts.
- Open appearance settings to choose six presets or any custom interface color. You can also adjust glow strength, animation speed, wing visibility, particles, compact cards, card shape, and desktop grid density. These preferences stay on this computer.
- The live telemetry cards read local posture, process, TCP, and startup counts. Select **View Signal Details** for the underlying protection checks.
- Use the **Privacy Tunnel** panel to control the installed NordVPN client. Choose Quick Connect or a country, select **Connect**, and use **Disconnect** when finished. The panel reads only the local NordVPN service and tunnel adapter. Cros stores no VPN history and does not send your IP to an external checking service. Expand **How This Protects You** for the privacy boundary.
- Tools marked `ADMIN` can still open normally, but Windows may restrict details until the launcher is run as Administrator. Tools marked `CONFIRM` do not start a Defender scan until you approve it inside the tool window.

The main screen keeps the original 1–19 layout. Option 20 opens the advanced toolkit. Network-based tools require an internet connection. Loading bars reflect the real operation and finish when the request finishes.

Only investigate public information, your own accounts and systems, or targets you have permission to test. Treat every result as a lead that needs confirmation.

## Main tools

### 1. Username (Single)

Enter one username. Choose an export format or `none`. The account engine checks public profiles across many services.

Best use: start with the exact spelling seen on a known profile. Confirm matches through repeated avatars, biographies, locations, or linked websites. A matching username alone does not prove the same person owns both accounts.

### 2. Username (Combos)

Creates common variations such as prefixes, numbers, and `official`, then checks them.

Best use: run this after the exact username produces few results. Variations increase false positives, so verify each result carefully.

### 3. Search Email

Checks public services that expose safe account-discovery signals for an email address.

Best use: use an address you own or are authorized to investigate. Do not treat the presence of an account as proof of current ownership.

### 4. Breach Hunter

Opens Have I Been Pwned for the address you enter. The address is not saved by Cros OSINT Tool.

Best use: check your own address, then change reused passwords and enable multi-factor authentication. This does not reveal passwords.

### 5. Port Scanner

Checks up to 50 TCP ports on a system you own or are authorized to test.

Best use: begin with `22,80,443`. An open port only shows that something accepted a connection; it does not identify a vulnerability.

### 6. Website History

Opens the Wayback Machine timeline for a domain or URL.

Best use: compare old contact pages, company descriptions, usernames, and linked domains. Archive dates can differ from the date the content was written.

### 7. Google Dorking

Builds focused Google queries for a site, public files, exact mentions, or a custom query.

Best use: use `site` for domain-only results, `files` for public documents, and `mentions` for an exact phrase. Search results are public links; do not attempt to bypass access controls.

### 8. Pastebin Checker

Searches indexed paste-style sites for an exact public term.

Best use: search a domain, unique username, or your own email. Do not download or use credentials that may appear in public dumps.

### 9. URL Scraper

Downloads a public webpage and lists up to 100 unique links.

Best use: inspect link relationships, old subdomains, social profiles, documents, and redirects. JavaScript-generated links may not appear.

### 10. IP Lookup

Resolves a domain and reports whether the address is private or global, plus its reverse name.

Best use: distinguish private addresses from public infrastructure. A hosting IP usually belongs to a provider, not the website owner.

### 11. Subdomain Finder

Queries public certificate-transparency records for subdomains.

Best use: compare results with DNS and HTTP checks. Certificate records can be old and do not guarantee a host is still active.

### 12. WHOIS Lookup

Uses RDAP to show domain status and registration, update, and expiration dates when available.

Best use: build a domain timeline and identify the registrar. Privacy services often hide registrant details.

### 13. DNS Lookup

Lists IPv4 and IPv6 addresses returned by the system resolver.

Best use: compare addresses over time and check whether a domain uses a CDN. Results can change by location.

### 14. SSL Checker

Reads the live TLS certificate, issuer, and expiration date.

Best use: confirm the hostname, certificate issuer, and remaining validity. A valid certificate does not prove a site is trustworthy.

### 15. Photo / Face OSINT

Accepts a local image path or public image URL. Local scans report file type, dimensions, camera metadata, dates, embedded GPS, and SHA-256. It can open Google Lens and TinEye for free reverse-image and scene matching.

Best use: preserve the original file because social sites often remove metadata. If GPS exists, verify it against visible landmarks. Without GPS, compare buildings, road signs, terrain, language, weather, and matching source pages. The tool does not identify a private person by their face.

### 16. Hash Generator

Generates MD5, SHA-1, SHA-256, and SHA-512 for text.

Best use: use SHA-256 or SHA-512 for modern integrity records. MD5 and SHA-1 remain useful only for comparing legacy identifiers.

### 17. Change Color

Sets the wing/title color and one shared perimeter color for all three boxes.

Best use: choose `red` wings with `cyan`, `white`, or `red` boxes for a consistent theme. The selection is saved automatically.

### 18. About

Shows the version and scope of the tool.

### 19. Exit

Closes the program cleanly.

### 20. More Tools

Opens the advanced toolkit. It uses the same shared border color as the main screen.

### 21. Security Center

Opens a separate 50-tool defensive Windows security center with RAT/remote-access heuristics, process and persistence audits, Microsoft Defender scans, static file analysis, integrity baselines, secret and macro checks, firewall/network review, protection-posture checks, update history, Secure Boot/TPM, BitLocker, browser-extension review, Wi-Fi/proxy audits, failed sign-ins, network exposure, Windows shares, security-service health, installed-software inventory, hardening and recovery checks, and local report generation. Open the in-app Learning Center or choose Security Center option 24 for the full defensive workflow.

## Advanced toolkit

### 1. HTTP Headers

Reports status, server hints, content type, and common browser-security headers. Missing headers are findings to investigate, not automatic vulnerabilities.

### 2. Domain Overview

Combines DNS, HTTP, server, final URL, and TLS expiration into one fast snapshot.

### 3. Discovery Files

Checks `robots.txt`, `sitemap.xml`, and `.well-known/security.txt`. These files can reveal public site structure and the correct security contact.

### 4. URL Analyzer

Breaks a URL into scheme, host, port, path, and query fields, then flags basic structural warning signs. It cannot guarantee that a URL is safe.

### 5. Redirect Tracer

Shows every HTTP redirect and the final destination. Use it to inspect shortened links and unexpected cross-domain movement before opening a link normally.

### 6. Web Metadata

Extracts title, description, OpenGraph fields, canonical URL, final URL, and status. Useful for finding the intended page identity and preview image.

### 7. Email Header Scan

Reads a local `.eml` or text header file and summarizes routing IPs, Received hops, SPF, DKIM, and authentication fields. Headers can be forged; confirm important findings independently.

### 8. File Checksums

Calculates MD5, SHA-1, SHA-256, and SHA-512 for a local file. Record SHA-256 before and after moving evidence to verify that it did not change.

### 9. Password Helper

Generates a random local password or estimates basic strength. Password text stays on the computer. Use a password manager for storage.

### 10. Reverse DNS

Looks up the PTR hostname associated with an IP address. Missing PTR records are common.

### 11. CIDR Calculator

Shows network, prefix, mask, first/last address, size, and private/global status for IPv4 or IPv6 ranges.

### 12. Base64 Tools

Encodes or decodes Base64 text locally. Base64 is an encoding, not encryption.

### 13. Hash Identifier

Guesses possible hash algorithms from hexadecimal length. Multiple formats share the same length, so the result is not proof.

### 14. Timestamp Converter

Converts Unix timestamps and ISO dates to UTC and local time. Use UTC when building investigation timelines.

### 15. JSON Formatter

Pretty-prints JSON entered directly or loaded from a `.json` file. Useful for API and exported OSINT results.

### 16. Coordinate Helper

Validates latitude/longitude and can open Google Maps and OpenStreetMap. Latitude comes first.

### 17. Case Notes

Appends timestamped notes to `outputs/cases/<case-name>.md`. Use neutral case names and avoid recording unnecessary sensitive information.

### 18. Account Setup

Checks or repairs the optional account-search engine.

### 19. Diagnostics

Shows Python, engine, Git, and settings locations. Use this first when account searches fail.

### 20. Full Tutorial

Asks whether to open this guide. Choose `skip` to return immediately.

### 21. File Type Inspector

Compares a local file's extension and MIME guess with recognizable header bytes without executing or uploading the file. A mismatch is a reason to review the file, not proof that it is malicious.

### 22. IOC Normalizer

Cleans, classifies, and deduplicates mixed IP addresses, domains, URLs, and common hash shapes locally. Unknown values are preserved instead of forced into a category.

### 23. Text File Compare

Creates a bounded line-by-line comparison of two local text files. Use the older snapshot first and the newer snapshot second.

### 24. JWT Decoder

Decodes a JWT header and payload locally. It does not verify the signature, issuer, audience, expiry, or authorization, so decoded claims remain untrusted.

## Recommended workflows

### Username investigation

1. Run Username (Single).
2. Verify strong matches through repeated details.
3. Run Username (Combos) only if needed.
4. Use Google Dorking and Website History.
5. Save confirmed leads with Case Notes.

### Domain investigation

1. Run Domain Overview.
2. Check WHOIS, DNS, SSL, and Subdomain Finder.
3. Review Discovery Files and HTTP Headers.
4. Trace redirects and extract page metadata.
5. Use Website History for timeline changes.

### Photo and location investigation

1. Work from the original image.
2. Run Photo / Face OSINT and record SHA-256.
3. Check embedded GPS and capture time.
4. Use Lens and TinEye for older copies and source pages.
5. Compare visible landmarks and maps.
6. Record confidence and alternative locations; do not present a visual guess as fact.

### Suspicious link review

1. Run URL Analyzer without opening the link in a normal browser.
2. Run Redirect Tracer.
3. Review Web Metadata and HTTP Headers.
4. Confirm the final domain with WHOIS and Domain Overview.

### Email authenticity review

1. Save the full original email as `.eml`.
2. Run Email Header Scan.
3. Review routing IPs and authentication results.
4. Use IP Lookup and Reverse DNS on relevant public addresses.
5. Confirm with the sending organization through a known contact channel.
