# Cros third-party engine notices

Cros includes local copies of these open-source username-search engines and
their Python dependencies inside the ABI-specific `engine_deps` runtime folder:

- Blackbird — GPL-3.0: https://github.com/p1ngul1n0/blackbird
- Sherlock Project 0.16.0 — MIT: https://github.com/sherlock-project/sherlock
- Maigret 0.6.3 — MIT: https://github.com/soxoj/maigret

Each project remains the work of its respective authors. Cros launches these
engines locally and converts their public-profile output into in-app result
cards. Their own license and metadata files are retained in the bundled Python
package directories where supplied by the package distributor.
