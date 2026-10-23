Extracting Mozilla's Root Certificates
======================================

When people need a list of root certificates, they often turn to Mozilla's. However, Mozilla doesn't produce a nice list of PEM encoded certificates, rather they keep them in a form which is convenient for NSS to build from:

    https://raw.githubusercontent.com/mozilla-firefox/firefox/release/security/nss/lib/ckfw/builtins/certdata.txt

Several people have written quick scripts to try and convert this into PEM format, but they often miss something critical: some certificates are explicitly _distrusted_. These include the DigiNotar certificates and the misissued COMODO certificates. If you don't parse the trust records from the NSS data file, then you end up trusting these!

So this is a tool that I wrote for converting the NSS file to PEM format which is also aware of the trust records. Only certificates whose trust records mark them as trusted for issuing TLS server certificates (`CKA_TRUST_SERVER_AUTH` = `CKT_NSS_TRUSTED_DELEGATOR`) are included, so the output is suitable for use as a TLS client's root store. Roots that Mozilla only trusts for S/MIME are excluded.

To use it, install Go (<https://go.dev/dl/>) and then:

    % curl -o certdata.txt https://raw.githubusercontent.com/mozilla-firefox/firefox/release/security/nss/lib/ckfw/builtins/certdata.txt
    % go run convert_mozilla_certdata.go > ca-bundle.pem

Flags:

* `-include-untrusted`: also emit certificates that are not trusted for TLS, marked with a `# NOT TRUSTED FOR SSL` comment.
* `-to-files`: write each certificate to an individual `.pem` file in the current directory instead of writing a bundle to stdout.
* `-ignore-list <file>`: skip certificates whose `CKA_LABEL` appears in the given file (one label per line, `#` starts a comment).
* `-write-pem-headers`: write metadata into the PEM headers of each block: `Label` (the `CKA_LABEL`), `Trust-ServerAuth` (`true` or `false`), and `Trust-ServerAuth-IssuedNotAfter` (the `CKA_NSS_SERVER_DISTRUST_AFTER` time in RFC 3339, only when set). A verifier that reads `Trust-ServerAuth-IssuedNotAfter` must reject a chain whose end-entity certificate has a `NotBefore` later than that time. The bound is inclusive, like X.509 `NotAfter`.

Time-based distrust
-------------------

Mozilla's root store now contains metadata that a PEM bundle cannot express. In particular, `CKA_NSS_SERVER_DISTRUST_AFTER` records a date after which certificates _issued_ by that root are no longer trusted for TLS, even though older certificates chaining to it remain valid. This tool emits that date as a comment above the affected certificate:

    # Server Distrust After: 2024-11-30T23:59:59Z

A plain PEM-based TLS client will still trust such roots unconditionally. If your TLS stack can enforce issuance-date-based distrust, you should parse these comments (or certdata.txt itself); otherwise be aware that this is a small fidelity gap between this output and what Firefox actually enforces.
