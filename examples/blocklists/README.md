# blocklists

Everything in this directory is loaded by `cora-sentinel --blocklist examples/blocklists`.

- One **list per file**; the file name (without extension) becomes the list name in reports.
- Loaded extensions: none, `.txt`, `.list`, `.hosts`, `.domains`, `.cidr`, `.nets`, `.netset`, `.ipset`.
  This README and dotfiles are ignored.
- Per line: a CIDR, a single IP, a domain (matches its subdomains too), `*.domain`, a hosts-file
  line (`0.0.0.0 ads.example.com`), or an adblock-style `||ads.example.com^`.
- Rejected on load (counted in the startup summary): entries broader than /8 (v4) or /16 (v6),
  anything overlapping loopback or the unspecified address, and malformed lines.
- Domains match through **resolved addresses**, since sockets expose IPs, not hostnames. A domain
  on a shared CDN address can false-positive; put exceptions in `../allow/`.
