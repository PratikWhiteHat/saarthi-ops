"""Tool-adapter catalog: named security tools with command templates.

A ``tool`` step can reference an adapter by name (``with: {tool: subfinder,
target: ...}``) instead of a raw ``cmd``. Templates use ``{param}`` placeholders
filled from the step's ``with`` params; unknown placeholders resolve to empty.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolAdapter:
    name: str
    binary: str
    category: str
    template: str
    description: str = ""
    install: str = ""


_ADAPTERS: tuple[ToolAdapter, ...] = (
    # --- subdomain discovery ---
    ToolAdapter("subfinder", "subfinder", "subdomain",
                "subfinder -d {target} -silent", "Passive subdomain enumeration",
                "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ToolAdapter("amass", "amass", "subdomain",
                "amass enum -passive -d {target}", "OWASP Amass subdomain enum"),
    ToolAdapter("assetfinder", "assetfinder", "subdomain",
                "assetfinder --subs-only {target}", "Find related domains/subdomains"),
    ToolAdapter("findomain", "findomain", "subdomain",
                "findomain -t {target} -q", "Fast subdomain finder"),
    # --- dns / resolution ---
    ToolAdapter("dnsx", "dnsx", "dns",
                "dnsx -l {input} -silent -a -resp", "DNS resolver/toolkit",
                "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    ToolAdapter("puredns", "puredns", "dns",
                "puredns resolve {input} -q", "Mass DNS resolver"),
    # --- http probing ---
    ToolAdapter("httpx", "httpx", "http",
                "httpx -l {input} -silent -status-code -title -tech-detect",
                "Live-host & HTTP metadata probe",
                "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    # --- crawling / urls ---
    ToolAdapter("katana", "katana", "crawl",
                "katana -u {target} -silent -jc", "Fast web crawler",
                "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ToolAdapter("gau", "gau", "urls",
                "gau {target}", "Fetch known URLs (AlienVault/Wayback/CommonCrawl)"),
    ToolAdapter("waybackurls", "waybackurls", "urls",
                "waybackurls {target}", "Fetch URLs from the Wayback Machine"),
    ToolAdapter("gospider", "gospider", "crawl",
                "gospider -s {target} -q", "Web spider"),
    # --- ports ---
    ToolAdapter("naabu", "naabu", "ports",
                "naabu -host {target} -silent", "Fast port scanner",
                "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ToolAdapter("nmap", "nmap", "ports",
                "nmap -sV -Pn {target}", "Network mapper / service detection"),
    # --- content discovery ---
    ToolAdapter("ffuf", "ffuf", "fuzzing",
                "ffuf -u {target}/FUZZ -w {wordlist} -mc 200,301,302,403",
                "Web content fuzzer"),
    ToolAdapter("gobuster", "gobuster", "fuzzing",
                "gobuster dir -u {target} -w {wordlist} -q", "Directory brute-forcer"),
    # --- vuln scanning ---
    ToolAdapter("nuclei", "nuclei", "vuln",
                "nuclei -u {target} -silent -jsonl", "Template-based vuln scanner",
                "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ToolAdapter("dalfox", "dalfox", "vuln",
                "dalfox url {target} --silence", "XSS scanner"),
    ToolAdapter("sqlmap", "sqlmap", "vuln",
                "sqlmap -u {target} --batch --level 1 --risk 1", "SQL injection scanner"),
    # --- SAST / SARIF ---
    ToolAdapter("semgrep", "semgrep", "sast",
                "semgrep scan --sarif --output {output} {target}",
                "Static analysis (SARIF output)", "pipx install semgrep"),
    ToolAdapter("trivy", "trivy", "sast",
                "trivy fs --format sarif --output {output} {target}",
                "Vuln/misconfig/secret scanner (SARIF output)"),
    ToolAdapter("cdncheck", "cdncheck", "classify",
                "cdncheck -i {input}", "CDN/WAF/cloud IP classification",
                "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"),
    # --- takeover / misc ---
    ToolAdapter("subjack", "subjack", "takeover",
                "subjack -w {input} -ssl", "Subdomain takeover check"),
    ToolAdapter("gf", "gf", "utility",
                "gf {pattern} {input}", "Grep-with-patterns for URLs"),
    ToolAdapter("anew", "anew", "utility",
                "anew {output}", "Append only new unique lines"),
    # --- more subdomain discovery ---
    ToolAdapter("chaos", "chaos", "subdomain",
                "chaos -d {target} -silent", "ProjectDiscovery Chaos dataset subdomains",
                "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest"),
    ToolAdapter("shuffledns", "shuffledns", "subdomain",
                "shuffledns -d {target} -w {wordlist} -r {resolvers} -silent",
                "Mass DNS bruteforce/resolve wrapper (massdns)",
                "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"),
    ToolAdapter("dnsgen", "dnsgen", "subdomain",
                "dnsgen {input}", "Generate permutation subdomain candidates",
                "pipx install dnsgen"),
    ToolAdapter("github-subdomains", "github-subdomains", "subdomain",
                "github-subdomains -d {target}", "Subdomains from GitHub code search",
                "go install github.com/gwen001/github-subdomains@latest"),
    ToolAdapter("massdns", "massdns", "dns",
                "massdns -r {resolvers} -t A -o S {input}", "High-perf DNS stub resolver"),
    ToolAdapter("dnsvalidator", "dnsvalidator", "dns",
                "dnsvalidator -tL {input} -threads 20 -o {output}",
                "Build a validated resolver list", "pipx install dnsvalidator"),
    ToolAdapter("tlsx", "tlsx", "dns",
                "tlsx -l {input} -silent -san -cn -resp-only",
                "TLS cert grabbing / SAN extraction",
                "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"),
    ToolAdapter("asnmap", "asnmap", "dns",
                "asnmap -d {target} -silent", "Map an org/domain to its ASN CIDRs",
                "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"),
    ToolAdapter("mapcidr", "mapcidr", "dns",
                "mapcidr -cidr {target} -silent", "Expand/aggregate CIDR ranges",
                "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"),
    # --- more crawling / urls ---
    ToolAdapter("hakrawler", "hakrawler", "crawl",
                "hakrawler -u {target}", "Fast endpoint crawler",
                "go install github.com/hakluke/hakrawler@latest"),
    ToolAdapter("waymore", "waymore", "urls",
                "waymore -i {target} -mode U -oU {output}",
                "Deep archived-URL fetcher (Wayback/CommonCrawl/URLScan/VT)",
                "pipx install waymore"),
    ToolAdapter("unfurl", "unfurl", "utility",
                "unfurl {mode}", "Pull components (domains/paths/keys) out of URLs",
                "go install github.com/tomnomnom/unfurl@latest"),
    ToolAdapter("httprobe", "httprobe", "http",
                "httprobe", "Probe for working http/https servers (stdin)",
                "go install github.com/tomnomnom/httprobe@latest"),
    # --- fingerprint / tech ---
    ToolAdapter("whatweb", "whatweb", "classify",
                "whatweb --no-errors {target}", "Web technology fingerprinter"),
    ToolAdapter("wafw00f", "wafw00f", "classify",
                "wafw00f {target}", "WAF detection", "pipx install wafw00f"),
    # --- content discovery ---
    ToolAdapter("feroxbuster", "feroxbuster", "fuzzing",
                "feroxbuster -u {target} -w {wordlist} -q", "Recursive content discovery"),
    ToolAdapter("arjun", "arjun", "fuzzing",
                "arjun -u {target} -oJ {output}", "HTTP parameter discovery",
                "pipx install arjun"),
    # --- vuln / takeover / oob ---
    ToolAdapter("subzy", "subzy", "takeover",
                "subzy run --targets {input}", "Subdomain takeover verifier",
                "go install github.com/PentestPad/subzy@latest"),
    ToolAdapter("interactsh-client", "interactsh-client", "vuln",
                "interactsh-client -json", "OOB interaction server client (SSRF/RCE)",
                "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    ToolAdapter("notify", "notify", "utility",
                "notify -silent", "Stream results to chat channels (stdin)",
                "go install github.com/projectdiscovery/notify/cmd/notify@latest"),
    ToolAdapter("gowitness", "gowitness", "utility",
                "gowitness scan file -f {input}", "Screenshot web hosts"),
)

TOOL_ADAPTERS: dict[str, ToolAdapter] = {adapter.name: adapter for adapter in _ADAPTERS}


def render_adapter_command(name: str, params: dict) -> str:
    """Render an adapter's template with ``{param}`` values from ``params``.

    Extra tokens listed under ``args`` are appended. Raises KeyError-free:
    unknown placeholders become empty strings.
    """

    adapter = TOOL_ADAPTERS.get(name)
    if adapter is None:
        raise ValueError(f"unknown tool adapter {name!r}")

    class _Blank(dict):
        def __missing__(self, key: str) -> str:  # noqa: D401
            return ""

    command = adapter.template.format_map(_Blank(params))
    extra = params.get("args")
    if isinstance(extra, list) and extra:
        command = command + " " + " ".join(str(token) for token in extra)
    elif isinstance(extra, str) and extra.strip():
        command = command + " " + extra.strip()
    return command.strip()


def adapter_catalog() -> list[dict]:
    """Metadata for the API/UI (includes plugin-registered adapters)."""

    return [
        {
            "name": a.name,
            "binary": a.binary,
            "category": a.category,
            "description": a.description,
            "install": a.install,
        }
        for a in TOOL_ADAPTERS.values()
    ]
