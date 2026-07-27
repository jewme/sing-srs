#!/usr/bin/env python3
"""
sing-box rule-set generator

Reads rule sources from sources.yaml (Clash lists / Clash YAML payloads /
JSON / SRS), converts them all to the sing-box rule-set JSON format,
deduplicates and sorts them, compiles to .srs, and optionally merges
multiple sources, filters by category, and extracts pure CIDR / domain
subsets.

Dependencies: pandas, requests, pyyaml, urllib3
Optional external command: sing-box (used for compile / decompile; the
script degrades gracefully to JSON-only output when it is not available)

sources.yaml format (full example in sources.example.yaml):
  sources:
    - name: ads          # required, becomes the output file name
      urls:                # required, 1 url is a single file, multiple are merged
        - https://example.com/ads1.list
        - https://example.com/ads2.list
      types: [domain, cidr]  # optional, keep only these categories; omit to keep all
      enabled: true          # optional, default true; set false to disable without deleting

Environment variables:
  SOURCES_FILE      Path to the source config file (defaults to searching
                    ./sources.yaml, ./sources.yml, and their parent directory)
  OUTPUT_DIR        Output directory (defaults to the current directory)
  MIN_SUCCESS_RATE  Success-rate threshold (0-1, default 0 disables the check).
                    For CI: if the actual success rate falls below this, the
                    script exits with a non-zero code so the run is marked
                    failed instead of publishing an incomplete rule-set.
  CLEANUP_STALE     Whether to delete old output files whose source has been
                    removed from the config (default true). This is judged by
                    "is it still in the config", not "did this run write it",
                    so a transient fetch failure never deletes good data; an
                    empty parsed config always skips cleanup as a safety net.
"""

import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import lru_cache
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --------------------------------------------------------------------------
# Constants & logging
# --------------------------------------------------------------------------

RULE_SET_VERSION = 3  # every output file uses this version number
USER_AGENT = "Mozilla/5.0"
REQUEST_TIMEOUT = 30
MAX_WORKERS = 4
SCRIPT_DIR = Path(__file__).parent

# Keywords that introduce a logical (AND/OR/NOT) rule line.
LOGICAL_KEYWORDS = ("AND", "OR", "NOT")

# Clash/Surge keyword -> sing-box field name.
# Sorted by key length descending so a longer keyword like DOMAIN-SUFFIX
# is preferred over its prefix DOMAIN when both could plausibly match.
MAP_DICT: Dict[str, str] = dict(sorted(
    {
        "DOMAIN-SUFFIX": "domain_suffix", "HOST-SUFFIX": "domain_suffix", "host-suffix": "domain_suffix",
        "DOMAIN-KEYWORD": "domain_keyword", "HOST-KEYWORD": "domain_keyword", "host-keyword": "domain_keyword",
        "DOMAIN-REGEX": "domain_regex", "URL-REGEX": "domain_regex",
        "DOMAIN": "domain", "HOST": "domain", "host": "domain",
        "IP-CIDR6": "ip_cidr", "IP6-CIDR": "ip_cidr", "IP-CIDR": "ip_cidr", "ip-cidr": "ip_cidr",
        "SRC-IP-CIDR": "source_ip_cidr",
        "SRC-PORT": "source_port", "DST-PORT": "port",
    }.items(),
    key=lambda kv: -len(kv[0]),
))
# Uppercase-normalized lookup table, used for case-insensitive matching
# when parsing logical rule conditions.
_MAP_LOOKUP: Dict[str, str] = {k.upper(): v for k, v in MAP_DICT.items()}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class Settings:
    sources_file: Path
    output_dir: Path
    max_workers: int = MAX_WORKERS
    timeout: int = REQUEST_TIMEOUT
    min_success_rate: float = 0.0  # 0 disables the check; CI typically wants ~0.8
    cleanup_stale: bool = True  # delete old json/srs whose source left the config

    @classmethod
    def from_env(cls) -> "Settings":
        env_sources = os.getenv("SOURCES_FILE")
        candidates = [
            Path(env_sources) if env_sources else None,
            SCRIPT_DIR.parent / "sources.yaml",
            SCRIPT_DIR / "sources.yaml",
            SCRIPT_DIR.parent / "sources.yml",
            SCRIPT_DIR / "sources.yml",
        ]
        sources_file = next((p for p in candidates if p and p.exists()), SCRIPT_DIR.parent / "sources.yaml")
        output_dir = Path(os.getenv("OUTPUT_DIR", os.getcwd()))
        min_success_rate = float(os.getenv("MIN_SUCCESS_RATE", "0") or "0")
        cleanup_stale = os.getenv("CLEANUP_STALE", "true").strip().lower() not in ("0", "false", "no")
        return cls(
            sources_file=sources_file, output_dir=output_dir,
            min_success_rate=min_success_rate, cleanup_stale=cleanup_stale,
        )


@dataclass
class Source:
    """A single rule source: 1 url is a standalone file, multiple urls get merged into one output"""
    name: str
    urls: List[str]
    types: Optional[List[str]] = None  # keep only these categories (domain/cidr/port); None = no filtering
    enabled: bool = True


# --------------------------------------------------------------------------
# HTTP client (thread-safe pooled-connection singleton)
# --------------------------------------------------------------------------

class HttpClient:
    """Thread-safe HTTP client with a pooled connection and a retry policy"""

    def __init__(self, timeout: int = REQUEST_TIMEOUT):
        self.timeout = timeout
        self._session: Optional[requests.Session] = None
        self._lock = threading.Lock()

    def _get_session(self) -> requests.Session:
        if self._session is None:
            with self._lock:
                if self._session is None:  # double-checked locking to avoid a race under concurrency
                    session = requests.Session()
                    retry = Retry(
                        total=3, backoff_factor=0.5,
                        status_forcelist=[429, 500, 502, 503, 504],
                        allowed_methods=["GET", "HEAD"],
                    )
                    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
                    session.mount("http://", adapter)
                    session.mount("https://", adapter)
                    self._session = session
        return self._session

    def get_text(self, url: str) -> str:
        resp = self._get_session().get(url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
        resp.raise_for_status()
        return resp.text

    def get_bytes(self, url: str) -> bytes:
        resp = self._get_session().get(url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout)
        resp.raise_for_status()
        return resp.content

    def close(self) -> None:
        if self._session:
            self._session.close()
            self._session = None


_http = HttpClient()


# --------------------------------------------------------------------------
# Address parsing & normalization
# --------------------------------------------------------------------------

def is_ip_address(value: str) -> bool:
    """Check whether a string is a valid IPv4/IPv6 address or network"""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


@lru_cache(maxsize=8192)
def normalize_address(address: str, rule_type: str) -> str:
    """Normalize an address for deduplication comparisons only (never affects the output's original form)"""
    address = address.strip()
    if "cidr" in rule_type:
        try:
            return str(ipaddress.ip_network(address, strict=False)).lower()
        except ValueError:
            return address.lower()
    if "domain" in rule_type:
        return address.lower()
    return address


def deduplicate_addresses(addresses: List[str], rule_type: str) -> List[str]:
    """Deduplicate by normalized value (keeping the original spelling of the first occurrence), sorted"""
    seen: set = set()
    unique: List[str] = []
    for addr in addresses:
        addr = str(addr).strip()
        key = normalize_address(addr, rule_type)
        if key not in seen:
            seen.add(key)
            unique.append(addr)
    return sorted(unique)


# --------------------------------------------------------------------------
# Rule source parsing: YAML payload / Clash list (including AND/OR/NOT logical rules)
# --------------------------------------------------------------------------

def _parse_yaml_payload(text: str) -> Optional[pd.DataFrame]:
    """Parse the Clash YAML payload format; returns None on an unexpected shape so the
    caller can fall back to CSV parsing instead of crashing"""
    data = yaml.safe_load(text)

    if isinstance(data, str):
        items = data.splitlines()[0].split() if data else []
    elif isinstance(data, dict):
        items = data.get("payload")
        if not isinstance(items, list):
            return None
    else:
        return None

    rows = []
    for raw_item in items:
        item = str(raw_item)
        address = item.strip("'")

        if "," in item:
            pattern, _, address = item.partition(",")
        elif is_ip_address(address):
            pattern = "IP-CIDR"
        elif address.startswith(("+", ".")):
            pattern, address = "DOMAIN-SUFFIX", address.lstrip("+.")
        else:
            pattern = "DOMAIN"

        address = address.strip()
        if address:
            rows.append({"pattern": pattern.strip(), "address": address, "other": None})

    return pd.DataFrame(rows, columns=["pattern", "address", "other"])


def _find_matching_paren(s: str, start: int) -> int:
    """s[start] must be '('. Returns the index of its matching ')', or -1 if the
    parentheses are unbalanced from that point on."""
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "(":
            depth += 1
        elif s[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _split_condition_groups(s: str) -> List[str]:
    """s is a sequence of parenthesized groups such as "(A),(B),(C)". Returns the
    inner content of each group, e.g. ["A", "B", "C"]. Each group may itself
    contain arbitrarily nested parentheses (a nested logical rule); nesting is
    tracked by depth, not by a fixed-depth regex. Anything outside of a group
    (stray commas, whitespace) is simply skipped, and unbalanced input stops the
    scan early rather than raising."""
    groups = []
    i, n = 0, len(s)
    while i < n:
        if s[i] == "(":
            end = _find_matching_paren(s, i)
            if end == -1:
                break
            groups.append(s[i + 1:end])
            i = end + 1
        else:
            i += 1
    return groups


def _parse_condition_group(content: str) -> Optional[Dict]:
    """content is the inside of one parenthesized group. It is either a leaf
    condition such as "DOMAIN,example.com", or a nested logical rule such as
    "OR,((DOMAIN,a.com),(DOMAIN,b.com))" -- in which case this recurses via
    _build_logical_rule."""
    content = content.strip()
    upper = content.upper()
    for kw in LOGICAL_KEYWORDS:
        if upper.startswith(kw + ","):
            return _build_logical_rule(kw, content[len(kw) + 1:])

    if "," not in content:
        return None
    keyword, _, value = content.partition(",")
    field_name = _MAP_LOOKUP.get(keyword.strip().upper())
    if not field_name:
        return None
    return {field_name: value.strip()}


def _build_logical_rule(keyword: str, rest: str) -> Optional[Dict]:
    """rest is whatever follows "KEYWORD," on a logical rule line, e.g.
    "((DOMAIN,example.com),(DST-PORT,80))". Some sources wrap the whole
    condition list in one extra pair of parentheses (as in that example),
    others don't -- both are handled by only stripping the outer pair when
    it truly spans the entire remaining string. Recurses for any nested
    logical rule found among the conditions, so nesting to any depth works
    the same way as a single flat AND/OR/NOT."""
    rest = rest.strip()
    if rest.startswith("(") and rest.endswith(")") and _find_matching_paren(rest, 0) == len(rest) - 1:
        rest = rest[1:-1]

    conditions = [c for c in (_parse_condition_group(g) for g in _split_condition_groups(rest)) if c]
    if not conditions:
        return None

    if keyword == "NOT":
        # Clash's NOT wraps a single condition and means "negate this". sing-box
        # has no separate NOT rule type, so this is represented as a one-condition
        # logical AND group with invert set to true -- functionally equivalent,
        # and it keeps every logical keyword producing the same
        # {"type": "logical", ...} shape that downstream code already handles
        # (stats, merging, type filtering).
        return {"type": "logical", "mode": "and", "rules": conditions, "invert": True}
    mode = "and" if keyword == "AND" else "or"
    return {"type": "logical", "mode": mode, "rules": conditions}


def _parse_logical_line(line: str, keyword: str) -> Optional[Dict]:
    """Parse a full logical rule line (starting with AND,/OR,/NOT,) into a
    sing-box logical rule, recursing into any nested AND/OR/NOT groups.

    Examples:
      AND,((DOMAIN,example.com),(DST-PORT,80))            -> logical, mode=and
      OR,((DOMAIN,a.com),(DOMAIN,b.com))                   -> logical, mode=or
      NOT,((DOMAIN,ads.com))                               -> logical, mode=and, invert=true
      AND,((DOMAIN,example.com),(OR,((DOMAIN,a.com),(DOMAIN,b.com))))
                                                            -> logical, mode=and, with a
                                                               nested mode=or rule inside
    """
    _, _, rest = line.partition(",")
    return _build_logical_rule(keyword, rest)


def parse_csv_rules(text: str) -> Tuple[pd.DataFrame, List[Dict]]:
    """Parse Clash-style rule list text, splitting out plain rules from AND/OR/NOT logical rules"""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]

    plain_lines: List[str] = []
    logical_rules: List[Dict] = []
    for line in lines:
        upper = line.upper()
        keyword = next((kw for kw in LOGICAL_KEYWORDS if upper.startswith(kw + ",")), None)
        if keyword:
            if rule := _parse_logical_line(line, keyword):
                logical_rules.append(rule)
        else:
            plain_lines.append(line)

    df = pd.read_csv(
        StringIO("\n".join(plain_lines)), header=None,
        names=["pattern", "address", "other", "other2", "other3"],
        on_bad_lines="skip",
    )
    return df, logical_rules


def fetch_rule_source(link: str) -> Tuple[pd.DataFrame, List[Dict]]:
    """Fetch and parse a rule source (a single network request; if YAML parsing fails,
    the same fetched text is reused for the CSV fallback instead of fetching again)"""
    text = _http.get_text(link)
    if link.endswith((".yaml", ".txt")):
        try:
            df = _parse_yaml_payload(text)
            if df is not None:
                return df, []
        except yaml.YAMLError as e:
            logger.warning(f"YAML parsing failed, falling back to rule list parsing: {link} ({e})")
    return parse_csv_rules(text)


def build_ruleset(df: pd.DataFrame, logical_rules: List[Dict]) -> Dict[str, Any]:
    """Turn a parsed DataFrame plus logical rules into a sing-box rule-set structure"""
    df = (
        df[~df["pattern"].astype(str).str.contains("#", na=False)]
        .loc[lambda x: x["pattern"].isin(MAP_DICT.keys())]
        .drop_duplicates()
        .assign(pattern=lambda x: x["pattern"].map(MAP_DICT))
        .reset_index(drop=True)
    )

    rules: List[Dict] = []
    domains: List[str] = []
    for pattern, addresses in df.groupby("pattern")["address"].apply(list).items():
        unique = deduplicate_addresses(addresses, str(pattern))
        if pattern == "domain":
            domains.extend(unique)
        else:
            rules.append({pattern: unique})

    if domains:
        rules.insert(0, {"domain": sorted(set(domains))})
    rules.extend(logical_rules)
    return {"version": RULE_SET_VERSION, "rules": rules}


# --------------------------------------------------------------------------
# Output: sorting, writing files, stats
# --------------------------------------------------------------------------

def sort_dict(obj: Any) -> Any:
    """Recursively sort dicts and lists so output is stable and diff-friendly"""
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        if obj and all(isinstance(x, dict) for x in obj):
            return sorted((sort_dict(x) for x in obj), key=lambda d: sorted(d.keys())[0] if d else "")
        return sorted(sort_dict(x) for x in obj)
    return obj


def write_ruleset_json(path: Path, data: Dict[str, Any]) -> None:
    data["version"] = RULE_SET_VERSION
    path.write_text(json.dumps(sort_dict(data), ensure_ascii=False, indent=2), encoding="utf-8")


def get_rule_stats(rules_data: Dict[str, Any]) -> Dict[str, int]:
    stats: Dict[str, int] = {}
    logical = 0
    total = 0
    for rule in rules_data.get("rules", []):
        if not isinstance(rule, dict):
            continue
        if rule.get("type") == "logical":
            logical += 1
            continue
        for rule_type, values in rule.items():
            count = len(values) if isinstance(values, list) else 1
            stats[rule_type] = stats.get(rule_type, 0) + count
            total += count
    if logical:
        stats["logical_rules"] = logical
    stats["total"] = total + logical
    return stats


# --------------------------------------------------------------------------
# sing-box compile / decompile
# --------------------------------------------------------------------------

def singbox_available() -> bool:
    try:
        result = subprocess.run(["sing-box", "version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logger.info(f"sing-box available: {result.stdout.strip()}")
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    logger.warning("sing-box command not found, SRS compilation will be skipped")
    return False


def _run_singbox(cmd: List[str], description: str) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60)
        logger.info(f"{description}: done")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"{description}: failed - {e.stderr}")
    except FileNotFoundError:
        logger.warning("sing-box command not found, skipping this step")
    except subprocess.TimeoutExpired:
        logger.error(f"{description}: timed out")
    return False


def compile_to_srs(json_path: Path) -> bool:
    srs_path = json_path.with_suffix(".srs")
    return _run_singbox(
        ["sing-box", "rule-set", "compile", "--output", str(srs_path), str(json_path)],
        f"compile SRS: {srs_path.name}",
    )


def expected_output_stems(sources: List[Source]) -> set:
    """The set of output file stems (no extension) that should exist per the current
    config, counting only enabled sources"""
    return {s.name for s in sources if s.enabled}


def cleanup_stale_outputs(output_dir: Path, expected_stems: set) -> int:
    """Delete .json/.srs files in the output directory whose stem is no longer in the
    current sources.yaml.

    This is judged by "is it still listed in sources.yaml", not "did this run write
    it" -- so if a source's fetch temporarily fails, its old files are kept as long
    as it is still in the config, and are never mistakenly treated as stale. Only a
    source truly removed from the config gets cleaned up. Only the two extensions
    this script manages are touched, and hidden directories (.git, etc.) are always
    skipped so unrelated files are never at risk.
    """
    removed = 0
    if not output_dir.exists():
        return removed
    for path in output_dir.rglob("*"):
        if not path.is_file() or path.suffix not in (".json", ".srs"):
            continue
        if any(part.startswith(".") for part in path.relative_to(output_dir).parts):
            continue
        if path.stem not in expected_stems:
            path.unlink()
            removed += 1
            logger.info(f"removed stale file (source no longer in sources.yaml): {path}")
    return removed


# --------------------------------------------------------------------------
# Processing a single source: JSON passthrough / SRS decompile / plain rule list
# --------------------------------------------------------------------------

def copy_json_file(
    url: str, output_dir: Path, name: Optional[str] = None, types: Optional[List[str]] = None
) -> Optional[Path]:
    try:
        data = json.loads(_http.get_text(url))
    except (json.JSONDecodeError, requests.RequestException) as e:
        logger.error(f"failed to copy JSON: {url} - {e}")
        return None

    if not isinstance(data, dict):
        logger.warning(f"malformed JSON: {url}")
        return None

    if types:
        data = filter_rules_by_types(data, types)

    path = output_dir / f"{name or Path(url).stem}.json"
    write_ruleset_json(path, data)
    logger.info(f"copied JSON: {path}")
    return path


def copy_srs_file(
    url: str, output_dir: Path, name: Optional[str] = None, types: Optional[List[str]] = None
) -> Optional[Path]:
    filename = name or Path(url).stem
    srs_path = output_dir / f"{filename}.srs"
    json_path = output_dir / f"{filename}.json"

    try:
        srs_path.write_bytes(_http.get_bytes(url))
    except requests.RequestException as e:
        logger.error(f"failed to download SRS: {url} - {e}")
        return None
    logger.info(f"downloaded SRS: {srs_path}")

    try:
        subprocess.run(
            ["sing-box", "rule-set", "decompile", "--output", str(json_path), str(srs_path)],
            check=True, capture_output=True, text=True, timeout=60,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"SRS decompile failed: {e.stderr}")
        return None
    except FileNotFoundError:
        logger.warning("sing-box command not found, keeping the SRS file only")
        return None
    except subprocess.TimeoutExpired:
        logger.error(f"decompile timed out: {srs_path}")
        return None

    data = json.loads(json_path.read_text(encoding="utf-8"))
    if types:
        data = filter_rules_by_types(data, types)
    write_ruleset_json(json_path, data)
    if types:
        # The downloaded .srs is the unfiltered original artifact; after filtering,
        # it must be recompiled from the new JSON, otherwise .srs and .json would
        # no longer agree with each other.
        compile_to_srs(json_path)
    logger.info(f"decompiled to JSON: {json_path}")
    return json_path


def process_link(
    link: str, output_dir: Path, name: Optional[str] = None,
    is_temp: bool = False, types: Optional[List[str]] = None,
) -> Optional[Path]:
    """Download and parse a single rule source, producing JSON (and, unless this is a
    temporary file, applying the types filter, compiling SRS, and extracting subsets)"""
    output_dir.mkdir(parents=True, exist_ok=True)
    ext = Path(link).suffix.lower()

    try:
        if ext == ".json":
            path = copy_json_file(link, output_dir, name, types if not is_temp else None)
            if path and not is_temp:
                compile_to_srs(path)
            return path

        if ext == ".srs":
            return copy_srs_file(link, output_dir, name, types if not is_temp else None)

        df, logical_rules = fetch_rule_source(link)
        rules_data = build_ruleset(df, logical_rules)
        if types and not is_temp:
            rules_data = filter_rules_by_types(rules_data, types)

        filename = name or Path(link).stem
        json_path = output_dir / f"{filename}.json"
        write_ruleset_json(json_path, rules_data)

        stats = get_rule_stats(rules_data)
        stats_str = ", ".join(f"{k}: {v}" for k, v in sorted(stats.items()))
        logger.info(f"generated JSON: {json_path} ({stats_str})")

        if not is_temp:
            compile_to_srs(json_path)
            extract_rule_types(rules_data, output_dir, filename)
        return json_path

    except Exception as e:
        logger.error(f"failed to process: {link} - {e}", exc_info=True)
        return None


def _rule_category(rule_type: str) -> str:
    """Map a sing-box field name to a coarse category, shared by subset extraction and types filtering"""
    key = str(rule_type).lower()
    if "cidr" in key:
        return "cidr"
    if "domain" in key or "host" in key:
        return "domain"
    if "port" in key:
        return "port"
    return "other"


def filter_rules_by_types(rules_data: Dict[str, Any], types: Optional[List[str]]) -> Dict[str, Any]:
    """Filter rules per the source's types setting, keeping only the requested categories;
    an empty/None types means no filtering"""
    if not types:
        return rules_data
    allowed = {t.strip().lower() for t in types if t.strip()}
    if not allowed:
        return rules_data

    kept: List[Dict] = []
    for rule in rules_data.get("rules", []):
        if not isinstance(rule, dict):
            continue
        if rule.get("type") == "logical":
            # Keep a whole logical rule if any of its conditions falls in an allowed
            # category -- splitting a logical group apart would not make sense.
            sub_categories = {_rule_category(k) for cond in rule.get("rules", []) for k in cond}
            if sub_categories & allowed:
                kept.append(rule)
            continue
        if any(_rule_category(rt) in allowed for rt in rule):
            kept.append(rule)

    return {"version": rules_data.get("version", RULE_SET_VERSION), "rules": kept}


def extract_rule_types(rules_data: Dict[str, Any], output_dir: Path, base_name: str) -> None:
    """Save pure-CIDR / pure-domain subsets into CIDR/ and DOMN/ subdirectories for standalone use"""
    buckets: Dict[str, List[Dict]] = {"CIDR": [], "DOMN": []}
    category_to_bucket = {"cidr": "CIDR", "domain": "DOMN"}
    for rule in rules_data.get("rules", []):
        if not isinstance(rule, dict):
            continue
        for rule_type, values in rule.items():
            bucket = category_to_bucket.get(_rule_category(rule_type))
            if bucket:
                buckets[bucket].append({rule_type: values})

    for category, rules in buckets.items():
        if not rules:
            continue
        cat_dir = output_dir / category
        cat_dir.mkdir(parents=True, exist_ok=True)
        path = cat_dir / f"{base_name}.json"
        write_ruleset_json(path, {"version": RULE_SET_VERSION, "rules": rules})
        logger.info(f"extracted {category} rules: {path}")
        compile_to_srs(path)


# --------------------------------------------------------------------------
# Merge groups
# --------------------------------------------------------------------------

def merge_rule_sets(
    json_files: List[Path], output_dir: Path, name: str, types: Optional[List[str]] = None
) -> Optional[Path]:
    merged: Dict[str, List] = {}
    logical_rules: List[Dict] = []

    for path in json_files:
        if not path or not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for rule in data.get("rules", []):
            if rule.get("type") == "logical":
                logical_rules.append(rule)
                continue
            for rule_type, values in rule.items():
                merged.setdefault(rule_type, []).extend(values if isinstance(values, list) else [values])

    rules: List[Dict] = [
        {rule_type: deduplicate_addresses(values, rule_type)}
        for rule_type, values in sorted(merged.items())
    ]
    rules.extend(logical_rules)
    rules_data = {"version": RULE_SET_VERSION, "rules": rules}
    if types:
        rules_data = filter_rules_by_types(rules_data, types)

    merged_path = output_dir / f"{name}.json"
    write_ruleset_json(merged_path, rules_data)

    stats = get_rule_stats(rules_data)
    stats_str = ", ".join(f"{k}: {v}" for k, v in sorted(stats.items()))
    logger.info(f"merged {len(json_files)} files -> {merged_path} ({stats_str})")

    compile_to_srs(merged_path)
    extract_rule_types(rules_data, output_dir, name)
    return merged_path


def process_merge_group(source: Source, settings: Settings) -> Optional[Path]:
    """Concurrently fetch every source in the group into a temp directory, then merge into
    one rule-set; the temp directory is cleaned up automatically when the with-block exits"""
    urls = source.urls
    with TemporaryDirectory(prefix="ruleset_merge_") as tmp:
        tmp_dir = Path(tmp)
        parts: List[Optional[Path]] = [None] * len(urls)

        with ThreadPoolExecutor(max_workers=settings.max_workers) as pool:
            futures = {
                pool.submit(process_link, url, tmp_dir, f"part_{i}", True): i
                for i, url in enumerate(urls)
            }
            for future in as_completed(futures):
                i = futures[future]
                try:
                    parts[i] = future.result()
                except Exception as e:
                    logger.error(f"  failed to process {urls[i]}: {e}")

        for i, (url, result) in enumerate(zip(urls, parts), 1):
            status = "ok" if result else "failed"
            logger.info(f"  [{i}/{len(urls)}] {status} {url}")

        valid_parts = [p for p in parts if p]
        if not valid_parts:
            return None
        return merge_rule_sets(valid_parts, settings.output_dir, source.name, source.types)


# --------------------------------------------------------------------------
# Source config parsing: sources.yaml
# --------------------------------------------------------------------------

def parse_sources_yaml(path: Path) -> List[Source]:
    """Parse sources.yaml; see the format description in the module docstring above"""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw_sources = data.get("sources", data) if isinstance(data, dict) else data
    if not isinstance(raw_sources, list):
        logger.error(f"{path} is malformed: the top level must be a list, or a dict with a sources: key")
        return []

    sources: List[Source] = []
    for i, item in enumerate(raw_sources):
        if not isinstance(item, dict):
            logger.warning(f"skipping item {i + 1}: not a dict")
            continue
        name = item.get("name")
        urls = item.get("urls") or item.get("url")
        if isinstance(urls, str):
            urls = [urls]
        if not name or not urls:
            logger.warning(f"skipping item {i + 1}: missing name or urls")
            continue
        types = item.get("types")
        if isinstance(types, str):
            types = [types]
        enabled = bool(item.get("enabled", True))
        sources.append(Source(name=str(name), urls=list(urls), types=types, enabled=enabled))
    return sources


# --------------------------------------------------------------------------
# Main flow
# --------------------------------------------------------------------------

def _report_summary(results: List[Path], total_tasks: int) -> float:
    rate = (len(results) / total_tasks * 100) if total_tasks else 0.0
    logger.info("=" * 60)
    logger.info(f"done: {len(results)}/{total_tasks} succeeded ({rate:.1f}%), version: {RULE_SET_VERSION}")
    total_size = 0
    for path in sorted(results):
        if path.exists():
            size = path.stat().st_size
            total_size += size
            logger.info(f"  ok {path.name} ({size / 1024 / 1024:.2f} MB)")
    logger.info(f"total size: {total_size / 1024 / 1024:.2f} MB")
    logger.info("=" * 60)
    return rate


def main() -> None:
    settings = Settings.from_env()
    logger.info(f"source config: {settings.sources_file}")
    logger.info(f"output directory: {settings.output_dir}")
    logger.info(f"rule-set version: {RULE_SET_VERSION}")

    if not settings.sources_file.exists():
        logger.error(f"source config file not found: {settings.sources_file}")
        return

    try:
        singbox_available()
        settings.output_dir.mkdir(parents=True, exist_ok=True)

        all_sources = parse_sources_yaml(settings.sources_file)
        sources = [s for s in all_sources if s.enabled]
        skipped = len(all_sources) - len(sources)
        single_sources = [s for s in sources if len(s.urls) == 1]
        multi_sources = [s for s in sources if len(s.urls) > 1]
        logger.info(
            f"{len(all_sources)} sources total ({skipped} disabled): "
            f"{len(single_sources)} single files, {len(multi_sources)} merge groups"
        )
        expected_stems = expected_output_stems(all_sources)

        results: List[Path] = []

        logger.info(f"processing {len(single_sources)} single files concurrently (up to {settings.max_workers} workers)...")
        with ThreadPoolExecutor(max_workers=settings.max_workers) as pool:
            futures = {
                pool.submit(process_link, s.urls[0], settings.output_dir, s.name, False, s.types): s
                for s in single_sources
            }
            for i, future in enumerate(as_completed(futures), 1):
                s = futures[future]
                try:
                    if path := future.result():
                        results.append(path)
                        logger.info(f"[{i}/{len(single_sources)}] ok {s.name}")
                    else:
                        logger.warning(f"[{i}/{len(single_sources)}] failed {s.name}")
                except Exception as e:
                    logger.error(f"[{i}/{len(single_sources)}] error processing {s.name}: {e}")

        for i, s in enumerate(multi_sources, 1):
            logger.info(f"[merge {i}/{len(multi_sources)}] {s.name} <- {len(s.urls)} sources")
            if path := process_merge_group(s, settings):
                results.append(path)

        total_tasks = len(single_sources) + len(multi_sources)
        rate = _report_summary(results, total_tasks)

        if settings.min_success_rate > 0 and total_tasks > 0 and rate < settings.min_success_rate * 100:
            logger.error(
                f"success rate {rate:.1f}% is below the {settings.min_success_rate * 100:.1f}% threshold, "
                f"treating this run as failed (to avoid publishing an incomplete rule-set)"
            )
            sys.exit(1)

        if settings.cleanup_stale:
            if not expected_stems:
                logger.warning("parsed source config is empty, skipping cleanup (to avoid deleting all output)")
            else:
                removed = cleanup_stale_outputs(settings.output_dir, expected_stems)
                if removed:
                    logger.info(f"removed {removed} stale file(s) (sources no longer in the config)")

    finally:
        _http.close()


if __name__ == "__main__":
    main()
