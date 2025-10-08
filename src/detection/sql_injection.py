# src/detection/sql_injection.py
import re
from typing import Tuple, List, Dict
from .pattern_matcher import match_patterns, normalize_payload


# Configurable limits
MAX_PAYLOAD_LEN = 2000  # truncate long payloads for safety/performance
MIN_INDICATORS_TO_BLOCK = 2  # require multiple indicators for lower-confidence hits

# Improved keywords (word-boundary checks)
SQL_KEYWORDS = [
    "select", "insert", "update", "delete", "drop", "union", "concat",
    "information_schema", "load_file", "outfile", "benchmark", "sleep",
    "waitfor", "exec", "execute", "xp_cmdshell",
]

# Suspicious comment-like tokens
SQL_COMMENT_PATTERNS = ["--", "#", "/*", "*/", ";--", ";#"]

# Classic logic manipulation patterns
SQL_LOGIC_PATTERNS = [
    "or 1=1", "or '1'='1", "or 1=1--", "and 1=1", "' or ''='", "' or '1'='1"
]

# Precompile logic and comment patterns for speed
_COMPILED_LOGIC = [re.compile(r'\b' + re.escape(p) + r'\b', re.IGNORECASE) for p in SQL_LOGIC_PATTERNS]
_COMPILED_KEYWORDS = [re.compile(r'\b' + re.escape(k) + r'\b', re.IGNORECASE) for k in SQL_KEYWORDS]


# dict is short for dictionary in Python — it’s a built-in data type used to store data as key–value pairs. 
#example req_dict = {
#   "path": "/login",
#   "args": {"user": "admin", "pass": "123"},
#   "body": "",
#   "headers": {"user-agent": "Mozilla"}
#}

def build_payload_string(req_dict: dict) -> str:
    parts = [] #Creates a list that will temporarily store all pieces of data extracted from the request (URL path, arguments, headers, etc.).
    parts.append(req_dict.get("path", ""))
    args = req_dict.get("args") or {}
    if isinstance(args, dict): #isinstance(x, T) checks whether x is an instance of type T
        #Here it asks: “Is args a dictionary?”
        for k, v in args.items():
            parts.append(f"{k}={v}") #if the args are dict , we combine the key value in on string and append it to parts list
    else:
        parts.append(str(args)) 
    parts.append(req_dict.get("body", "") or "")
    headers = req_dict.get("headers") or {}
    for h in ("user-agent", "referer", "x-forwarded-for", "cookie"):
        if headers.get(h):
            parts.append(headers.get(h))
    payload = " ".join(parts)
    # truncate overly long payloads to avoid problems and speed up checks
    if len(payload) > MAX_PAYLOAD_LEN:
        payload = payload[:MAX_PAYLOAD_LEN]#prevent using too much memory
    return payload
#example what will return thi function /search user=admin password=1234 {"login": "true"} Mozilla/5.0 https://google.com 192.168.1.1 session=abc123

def _keyword_hits(normalized: str) -> List[str]:
    hits = []
    for rx, kw in zip(_COMPILED_KEYWORDS, SQL_KEYWORDS):
        if rx.search(normalized):
            hits.append(kw)
    return hits
#it's content is sql keyword exist in the payload

def _logic_hits(normalized: str) -> List[str]:
    hits = []
    for rx, pat in zip(_COMPILED_LOGIC, SQL_LOGIC_PATTERNS):
        if rx.search(normalized):
            hits.append(pat)
    return hits


def detect_sql_injection(req_dict: dict, patterns: List[str] = None) -> Tuple[bool, Dict]:
    """
    Returns (is_attack, details)
    details contains: reason, hits/list, sample, confidence
    """
    payload = build_payload_string(req_dict)
    normalized = normalize_payload(payload)
    sample = payload[:300] # # Instead of storing entire payloads that could be thousands of characters we take first 300 , that should be enought

    indicators = []  # collect indicators for thresholding

    # 1) Keyword heuristic (low/medium confidence)
    kw_hits = _keyword_hits(normalized)
    if kw_hits:
        indicators.append({"type": "keyword", "hits": kw_hits})

    # 2) SQL comment tokens (high confidence)
    for comment in SQL_COMMENT_PATTERNS:
        if comment in payload:
            indicators.append({"type": "comment", "pattern": comment})

    # 3) Logic manipulation patterns (high confidence)
    logic = _logic_hits(normalized)
    if logic:
        indicators.append({"type": "logic", "hits": logic})

    # 4) Regex patterns from rules (high confidence if matched)
    regex_hits = []
    if patterns:
        # pass normalized to match_patterns; match_patterns precompiles and finds all matches
        regex_hits = match_patterns(normalized, patterns)
        if regex_hits:
            indicators.append({"type": "regex", "hits": regex_hits})

    # Decision logic:
    # - If any high-confidence indicator (comment, logic, regex): block
    # - Else if >= MIN_INDICATORS_TO_BLOCK indicators total: block
    # - Else: allow but return low-confidence detection if any keyword matched (for logging)
    # check for high-confidence types
    high_conf_types = {"comment", "logic", "regex"}
    for ind in indicators:
        if ind["type"] in high_conf_types:
            return True, {
                "reason": ind["type"],
                "hits": ind.get("hits") or [ind.get("pattern")],
                "sample": sample,
                "confidence": "high"
            }

    # not high-confidence; check total indicators
    if len(indicators) >= MIN_INDICATORS_TO_BLOCK:
        return True, {
            "reason": "combined",
            "indicators": indicators,
            "sample": sample,
            "confidence": "medium"
        }

    # low-confidence: keywords only -> do not block but report 
    if indicators:
        return False, {
            "reason": "keyword-only",
            "indicators": indicators,
            "sample": sample,
            "confidence": "low"
        }

    return False, {}
