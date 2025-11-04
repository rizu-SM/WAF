import re #allow search, match, and manipulate text
import html
import urllib.parse #parsing, constructing, and decoding URLs and query strings

# Precompile cache creates a global dictionary that stores 
# compiled regular expressions (regex) so they don’t have 
# to be recompiled every time you check a request.
_precompiled_cache = {}

def normalize_payload(payload: str) -> str:
    """URL-decode, unescape HTML entities and lowercase the payload."""
    try:
        p = urllib.parse.unquote_plus(payload or "") #This URL-decodes the payload example"SELECT%20*%20FROM%20users" → "SELECT * FROM users"
    except Exception:
        p = payload or ""
    p = html.unescape(p) #decodes HTML entities example "&lt;script&gt;" → "<script>"
    return p.lower() #Everything is lowercased to make detection easier.

def compile_pattern(pat):
    """Return compiled regex; cache it to improve performance."""
    if pat in _precompiled_cache:
        return _precompiled_cache[pat]
    regex = re.compile(pat, re.IGNORECASE)  #re.compile("sami") turns the string pattern into a compiled regex object.
                                            #re.IGNORECASE makes the regex case-insensitive (e.g. “SELECT” or “select” both match).
    _precompiled_cache[pat] = regex #After compiling, we store the compiled regex in the cache dictionary
    return regex
#compile_pattern(pat) = Convert the pattern string into a re.Pattern object that’s faster and easier to use .
def match_patterns(payload: str, patterns: list):
    """
    payload: raw string
    patterns: list of regex strings (or compiled regex objects)
    returns: list of {"pattern": pattern_text, "matches": [...], "count": n}
    """
    text = normalize_payload(payload)
    hits = []
    for pat in patterns:
        regex = pat if hasattr(pat, "finditer") else compile_pattern(pat) #checks the dictionary _precompiled_cache to see if this regex was already compiled before.
        #Does this object (pat) have a method called finditer? All compiled regex objects (from re.compile()) have this method.
        matches = [m.group(0) for m in regex.finditer(text)]
        if matches:
            hits.append({"pattern": getattr(regex, "pattern", str(pat)), "matches": matches, "count": len(matches)})
    return hits