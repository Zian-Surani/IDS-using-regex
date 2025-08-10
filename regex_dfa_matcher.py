"""
Dual-mode detector for IDS:
- Regex (Python re)
- Formal DFA (pyformlang)

Exports (used by ui_app.py):
- load_patterns(file)
- build_detectors(patterns)
- regex_detectors_from_file(file)
- match_regex(detectors, text)
- match_dfa(detectors, text)
- match_both(detectors, text) -> {"regex":[...], "dfa":[...], "both":[...]}
- explain_pattern(pattern)
"""

from __future__ import annotations
import re
from typing import List, Tuple, Any, Dict

# pyformlang for formal regex -> DFA
from pyformlang.regular_expression import Regex
from pyformlang.finite_automaton import Symbol, DeterministicFiniteAutomaton

Detector = Tuple[str, str, Any]  # ('dfa'|'re', pattern_str, compiled_obj)


# --------------------------
# Pattern loading
# --------------------------
def load_patterns(filename: str = "signatures.txt") -> List[str]:
    patterns: List[str] = []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                if re.fullmatch(r"[*+?]+", raw):
                    continue
                patterns.append(raw)
    except FileNotFoundError:
        patterns = [
            "<script>.*?</script>",
            "(?i)select.+from",
            "(?i)union\\s+select",
            "(?i)or\\s+1=1",
            "(?i)drop\\s+table",
            "(?i)cmd\\.exe",
            "(?i)rm\\s+-rf",
            "(?i)wget\\s+http",
            "(?i)curl\\s+http",
            "%3Cscript%3E.*%3C/script%3E",
            "\\.\\./etc/passwd",
        ]
    return patterns


# --------------------------
# Build detectors
# --------------------------
def _regex_to_dfa(pattern: str) -> DeterministicFiniteAutomaton:
    """
    Convert regex -> DFA using pyformlang.
    Handles (?i) by stripping and mirroring transitions for case-insensitivity.
    """
    case_insensitive = pattern.startswith("(?i)")
    core = pattern[4:] if case_insensitive else pattern

    regex_obj = Regex(core)
    enfa = regex_obj.to_epsilon_nfa()
    dfa = enfa.minimize()

    if not case_insensitive:
        return dfa

    # Emulate case-insensitive DFA by mirroring transitions for upper/lower
    new_dfa = DeterministicFiniteAutomaton()
    for st in dfa.states:
        new_dfa.add_state(st)
        if st in dfa.final_states:
            new_dfa.add_final_state(st)
    for (state, sym), nxt in dfa._transition_function._transitions.items():
        s = str(sym)
        new_dfa.add_transition(state, Symbol(s.lower()), nxt)
        new_dfa.add_transition(state, Symbol(s.upper()), nxt)
    if dfa.start_state:
        new_dfa.add_start_state(dfa.start_state)
    return new_dfa


def build_detectors(patterns: List[str]) -> List[Detector]:
    out: List[Detector] = []
    for pat in patterns:
        # DFA attempt (may fail for non-regular constructs)
        try:
            dfa = _regex_to_dfa(pat)
            out.append(("dfa", pat, dfa))
        except Exception as e:
            print(f"[regex_dfa_matcher] DFA build failed for '{pat}': {e}")

        # Python regex fallback (support (?i))
        try:
            flags = re.IGNORECASE if pat.startswith("(?i)") else 0
            core = pat[4:] if pat.startswith("(?i)") else pat
            rx = re.compile(core, flags)
            out.append(("re", pat, rx))
        except Exception as e:
            print(f"[regex_dfa_matcher] Invalid regex '{pat}': {e}")
    return out


def regex_detectors_from_file(filename: str = "signatures.txt") -> List[Detector]:
    return build_detectors(load_patterns(filename))


# --------------------------
# Matching helpers
# --------------------------
def match_regex(detectors: List[Detector], text: str) -> List[str]:
    hits: List[str] = []
    for kind, pat, obj in detectors:
        if kind != "re":
            continue
        try:
            if obj.search(text):
                hits.append(pat)
        except Exception:
            pass
    return hits


def match_dfa(detectors: List[Detector], text: str) -> List[str]:
    hits: List[str] = []
    symbols = [Symbol(c) for c in text]
    for kind, pat, obj in detectors:
        if kind != "dfa":
            continue
        try:
            if obj.accepts(symbols):
                hits.append(pat)
        except Exception:
            try:
                if obj.accepts(text):
                    hits.append(pat)
            except Exception:
                pass
    return hits


def match_both(detectors: List[Detector], text: str) -> Dict[str, List[str]]:
    r = match_regex(detectors, text)
    d = match_dfa(detectors, text)
    return {"regex": r, "dfa": d, "both": sorted(set(r) & set(d))}


# --------------------------
# Human explanations
# --------------------------
def explain_pattern(pat: str) -> str:
    p = pat.lower()
    if "select" in p or "union" in p or "drop table" in p or "or\\s+1=1" in p or "or 1=1" in p:
        return "SQL Injection signature — could read or modify database contents."
    if "script" in p or "%3cscript%3e" in p or ("<img" in p and "onerror" in p):
        return "Cross-Site Scripting (XSS) — attacker-controlled JavaScript execution."
    if "cmd.exe" in p or "rm\\s+-rf" in p or "rm -rf" in p or "wget" in p or "curl" in p or "powershell" in p:
        return "Command or remote download — may execute OS commands or fetch payloads."
    if "../" in p or "etc/passwd" in p:
        return "Directory traversal — reading files outside allowed directories."
    if "malware" in p or "trojan" in p or "ransomware" in p:
        return "Malware keyword — suspicious but needs corroboration."
    return "Suspicious signature — investigate the context and source."


if __name__ == "__main__":
    dets = regex_detectors_from_file()
    sample = "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E\ncmd.exe /c dir\nSELECT * FROM users"
    print(match_both(dets, sample))
