# dfa.py
from regex_dfa_matcher import regex_detectors_from_file, match_dfa

def run_dfa_test(input_text: str, signatures_file: str = "signatures.txt"):
    detectors = regex_detectors_from_file(signatures_file)
    matches = match_dfa(detectors, input_text)
    return matches

if __name__ == "__main__":
    sample = "<script>alert('XSS')</script>"
    print("DFA Matches:", run_dfa_test(sample))
