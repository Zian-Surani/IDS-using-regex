import re
import time
from pyformlang.regular_expression import Regex

patterns = [
    "<script>.*?</script>",
    "(?i)select.+from",
    "(?i)cmd\\.exe",
    "wget",
    "curl"
]

test_text = """
GET /search?q=<script>alert('Hacked!')</script> HTTP/1.1
Host: vulnerable-website.com
User-Agent: Mozilla/5.0
Referer: http://evil.com
SELECT * FROM users WHERE username='admin' AND password='password';
"""

# Compile regex patterns
regex_objects = [re.compile(pat, flags=re.IGNORECASE if pat.startswith("(?i)") else 0) for pat in patterns]

# Compile DFA patterns
dfa_objects = []
for pat in patterns:
    try:
        pat_clean = pat[4:] if pat.startswith("(?i)") else pat
        dfa = Regex(pat_clean).to_epsilon_nfa().minimize()
        dfa_objects.append(dfa)
    except Exception as e:
        print(f"Could not compile DFA for {pat}: {e}")

# Benchmark regex
start = time.time()
for _ in range(1000):
    for regex_obj in regex_objects:
        regex_obj.search(test_text)
end = time.time()
print(f"Regex time: {end - start:.4f}s")

# Benchmark DFA
start = time.time()
for _ in range(1000):
    for dfa in dfa_objects:
        try:
            dfa.accepts(list(test_text))
        except Exception:
            pass
end = time.time()
print(f"DFA time: {end - start:.4f}s")
