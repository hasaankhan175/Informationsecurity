"""
Password Security Analyzer - Group E (Information Security, BS Data Science)

How the file is organised:
  1. Settings & data : common-password list, constants.
  2. Logic functions : pool_size, find_patterns, format_time, analyze, check_breach, generators.
  3. User interface  : five tabs (Analyzer, Generator, Hashing Demo, Brute-Force Simulation, About).
Run with:  streamlit run app.py
"""
import hashlib
import itertools
import math
import re
import secrets
import string
import time

import bcrypt
import requests
import streamlit as st

st.set_page_config(page_title="Password Security Analyzer", page_icon="🔐", layout="centered")

# ---------------------------------------------------------------------------
# Settings and data
# ---------------------------------------------------------------------------
# One short, neutral message for each strength level
MESSAGES = {
    "Very Strong": "This password is very strong and would take an extremely long time to crack.",
    "Strong": "This password is strong. Making it longer would improve it further.",
    "Medium": "This password is acceptable but could be stronger. Add length and variety.",
    "Weak": "This password is weak and could be guessed or cracked quickly.",
    "Very Weak": "This password is very weak. Do not use it.",
}

# Small list of very common passwords (a real tool would use millions of entries)
COMMON = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "111111", "123123",
    "admin", "letmein", "welcome", "monkey", "dragon", "iloveyou", "sunshine", "princess",
    "football", "baseball", "login", "master", "hello", "freedom", "whatever", "trustno1",
    "passw0rd", "password1", "1234567890", "000000", "qwerty123", "superman", "batman",
    "shadow", "michael", "pakistan", "karachi", "ali123", "ahmed123", "zaq12wsx", "1q2w3e4r",
}

# Sequences that attackers try early (checked forwards and backwards)
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm", "0123456789"]

# Translation table that undoes l33t speak: 4->a, 3->e, 1->i, 0->o, @->a, $->s, 5->s, 7->t
LEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "@": "a", "$": "s", "5": "s", "7": "t"})

# Word list for the passphrase option
WORDS = ["pizza", "turtle", "laser", "banana", "rocket", "ninja", "pickle", "cactus", "wizard", "taco",
         "dragon", "coffee", "panda", "thunder", "noodle", "galaxy", "robot", "cookie", "sphinx", "mango",
         "viking", "bubble", "jelly", "castle", "falcon", "marshmallow", "sandwich", "unicorn", "zombie", "biryani"]

# Attacker speed used for crack-time estimates (a GPU rig attacking a fast, unsalted hash)
GUESSES_PER_SEC = 1e10


# ---------------------------------------------------------------------------
# Logic functions
# ---------------------------------------------------------------------------
def pool_size(pw: str) -> int:
    """
    Count how many different characters an attacker must try for EACH position.
    Lowercase=26, uppercase=26, digits=10, symbols=33, space=1. A password that mixes
    more character types has a bigger pool, so it is harder to brute-force.
    """
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"\d", pw):
        size += 10
    if re.search(r"[^\w\s]|_", pw):
        size += 33
    if re.search(r"\s", pw):
        size += 1
    return size


def find_patterns(pw: str):
    """
    Look for habits that attackers guess first and return a list of problems:
      - keyboard/alphabet/number sequences of 4+ characters (qwer, abcd, 1234, also reversed)
      - 3 or more identical characters in a row (aaa, 111)
      - years such as 1999 or 2024
      - common passwords, even when disguised with l33t substitutions (p@ssw0rd)
    Each problem found later reduces the entropy score in analyze().
    """
    found = []
    low = pw.lower()
    for seq in SEQUENCES:
        if any(seq[i:i + 4] in low or seq[i:i + 4][::-1] in low for i in range(len(seq) - 3)):
            found.append("Contains a keyboard, alphabet or number sequence (for example 'qwer' or '1234')")
            break
    if re.search(r"(.)\1{2,}", pw):
        found.append("Contains repeated characters (for example 'aaa' or '111')")
    if re.search(r"(19|20)\d{2}", pw):
        found.append("Contains a year, which is an easy guess")
    if low in COMMON or low.translate(LEET) in COMMON:
        found.append("Is a common password (even with letter-to-symbol substitutions)")
    return found


def format_time(seconds: float) -> str:
    """
    Turn a number of seconds into readable text such as '5 hours' or '12 million years'.
    The loop divides by 60, 60, 24, 365, 1000... until the value fits the current unit.
    """
    if seconds < 1:
        return "instantly"
    units = [("seconds", 60), ("minutes", 60), ("hours", 24), ("days", 365), ("years", 1000),
             ("thousand years", 1000), ("million years", 1000), ("billion years", 1000)]
    value = seconds
    for name, step in units:
        if value < step:
            return f"{value:,.0f} {name}"
        value /= step
    return "trillions of years"


def analyze(pw: str) -> dict:
    """
    Main function. Takes a password and returns a dictionary with:
    length, entropy (bits), score (0-100), level (Very Weak ... Very Strong),
    checklist results, detected patterns and the estimated crack time.

    Steps:
      1. entropy = length x log2(pool size)  -> theoretical bits of randomness
      2. subtract 10 bits for every pattern found (the password is more predictable)
      3. common passwords are capped at 8 bits (they are cracked instantly from wordlists)
      4. score = entropy / 80 x 100 (80 bits is treated as 'excellent'), with extra caps for
         short passwords (<8 chars max 25) and for anything under 12 chars (never 'Very Strong')
      5. crack time = 2^entropy / 2 / guesses per second (average case: half the space)
    """
    length = len(pw)
    size = pool_size(pw)
    raw_entropy = length * math.log2(size) if size else 0
    patterns = find_patterns(pw)
    is_common = pw.lower() in COMMON or pw.lower().translate(LEET) in COMMON

    entropy = max(0.0, raw_entropy - 10 * len(patterns))
    if is_common:
        entropy = min(entropy, 8)

    score = min(100, round(entropy / 80 * 100))
    if length < 8:
        score = min(score, 25)
    if length < 12 and score > 79:
        score = 79

    if score >= 80:
        level = "Very Strong"
    elif score >= 60:
        level = "Strong"
    elif score >= 40:
        level = "Medium"
    elif score >= 20:
        level = "Weak"
    else:
        level = "Very Weak"

    checks = {
        "At least 12 characters": length >= 12,
        "Lowercase letters": bool(re.search(r"[a-z]", pw)),
        "Uppercase letters": bool(re.search(r"[A-Z]", pw)),
        "Numbers": bool(re.search(r"\d", pw)),
        "Special characters": bool(re.search(r"[^\w\s]|_", pw)),
        "No common patterns": not patterns,
    }
    crack_seconds = (2 ** entropy) / GUESSES_PER_SEC / 2
    return dict(length=length, entropy=entropy, score=score, level=level, checks=checks,
                patterns=patterns, crack_time=format_time(crack_seconds))


def check_breach(pw: str):
    """
    Ask the HaveIBeenPwned database whether this password appeared in a known data breach.
    Privacy (k-anonymity): we SHA-1 hash the password and send ONLY the first 5 characters
    of the hash. The server returns every hash starting with those 5 characters and we compare
    the rest locally, so the real password never leaves the app.
    Returns the number of times it was leaked, 0 if never, or None if the service is unreachable.
    """
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=6)
        r.raise_for_status()
    except requests.RequestException:
        return None
    for line in r.text.splitlines():
        h, _, count = line.partition(":")
        if h == suffix:
            return int(count)
    return 0


def generate_password(length, upper, digits, symbols):
    """
    Build a random password with Python's `secrets` module (cryptographically secure).
    It guarantees one character from every selected type, fills the rest randomly,
    then shuffles so the guaranteed characters are not always at the start.
    """
    chars = string.ascii_lowercase
    required = [secrets.choice(string.ascii_lowercase)]
    if upper:
        chars += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if digits:
        chars += string.digits
        required.append(secrets.choice(string.digits))
    if symbols:
        sym = "!@#$%^&*()-_=+[]{}?"
        chars += sym
        required.append(secrets.choice(sym))
    rest = [secrets.choice(chars) for _ in range(max(length - len(required), 0))]
    pwd = required + rest
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def generate_passphrase(n=4):
    """
    Make an easy-to-remember passphrase: n random words plus a 3-digit number,
    joined by dashes (for example pizza-ninja-taco-mango-482).
    """
    return "-".join(secrets.choice(WORDS) for _ in range(n)) + "-" + str(secrets.randbelow(900) + 100)


# ---------------------------------------------------------------------------
# User interface
# ---------------------------------------------------------------------------
st.title("🔐 Password Security Analyzer")
st.caption("Information Security project · Group E · Passwords are never stored or logged.")

tab_an, tab_gen, tab_hash, tab_bf, tab_about = st.tabs(
    ["Analyzer", "Generator", "Hashing Demo", "Brute-Force Simulation", "About"])

# ---------- TAB 1: ANALYZER ----------
with tab_an:
    st.header("Password Strength Analyzer")
    show = st.checkbox("Show password")
    pw = st.text_input("Enter a password", type="default" if show else "password")

    if pw:
        res = analyze(pw)

        # Verdict, coloured by level
        verdict = f"**{res['level']}** (score {res['score']}/100). {MESSAGES[res['level']]}"
        if res["level"] in ("Very Weak", "Weak"):
            st.error(verdict)
        elif res["level"] == "Medium":
            st.warning(verdict)
        else:
            st.success(verdict)
        st.progress(res["score"] / 100)

        c1, c2, c3 = st.columns(3)
        c1.metric("Length", res["length"])
        c2.metric("Entropy (bits)", f"{res['entropy']:.1f}")
        c3.metric("Estimated crack time*", res["crack_time"])
        st.caption("*Offline attack at 10 billion guesses per second.")

        st.subheader("Checklist")
        for name, ok in res["checks"].items():
            st.write(("✅ " if ok else "❌ ") + name)

        if res["patterns"]:
            st.subheader("Problems found")
            for p in res["patterns"]:
                st.write("• " + p)

        st.subheader("Data breach check")
        st.caption("Only the first 5 characters of the password's SHA-1 hash are sent.")
        if st.button("Check in known data breaches"):
            with st.spinner("Checking..."):
                hits = check_breach(pw)
            if hits is None:
                st.warning("Could not reach the breach database. Try again later.")
            elif hits == 0:
                st.success("Not found in known breaches.")
            else:
                st.error(f"Found {hits:,} times in leaked databases. Do not use this password.")
    else:
        st.info("Enter a password to analyze it.")

# ---------- TAB 2: GENERATOR ----------
with tab_gen:
    st.header("Password Generator")
    length = st.slider("Length", 8, 40, 16)
    a, b, c = st.columns(3)
    up = a.checkbox("Uppercase", True)
    dg = b.checkbox("Numbers", True)
    sy = c.checkbox("Symbols", True)
    if st.button("Generate password"):
        st.session_state["gen"] = generate_password(length, up, dg, sy)
    if st.button("Generate passphrase"):
        st.session_state["gen"] = generate_passphrase()
    if "gen" in st.session_state:
        st.code(st.session_state["gen"], language=None)
        g = analyze(st.session_state["gen"])
        st.write(f"Strength: **{g['level']}** · Entropy: **{g['entropy']:.0f} bits**")
    st.caption("Generated with Python's `secrets` module (cryptographically secure randomness).")

# ---------- TAB 3: HASHING DEMO ----------
with tab_hash:
    st.header("Password Hashing Demonstration")
    st.write("A secure website stores a hash of your password, not the password itself. "
             "A hash is a one-way fingerprint. Change one letter below and the whole hash changes.")
    hpw = st.text_input("Text to hash", value="password123", key="hash_in")
    if hpw:
        data = hpw.encode("utf-8")
        st.subheader("1. Fast hashes (hashlib)")
        for algo in ["md5", "sha1", "sha256", "sha512"]:
            st.write(f"**{algo.upper()}**")
            st.code(hashlib.new(algo, data).hexdigest(), language=None)
        st.caption("Fast hashes are fine for files but not recommended for storing passwords.")

        st.subheader("2. Salting")
        salt = secrets.token_hex(8)
        st.code(f"salt    : {salt}\nSHA-256 : {hashlib.sha256((salt + hpw).encode()).hexdigest()}", language=None)
        st.caption("A random salt makes identical passwords produce different hashes and defeats rainbow tables.")

        st.subheader("3. bcrypt")
        cost = st.slider("Cost factor (each +1 doubles the time)", 4, 13, 10)
        if st.button("Hash with bcrypt"):
            pw_b = data[:72]  # bcrypt only uses the first 72 bytes
            t0 = time.time()
            # gensalt() creates a fresh random salt each time, so two hashes of the same password differ
            h1 = bcrypt.hashpw(pw_b, bcrypt.gensalt(rounds=cost))
            elapsed = time.time() - t0
            h2 = bcrypt.hashpw(pw_b, bcrypt.gensalt(rounds=cost))
            st.write("The same password hashed twice gives different hashes because of the random salt:")
            st.code(f"{h1.decode()}\n{h2.decode()}", language=None)
            st.write(f"One hash took **{elapsed:.3f} seconds**. This is fast enough for a login "
                     "but slow for an attacker making billions of guesses.")
            st.write(f"Verification with the correct password: **{bcrypt.checkpw(pw_b, h1)}** · "
                     f"with a wrong password: **{bcrypt.checkpw(b'wrong-password', h1)}**")

# ---------- TAB 4: BRUTE-FORCE SIMULATION ----------
with tab_bf:
    st.header("Brute-Force Attack Simulation")
    st.warning("Controlled demonstration: it only attacks the password you type here and stops after 2 million guesses.")
    MAX_ATTEMPTS = 2_000_000
    mode = st.radio("Attack type", ["Dictionary attack", "Brute-force attack"], horizontal=True)
    target = st.text_input("Target password (keep it short for brute force)", key="bf_pw")

    charsets = {
        "Digits (10)": string.digits,
        "Lowercase letters (26)": string.ascii_lowercase,
        "Lowercase letters and digits (36)": string.ascii_lowercase + string.digits,
    }
    if mode == "Brute-force attack":
        cs_name = st.selectbox("Attacker's character set", list(charsets))
        max_len = st.slider("Maximum length the attacker tries", 1, 6, 4)

    if st.button("Run attack"):
        if not target:
            st.error("Enter a target password first.")
        else:
            target_hash = hashlib.sha256(target.encode()).digest()
            st.write("The attacker only knows the SHA-256 hash:")
            st.code(target_hash.hex(), language=None)

            if mode == "Dictionary attack":
                start, found, attempts = time.time(), None, 0
                for guess in sorted(COMMON):
                    attempts += 1
                    if hashlib.sha256(guess.encode()).digest() == target_hash:
                        found = guess
                        break
                if found:
                    st.error(f"Cracked: '{found}' after {attempts} guesses in {time.time() - start:.4f} seconds.")
                else:
                    st.success(f"Not found in the list of {attempts} common passwords.")
            else:
                charset = charsets[cs_name]
                if len(target) > max_len or any(ch not in charset for ch in target):
                    st.info("This password is outside the attacker's character set or length limit, "
                            "so this attack cannot crack it.")
                else:
                    keyspace = sum(len(charset) ** n for n in range(1, max_len + 1))
                    st.write(f"Search space: **{keyspace:,}** possible passwords.")
                    bar = st.progress(0.0, text="Running...")
                    start, attempts, found, done = time.time(), 0, None, False
                    # Try every combination of length 1, then 2, ... up to max_len, hashing each guess
                    # with SHA-256 and comparing it to the target hash (what a real cracker does).
                    for length in range(1, max_len + 1):
                        for combo in itertools.product(charset, repeat=length):
                            attempts += 1
                            guess = "".join(combo)
                            if hashlib.sha256(guess.encode()).digest() == target_hash:
                                found, done = guess, True
                                break
                            if attempts % 50_000 == 0:
                                bar.progress(min(attempts / min(keyspace, MAX_ATTEMPTS), 1.0),
                                             text=f"{attempts:,} guesses...")
                            if attempts >= MAX_ATTEMPTS:
                                done = True
                                break
                        if done:
                            break
                    bar.progress(1.0, text="Finished")
                    elapsed = max(time.time() - start, 1e-6)
                    speed = attempts / elapsed
                    if found:
                        st.error(f"Cracked: '{found}' after {attempts:,} guesses in {elapsed:.2f} seconds "
                                 f"(about {speed:,.0f} guesses per second).")
                    else:
                        st.success(f"Not cracked within {attempts:,} guesses ({elapsed:.1f} seconds).")
                    st.write(f"Worst case for this search space on this server: **{format_time(keyspace / speed)}**. "
                             f"On a GPU system (10 billion guesses per second): **{format_time(keyspace / GUESSES_PER_SEC)}**.")
    st.caption("Every extra character multiplies the work. Slow hashes such as bcrypt make each guess more expensive.")

# ---------- TAB 5: ABOUT ----------
with tab_about:
    st.header("About This Project")
    st.markdown("""
**Course:** Information Security · **Program:** BS Data Science, 3rd Semester · **Group E**

### Objective
Many people choose passwords that are easy to remember and easy to crack. This tool analyzes a
password, explains why it is weak or strong, estimates how long an attacker would need, and
demonstrates hashing and attacks.

### Main features
1. Password Strength Checker
2. Common Password Detector
3. Password Entropy Analyzer
4. Secure Password Generator
5. Password Hashing Demonstration (hashlib and bcrypt)
6. Brute-Force Attack Simulation (dictionary and brute force)

### How the analyzer works
1. **Character pool:** lowercase 26, uppercase 26, digits 10, symbols about 33.
2. **Entropy:** `Entropy = Length × log2(Pool size)` bits. More bits means exponentially more guesses.
3. **Pattern penalties:** sequences (`qwerty`, `1234`), repeats (`aaa`), years and common passwords
   (including `p@ssw0rd`) reduce the entropy.
4. **Crack time:** `2^entropy / 2 / guesses per second`, using 10 billion guesses per second.
5. **Score and level:** entropy is mapped to 0–100 and five levels: Very Weak, Weak, Medium, Strong, Very Strong.
6. **Breach check (optional):** uses the HaveIBeenPwned k-anonymity API. Only the first 5 characters of
   the SHA-1 hash are sent, so the password never leaves the app.

### Security concepts demonstrated
- Password entropy and brute-force attacks
- Dictionary attacks and common-password lists
- Hashing, salting, and slow adaptive hashing with bcrypt
- k-anonymity for privacy-preserving breach lookups
- Cryptographically secure random generation (`secrets`)
- No storage or logging of passwords

### Technologies
Python 3 · Streamlit · hashlib · bcrypt · Requests · secrets

### Limitations
- Crack times are estimates; real attackers use smarter rules and larger wordlists.
- The common-password list is small.
- Do not type real, important passwords into any website you do not control.

### Team members
""")
    st.table({"Name": ["Umm e Hani", "Muznah Khan", "M. Hasaan Hassan Khan", "Hiba"],
              "Roll No.": ["25F-DS-018", "25F-DS-002", "25F-DS-012", "25F-DS-013"],
              "Contribution": ["Introduction, objectives, coordination", "Strength analysis and entropy",
                               "Hashing demonstration", "Brute-force simulation and generator"]})
