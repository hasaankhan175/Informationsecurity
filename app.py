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

st.set_page_config(page_title="Password Roast Analyzer", page_icon="🔐", layout="centered")

# ---------------------------------------------------------------------------
# 🎬 MEME GIFS - REPLACE THESE WITH YOUR OWN!
# Go to giphy.com / tenor.com (or Google Images -> GIF), open a GIF, right-click
# -> "Copy image address" (must end with .gif) and paste below.
# If a link is broken, the app shows a big emoji instead, so it never crashes.
# ---------------------------------------------------------------------------
GIFS = {
    "Very Strong": [
        "https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExZnpnYzZoZTFhdndicDM3eGk4NXlqd3JlMmdubThodGkxbXk1ajBqNCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/Fh8Ag5sHrzjQEcWMdg/giphy.gif"
    ],
    "Strong": ["https://media.giphy.com/media/v1.Y2lkPWVjZjA1ZTQ3M3NlOXI5Z3E2dW1yYTJ3dDU4NmlodzRkaWJweWxnaXh0MW53ZTB0YiZlcD12MV9naWZzX3RyZW5kaW5nJmN0PWc/5uDNFrOi6VwrkFKBaj/giphy.gif"],
    "Medium": ["https://media.giphy.com/media/v1.Y2lkPWVjZjA1ZTQ3M3NlOXI5Z3E2dW1yYTJ3dDU4NmlodzRkaWJweWxnaXh0MW53ZTB0YiZlcD12MV9naWZzX3RyZW5kaW5nJmN0PWc/hkUZaeuLYmzZacPREb/giphy.gif"],
    "Weak": ["https://media.giphy.com/media/v1.Y2lkPWVjZjA1ZTQ3M3NlOXI5Z3E2dW1yYTJ3dDU4NmlodzRkaWJweWxnaXh0MW53ZTB0YiZlcD12MV9naWZzX3RyZW5kaW5nJmN0PWc/ZJieMJ372LLjXsInfV/giphy.gif"],
    "Very Weak": [
        "https://media.giphy.com/media/v1.Y2lkPWVjZjA1ZTQ3c2M3bmZhY2xrbXd2cGw1eWlvbmdyOXQwbXdxZTZwcnR5MTE5cW5vNSZlcD12MV9naWZzX3RyZW5kaW5nJmN0PWc/QZyBvNVaMbIZ9yadec/giphy.gif"
    ],
}

FALLBACK_EMOJI = {"Very Strong": "😎🏆", "Strong": "💪", "Medium": "😐", "Weak": "😬", "Very Weak": "💀☠️"}

MESSAGES = {
    "Very Strong": "Absolute unit of a password. Hackers just quit their jobs. 🏆",
    "Strong": "Pretty solid! A hacker would need to skip lunch to crack this. 💪",
    "Medium": "Mid. Like pineapple on pizza: some people accept it, experts don't. 🍕",
    "Weak": "Bro... a toddler with a laptop could guess this. 😬",
    "Very Weak": "THIS PASSWORD HAS BEEN ALREADY HACKED IN YOUR DREAMS. 💀",
}

COMMON = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "111111", "123123",
    "admin", "letmein", "welcome", "monkey", "dragon", "iloveyou", "sunshine", "princess",
    "football", "baseball", "login", "master", "hello", "freedom", "whatever", "trustno1",
    "passw0rd", "password1", "1234567890", "000000", "qwerty123", "superman", "batman",
    "shadow", "michael", "pakistan", "karachi", "ali123", "ahmed123", "zaq12wsx", "1q2w3e4r",
}

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm", "0123456789"]
LEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "@": "a", "$": "s", "5": "s", "7": "t"})
WORDS = ["pizza", "turtle", "laser", "banana", "rocket", "ninja", "pickle", "cactus", "wizard", "taco",
         "dragon", "coffee", "panda", "thunder", "noodle", "galaxy", "robot", "cookie", "sphinx", "mango",
         "viking", "bubble", "jelly", "castle", "falcon", "marshmallow", "sandwich", "unicorn", "zombie", "biryani"]

GUESSES_PER_SEC = 1e10  # offline attack, fast hash on a GPU rig


# ---------------------------------------------------------------------------
# Analysis logic
# ---------------------------------------------------------------------------
def pool_size(pw: str) -> int:
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
    found = []
    low = pw.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - 3):
            chunk = seq[i:i + 4]
            if chunk in low or chunk[::-1] in low:
                found.append("Keyboard/alphabet/number sequence (e.g. 'qwer', '1234')")
                break
        else:
            continue
        break
    if re.search(r"(.)\1{2,}", pw):
        found.append("Repeated characters (e.g. 'aaa', '111')")
    if re.search(r"(19|20)\d{2}", pw):
        found.append("Contains a year (birthdays/years are easy guesses)")
    if low.translate(LEET) in COMMON or low in COMMON:
        found.append("Common password (even with l33t substitutions)")
    return found


def format_time(seconds: float) -> str:
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
    return dict(length=length, entropy=entropy, raw_entropy=raw_entropy, score=score, level=level,
                checks=checks, patterns=patterns, crack_time=format_time(crack_seconds), pool=size)


def check_breach(pw: str):
    """HaveIBeenPwned k-anonymity: only the first 5 chars of the SHA-1 hash leave this app."""
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
    return "-".join(secrets.choice(WORDS) for _ in range(n)) + "-" + str(secrets.randbelow(900) + 100)


# ---------------------------------------------------------------------------
# Theming: dark & spooky when weak, bright & party mode when strong
# ---------------------------------------------------------------------------
LIGHT_CSS = """
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp p, .stApp label, .stApp li,
.stApp div[data-testid="stMetricValue"], .stApp div[data-testid="stMetricLabel"],
.stApp div[data-testid="stCaptionContainer"], .stApp div[data-testid="stMarkdownContainer"] * {
    color: #000000 !important; }
.stTextInput input { color: #000000 !important; background: #ffffff !important; border: 1px solid #000000; }
.stApp pre, .stApp code { background: #f0f2f6 !important; color: #000000 !important; }
.stApp pre span { color: #000000 !important; }
.stApp .stButton button { background: #f0f2f6 !important; border: 1px solid #999999 !important; }
.stApp .stButton button p { color: #000000 !important; }
header[data-testid="stHeader"] { background: transparent; }
"""


def apply_theme(level):
    """level: weak/strong levels trigger effects; None or Medium = plain white page, black text."""
    if level in ("Very Weak", "Weak"):
        glow = "#ff1f1f" if level == "Very Weak" else "#ff7a1f"
        css = f"""
        .stApp {{ background: radial-gradient(circle at top, #1a0000 0%, #000 70%); }}
        .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp p, .stApp label, .stApp span, .stApp li,
        .stApp div[data-testid="stMetricValue"], .stApp div[data-testid="stMetricLabel"],
        .stApp div[data-testid="stCaptionContainer"] {{
            color: {glow} !important; font-family: 'Courier New', monospace; text-shadow: 0 0 6px {glow}55; }}
        .stTextInput input {{ background: #111 !important; color: {glow} !important; border: 1px solid {glow}; }}
        .stApp pre, .stApp code {{ background: #111 !important; color: {glow} !important; }}
        .stApp pre span {{ color: {glow} !important; }}
        .stApp .stButton button {{ background: #111 !important; border: 1px solid {glow} !important; }}
        .stApp .stButton button p {{ color: {glow} !important; }}
        header[data-testid="stHeader"] {{ background: transparent; }}
        """
    elif level in ("Very Strong", "Strong"):
        css = ".stApp { background: linear-gradient(135deg, #fdfbfb 0%, #c3f0ca 50%, #a1c4fd 100%); }" + LIGHT_CSS
    else:
        css = ".stApp { background: #ffffff; }" + LIGHT_CSS
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def show_gif(level: str):
    urls = GIFS.get(level, [])
    if not urls:
        return
    url = secrets.choice(urls)
    emoji = FALLBACK_EMOJI[level]
    html = f"""
    <div style="text-align:center">
      <img src="{url}" style="max-width:100%;max-height:340px;border-radius:14px;"
           onerror="this.outerHTML='<div style=&quot;font-size:90px&quot;>{emoji}</div>'">
    </div>"""
    st.markdown(html, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
PAGES = ["🔍 Analyzer", "🎲 Generator", "🔑 Hashing Demo", "💥 Brute-Force Sim", "📘 About Project"]
page = st.radio("Navigation", PAGES, horizontal=True, label_visibility="collapsed")
if page != PAGES[0]:
    apply_theme(None)  # simple white page, black text everywhere except the Analyzer

if page == PAGES[0]:
    # placeholder so theme can be decided after we read the password
    theme_slot = st.empty()
    st.title("🔐 Password Roast Analyzer")
    st.caption("Type a password. We'll judge you. Nothing is stored or logged.")

    show = st.checkbox("Show password")
    pw = st.text_input("Enter a password", type="default" if show else "password",
                       placeholder="e.g. ilovepizza123")

    if pw:
        res = analyze(pw)
        with theme_slot:
            apply_theme(res["level"])

        st.subheader(f"Verdict: {res['level']}")
        st.progress(res["score"] / 100, text=f"Score {res['score']}/100")
        st.write(MESSAGES[res["level"]])
        show_gif(res["level"])
        if res["level"] == "Very Strong":
            st.balloons()
        elif res["level"] == "Very Weak":
            st.snow()

        c1, c2, c3 = st.columns(3)
        c1.metric("Length", res["length"])
        c2.metric("Entropy (bits)", f"{res['entropy']:.1f}")
        c3.metric("Crack time*", res["crack_time"])
        st.caption("*Offline attack at 10 billion guesses/second (GPU vs. fast hash).")

        st.markdown("#### ✅ Checklist")
        for name, ok in res["checks"].items():
            st.write(("✅ " if ok else "❌ ") + name)

        if res["patterns"]:
            st.markdown("#### ⚠️ Problems found")
            for p in res["patterns"]:
                st.write("• " + p)

        st.markdown("#### 🕵️ Has it been leaked?")
        if st.button("Check in known data breaches"):
            with st.spinner("Asking HaveIBeenPwned (only a partial hash is sent)..."):
                hits = check_breach(pw)
            if hits is None:
                st.warning("Couldn't reach the breach database. Try again later.")
            elif hits == 0:
                st.success("Not found in known breaches. Nice!")
            else:
                st.error(f"Found {hits:,} times in leaked databases. Never use this one!")
    else:
        with theme_slot:
            apply_theme(None)
        st.info("Waiting for a password... don't be shy 👀")

if page == PAGES[1]:
    st.header("🎲 Generate a strong password")
    length = st.slider("Length", 8, 40, 16)
    a, b, c = st.columns(3)
    up = a.checkbox("Uppercase", True)
    dg = b.checkbox("Numbers", True)
    sy = c.checkbox("Symbols", True)
    if st.button("Generate password"):
        st.session_state["gen"] = generate_password(length, up, dg, sy)
    if st.button("Generate funny passphrase"):
        st.session_state["gen"] = generate_passphrase()
    if "gen" in st.session_state:
        st.code(st.session_state["gen"], language=None)
        g = analyze(st.session_state["gen"])
        st.write(f"Strength: **{g['level']}** · Entropy: **{g['entropy']:.0f} bits**")
    st.caption("Uses Python's `secrets` module (cryptographically secure randomness).")

if page == PAGES[2]:
    st.header("🔑 Password Hashing Demonstration")
    st.write("A secure website never stores your password. It stores a **hash**: a one-way fingerprint "
             "that can't be reversed. Change one letter below and watch the whole hash change.")
    hpw = st.text_input("Text to hash", value="password123", key="hash_in")
    if hpw:
        data = hpw.encode("utf-8")
        st.markdown("#### 1. Fast hashes (hashlib): fine for files, bad for passwords")
        for algo in ["md5", "sha1", "sha256", "sha512"]:
            st.write(f"**{algo.upper()}**")
            st.code(hashlib.new(algo, data).hexdigest(), language=None)

        st.markdown("#### 2. Salting: random data added before hashing")
        salt = secrets.token_hex(8)
        st.code(f"salt    : {salt}\nSHA-256 : {hashlib.sha256((salt + hpw).encode()).hexdigest()}", language=None)
        st.caption("Without a salt, two users with the same password get the same hash, and attackers "
                   "can use precomputed rainbow tables. A fresh salt per user defeats that.")

        st.markdown("#### 3. bcrypt: salted AND deliberately slow (the right way)")
        cost = st.slider("Cost factor (each +1 doubles the time)", 4, 13, 10)
        if st.button("Hash with bcrypt"):
            pw_b = data[:72]  # bcrypt only uses the first 72 bytes
            t0 = time.time()
            h1 = bcrypt.hashpw(pw_b, bcrypt.gensalt(rounds=cost))
            elapsed = time.time() - t0
            h2 = bcrypt.hashpw(pw_b, bcrypt.gensalt(rounds=cost))
            st.write("Same password hashed twice gives **different** hashes (random salt):")
            st.code(f"{h1.decode()}\n{h2.decode()}", language=None)
            st.write(f"⏱️ One hash took **{elapsed:.3f} s**. Fine for one login, "
                     "painful for an attacker trying billions of guesses.")
            st.write(f"Verify with the correct password: **{bcrypt.checkpw(pw_b, h1)}** · "
                     f"with a wrong password: **{bcrypt.checkpw(b'wrong-password', h1)}**")

if page == PAGES[3]:
    st.header("💥 Brute-Force Attack Simulation")
    st.warning("Controlled demo: it only attacks the password you type here, and stops after 2 million guesses.")
    MAX_ATTEMPTS = 2_000_000
    mode = st.radio("Attack type", ["Dictionary attack", "Brute-force attack"], horizontal=True)
    target = st.text_input("Target password (keep it short for brute force)", key="bf_pw")

    charsets = {
        "Digits (10)": string.digits,
        "Lowercase letters (26)": string.ascii_lowercase,
        "Lowercase + digits (36)": string.ascii_lowercase + string.digits,
    }
    if mode == "Brute-force attack":
        cs_name = st.selectbox("Attacker's character set", list(charsets))
        max_len = st.slider("Maximum length the attacker tries", 1, 6, 4)

    if st.button("Launch attack 🚀"):
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
                    st.error(f"💀 CRACKED: '{found}' after {attempts} guesses in {time.time() - start:.4f} s")
                else:
                    st.success(f"Survived all {attempts} common passwords. A bigger wordlist might still win.")
            else:
                charset = charsets[cs_name]
                if len(target) > max_len or any(ch not in charset for ch in target):
                    st.info("This password is outside the attacker's character set or length limit, "
                            "so this attack can't crack it. That's exactly why longer and more varied passwords win.")
                else:
                    keyspace = sum(len(charset) ** n for n in range(1, max_len + 1))
                    st.write(f"Search space: **{keyspace:,}** possible passwords.")
                    bar = st.progress(0.0, text="Cracking...")
                    start, attempts, found = time.time(), 0, None
                    done = False
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
                        st.error(f"💀 CRACKED: '{found}' after {attempts:,} guesses in {elapsed:.2f} s "
                                 f"(~{speed:,.0f} guesses/s)")
                    else:
                        st.success(f"Not cracked within {attempts:,} guesses ({elapsed:.1f} s).")
                    st.write(f"Worst case for this search space on this server: **{format_time(keyspace / speed)}**. "
                             f"A GPU rig (10 billion guesses/s): **{format_time(keyspace / GUESSES_PER_SEC)}**.")
    st.caption("Lesson: every extra character multiplies the work. Slow hashes like bcrypt make each guess costly too.")

if page == PAGES[4]:
    st.header("📘 About this project")
    st.markdown("""
**Course:** Information Security · **Program:** BS Data Science, 3rd Semester · **Group E**

### ✨ Main features
1. Password Strength Checker
2. Common Password Detector
3. Password Entropy Analyzer
4. Secure Password Generator
5. Password Hashing Demonstration (hashlib + bcrypt)
6. Brute-Force Attack Simulation (dictionary + brute force)

### 🎯 Objective
Most people pick passwords that are easy to remember and, unfortunately, easy to crack.
This tool analyzes a password, explains *why* it is weak or strong, estimates how long an attacker
would need, and makes security fun with memes and a dark/bright theme.

### ⚙️ How it works
1. **Character pool:** we detect which character types are used (lowercase 26, uppercase 26, digits 10, symbols ~33).
2. **Entropy:** `Entropy = Length × log2(Pool size)` bits. More bits = exponentially more guesses.
3. **Pattern penalties:** sequences (`qwerty`, `1234`), repeats (`aaa`), years, and common passwords
   (including l33t like `p@ssw0rd`) reduce the entropy.
4. **Crack time:** `2^entropy / 2 / guesses per second` (average case, 10¹⁰ guesses/sec).
5. **Score & verdict:** entropy is mapped to 0–100 and 5 levels: Very Weak, Weak, Medium, Strong, Very Strong.
6. **Breach check (optional):** uses the HaveIBeenPwned *k-anonymity* API. Only the first 5 characters
   of the SHA-1 hash are sent, so your real password never leaves the app.
7. **Fun layer:** weak password → dark horror theme + snow; strong password → bright theme, balloons and a meme GIF.

### 🔒 Information security concepts demonstrated
- Password entropy and brute-force attacks
- Dictionary attacks and common-password lists
- Hashing (SHA-1) and k-anonymity for privacy-preserving lookups
- Cryptographically secure random generation (`secrets`)
- Salting, and slow adaptive hashing with bcrypt vs. fast hashes (MD5/SHA)
- Dictionary and brute-force attacks, and why search space and hash speed matter
- Secure design: no storage, no logging of passwords

### 🧰 Tech stack
Python 3 · Streamlit · hashlib · bcrypt · Requests · secrets · regex

### ⚠️ Limitations
- Crack-time values are estimates; real attackers use smarter rules and wordlists.
- The common-password list is small (a real tool would use millions of entries).
- Do not type your real, important passwords into any website you don't control. Test with similar ones.

### 🚀 Future work
Larger wordlists, zxcvbn integration, multi-language support, password-policy checker for organizations.

### 👥 Team members
""")
    st.table({"Name": ["Umm e Hani", "Muznah Khan", "M. Hasaan Hassan Khan", "Hiba"],
              "Roll No.": ["25F-DS-018", "25F-DS-002", "25F-DS-012", "25F-DS-013"],
              "Role": ["Strength checker & entropy", "UI, theming & memes", "Hashing demo & brute-force sim",
                       "Generator, testing & documentation"]})
    st.caption("Project: Password Security Analyzer · Subject: Information Security")
