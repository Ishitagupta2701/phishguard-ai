"""Generate a synthetic labelled URL dataset (data/urls.csv).

NOTE: This is for demonstration so the project runs offline. For real-world
accuracy, replace data/urls.csv with a real dataset (PhishTank / OpenPhish for
phishing URLs, Tranco top-sites list for legitimate ones) using the same
columns: url,label   (label: 1 = phishing, 0 = legitimate).
"""
import csv
import os
import random
import string

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "amazon.in", "flipkart.com",
    "github.com", "stackoverflow.com", "microsoft.com", "apple.com", "linkedin.com",
    "twitter.com", "reddit.com", "bbc.co.uk", "nytimes.com", "python.org",
    "mozilla.org", "paypal.com", "netflix.com", "dropbox.com", "zoom.us",
    "irctc.co.in", "sbi.co.in", "hdfcbank.com", "icicibank.com", "gov.in",
    "nptel.ac.in", "coursera.org", "medium.com", "spotify.com", "adobe.com",
    "cloudflare.com", "openai.com", "w3schools.com", "khanacademy.org", "imdb.com",
]
LEGIT_PATHS = [
    "", "/", "/about", "/contact", "/products", "/blog/how-to-learn-python",
    "/search?q=machine+learning", "/docs/getting-started", "/help/faq",
    "/news/2025/10/top-stories", "/user/profile", "/careers", "/pricing",
    "/watch?v=dQw4w9WgXcQ", "/login", "/account/settings", "/support",
]
BRANDS = ["paypal", "amazon", "google", "microsoft", "apple", "netflix",
          "sbi", "hdfc", "icici", "facebook", "instagram", "dropbox"]
KEYWORDS = ["login", "verify", "secure", "account", "update", "confirm",
            "signin", "banking", "password", "billing", "suspend", "wallet"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "click", "work", "icu", "cam", "info", "online"]
SHORT = ["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd"]


def rnd(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    if random.random() < 0.15:
        domain = "www." + domain
    elif random.random() < 0.08:
        domain = random.choice(["mail", "docs", "blog", "support"]) + "." + domain
    scheme = "https" if random.random() < 0.93 else "http"
    return f"{scheme}://{domain}{random.choice(LEGIT_PATHS)}"


def phishing_url():
    brand = random.choice(BRANDS)
    kw = random.choice(KEYWORDS)
    kind = random.randint(0, 7)
    scheme = "http" if random.random() < 0.7 else "https"
    tld = random.choice(BAD_TLDS)
    if kind == 0:  # IP address host
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        return f"http://{ip}/{brand}/{kw}.php?id={rnd(8)}"
    if kind == 1:  # brand in subdomain of unrelated domain
        return f"{scheme}://{brand}.{kw}.{rnd(7)}.{tld}/{kw}/{rnd(5)}"
    if kind == 2:  # hyphenated look-alike
        return f"{scheme}://{brand}-{kw}-{rnd(4)}.{tld}/index.html"
    if kind == 3:  # @ trick
        return f"{scheme}://www.{brand}.com@{rnd(8)}.{tld}/{kw}"
    if kind == 4:  # many subdomains
        subs = ".".join(random.choices(["secure", "login", "web", "my", "id", brand], k=4))
        return f"{scheme}://{subs}.{rnd(6)}.com/{kw}?session={rnd(16)}"
    if kind == 5:  # shortener
        return f"http://{random.choice(SHORT)}/{rnd(7)}"
    if kind == 6:  # typo-squat with long path
        typo = brand[:-1] + random.choice("01l") + brand[-1:]
        return f"{scheme}://{typo}.com/{kw}/{rnd(6)}/{kw}.html?user={rnd(10)}&token={rnd(20)}"
    # kind == 7: odd port + keywords
    return f"http://{brand}-{kw}.{rnd(5)}.{tld}:8080/{kw}/{kw}.php"


def main():
    os.makedirs("data", exist_ok=True)
    rows = [(legit_url(), 0) for _ in range(2500)]
    rows += [(phishing_url(), 1) for _ in range(2500)]
    # Label noise (~2%) so the model doesn't look unrealistically perfect.
    rows = [(u, 1 - l) if random.random() < 0.02 else (u, l) for u, l in rows]
    random.shuffle(rows)
    with open("data/urls.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(rows)
    print(f"Wrote {len(rows)} rows to data/urls.csv")


if __name__ == "__main__":
    main()
