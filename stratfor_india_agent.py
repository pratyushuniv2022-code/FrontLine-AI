import os
import re
import json
from datetime import datetime
from dotenv import load_dotenv
from exa_py import Exa

# ------------------ CONFIG ------------------
load_dotenv()
EXA_API_KEY = os.getenv("EXA_API_KEY")  # Your Exa.ai API key
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "latest_raw.json")
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
MAX_RESULTS_PER_QUERY = 20
INDIA_BOOST_FACTOR = 1.6

# ------------------ KEYWORDS & REGIONS ------------------
KEYWORD_WEIGHTS = {
    r"\b(nuclear|atomic|radiation|chemical attack|chemical spill|biological attack|cbrn)\b": 8,
    r"\b(ballistic missile|missile strike|icbm|slbm|rocket artillery|airstrike|air strike)\b": 6,
    r"\b(attack|assault|ambush|strike|cross[- ]border shelling|cross[- ]border|incursion|infiltrat|raid)\b": 6,
    r"\b(LoC|L\.?O\.?C\.?|Line of Control|LAC|L\.?A\.?C\.?|Line of Actual Control|Sino[- ]India|China[- ]India|Pakistan[- ]India|border clash|ceasefire violation)\b": 6,
    r"\b(ceasefire violation|cease[- ]fire|ceasefire breach)\b": 5,
    r"\b(Lashkar|Jaish|JeM|LeT|Indian Mujahideen|Naxal|Maoist|Naxalite|ULFA|insurgenc|terrorist|terror attack|IED|bombing)\b": 6,
    r"\b(protest|demonstration|mass protest|farmers protest|bandh|hartal|strike|civil unrest|communal violence|riots|mob violence|clash with police)\b": 4,
    r"\b(farmers protest|farm laws|agitation|land dispute)\b": 3,
    r"\b(power outage|blackout|grid failure|grid collapse|dam breach|bridge collapse|infrastructure damage|port closure|logistics disruption)\b": 5,
    r"\b(fuel shortage|petrol shortage|diesel shortage|fuel supply|crude oil spike|energy crisis|refinery fire|pipeline attack|pipeline blast)\b": 5,
    r"\b(sanction|embargo|trade restriction|tariff change|supply chain disruption|shipping disruption|port blockade|chokepoint|Strait of Hormuz|Bab el Mandeb)\b": 4,
    r"\b(Indian Ocean|Bay of Bengal|Arabian Sea|Andaman|Nicobar|IOR|maritime incident|vessel seizure|piracy|fishing boat attack|naval clash)\b": 4,
    r"\b(cyberattack|ransomware|ddos|data breach|critical infrastructure hack|power grid hack)\b": 5,
    r"\b(evacuat|displaced|displacement|refugee|humanitarian|internally displaced)\b": 4,
    r"\b(cyclone|flood|cloudburst|landslide|earthquake|tsunami|monsoon surge|drought|heatwave)\b": 4,
    r"\b(food shortage|grain shortage|crop failure|famine|inflation spike|bank run|currency crash)\b": 3,
    r"\b(declare emergency|martial law|state of emergency|diplomatic expulsion|sanction|trade embargo|major cabinet reshuffle)\b": 4,
    r"\b(unverified|unconfirmed report|possible|probable|alleged|reports of)\b": 1
}

INDIA_REGION_PATTERNS = [
    r"\bIndia\b", r"\bRepublic of India\b",
    r"\bNew Delhi\b", r"\bDelhi\b", r"\bMumbai\b", r"\bKolkata\b", r"\bChennai\b", r"\bBengaluru\b",
    r"\bKashmir\b", r"\bJammu\b", r"\bLadakh\b", r"\bPunjab\b", r"\bRajasthan\b",
    r"\bAssam\b", r"\bArunachal\b", r"\bNagaland\b", r"\bManipur\b", r"\bMizoram\b",
    r"\bWest Bengal\b", r"\bOdisha\b", r"\bGujarat\b", r"\bAndhra Pradesh\b",
    r"\bBay of Bengal\b", r"\bIndian Ocean\b", r"\bAndaman\b", r"\bNicobar\b",
    r"\bChina\b", r"\bPakistan\b", r"\bMyanmar\b", r"\bBangladesh\b", r"\bNepal\b", r"\bSri Lanka\b"
]

# ------------------ HELPER FUNCTIONS ------------------
def clean_text(text):
    return re.sub(r"\s+", " ", str(text)).strip() if text else ""

def compute_severity_score(text):
    s = (text or "").lower()
    score = 0
    for pat, wt in KEYWORD_WEIGHTS.items():
        matches = re.findall(pat, s, flags=re.IGNORECASE)
        if matches:
            score += len(matches) * wt
    # Boost if India region mentioned
    for pat in INDIA_REGION_PATTERNS:
        if re.search(pat, text, flags=re.IGNORECASE):
            score *= INDIA_BOOST_FACTOR
            break
    return int(score)

def score_to_label(score):
    if score >= 8:
        return "critical"
    if score >= 5:
        return "high"
    if score >= 2:
        return "medium"
    return "low"

# ------------------ EXA.AI INTEGRATION ------------------
exa = Exa(EXA_API_KEY)

def exa_search_and_fetch(query, max_results=MAX_RESULTS_PER_QUERY):
    """
    Uses Exa.ai to search and fetch full content.
    Returns list of dicts with url, title, snippet, full_text, score, label.
    """
    search_results = exa.search_and_contents(query, text=True, num_results=max_results)
    articles = []

    # Iterate over SearchResponse.results
    for result in search_results.results:
        url = getattr(result, "url", "")
        title = clean_text(getattr(result, "title", ""))
        # Exa may not provide snippet; fallback to empty
        snippet = clean_text(getattr(result, "snippet", "") or getattr(result, "summary", ""))
        # Full content may be in 'text', 'content', or 'body'
        full_text = clean_text(
            getattr(result, "text", None) or getattr(result, "content", None) or getattr(result, "body", "")
        )
        score = compute_severity_score(full_text)
        label = score_to_label(score)

        articles.append({
            "url": url,
            "title": title,
            "snippet": snippet,
            "full_text": full_text,
            "score": score,
            "label": label
        })
    return articles

# ------------------ MONITORING ------------------
SEARCH_QUERIES = [
    "site:worldview.stratfor.com India OR LoC OR LAC OR Pakistan OR China",
    "site:worldview.stratfor.com India insurgency OR Naxal OR Maoist OR terrorism",
    "site:worldview.stratfor.com India civil unrest OR protest OR communal violence",
    "site:worldview.stratfor.com India power outage OR infrastructure failure OR grid collapse",
    "site:worldview.stratfor.com India cyberattack OR critical infrastructure hack",
    "site:worldview.stratfor.com India natural disaster OR cyclone OR flood OR earthquake",
    "site:worldview.stratfor.com India economic disruption OR food shortage OR fuel shortage OR Trump tarrifs"
]

def run_agent():
    all_articles = []

    print("Starting Stratfor → India-focused monitoring agent\n")
    for idx, query in enumerate(SEARCH_QUERIES, start=1):
        print(f"[{idx}/{len(SEARCH_QUERIES)}] Searching: {query}")
        try:
            articles = exa_search_and_fetch(query)
            print(f"  -> Found {len(articles)} articles")
            all_articles.extend(articles)
        except Exception as e:
            print(f"  ⚠ Error fetching results for query: {e}")

    # Remove duplicates by URL
    seen = set()
    unique_articles = []
    for a in all_articles:
        if a["url"] not in seen:
            unique_articles.append(a)
            seen.add(a["url"])

    # Sort by score descending
    unique_articles.sort(key=lambda x: x["score"], reverse=True)

    # Save JSON output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique_articles, f, indent=2, ensure_ascii=False)

    # Summary
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in unique_articles:
        counts[a["label"]] += 1

    print("\n=== Summary ===")
    print(f"Total articles: {len(unique_articles)}")
    print(f"By severity: {counts}")
    print(f"Output JSON: {os.path.abspath(OUTPUT_FILE)}")
    print("Done.")

# ------------------ MAIN ------------------
if __name__ == "__main__":
    run_agent()
