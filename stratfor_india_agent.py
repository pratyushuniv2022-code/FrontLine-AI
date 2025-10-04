import os
import re
import json
import asyncio
from datetime import datetime
from dotenv import load_dotenv
from exa_py import Exa

# ------------------ CONFIG ------------------
load_dotenv()
EXA_API_KEY = os.getenv("EXA_API_KEY")  # Your Exa.ai API key
if not EXA_API_KEY:
    raise RuntimeError("EXA_API_KEY is missing. Set it as an env var / GitHub Actions secret.")

# write into repo/data for the workflow
BASE_DIR = os.path.join(os.getcwd(), "data")  # <- write inside repo /data
os.makedirs(BASE_DIR, exist_ok=True)

OUTPUT_FILE = os.path.join(BASE_DIR, "latest_raw.json")

# performance tweaks
MAX_RESULTS_PER_QUERY = int(os.getenv("MAX_RESULTS", 10))         # ↓ from 20 for faster runs
INDIA_BOOST_FACTOR = 1.6
MAX_CONCURRENCY = 4                 # limit concurrent Exa calls

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

# ------------------ HELPERS ------------------
def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text)).strip() if text else ""

def compute_severity_score(text: str) -> int:
    s = (text or "").lower()
    score = 0
    for pat, wt in KEYWORD_WEIGHTS.items():
        hits = re.findall(pat, s, flags=re.IGNORECASE)
        if hits:
            score += len(hits) * wt
    for pat in INDIA_REGION_PATTERNS:
        if re.search(pat, text or "", flags=re.IGNORECASE):
            score *= INDIA_BOOST_FACTOR
            break
    return int(score)

def score_to_label(score: int) -> str:
    if score >= 8: return "critical"
    if score >= 5: return "high"
    if score >= 2: return "medium"
    return "low"

# ------------------ EXA.AI ------------------
exa = Exa(EXA_API_KEY)

def _exa_fetch_sync(query: str, max_results: int) -> list[dict]:
    """Blocking fetch for a single query; wrapped in a thread by asyncio."""
    out = []
    resp = exa.search_and_contents(query, text=True, num_results=max_results)
    for r in getattr(resp, "results", []) or []:
        url = getattr(r, "url", "")
        title = clean_text(getattr(r, "title", ""))
        snippet = clean_text(getattr(r, "snippet", "") or getattr(r, "summary", ""))
        full_text = clean_text(getattr(r, "text", None) or getattr(r, "content", None) or getattr(r, "body", ""))
        score = compute_severity_score(full_text)
        out.append({
            "url": url,
            "title": title,
            "snippet": snippet,
            "full_text": full_text,
            "score": score,
            "label": score_to_label(score),
        })
    return out

async def exa_search_and_fetch(query: str, sem: asyncio.Semaphore) -> list[dict]:
    async with sem:
        try:
            return await asyncio.to_thread(_exa_fetch_sync, query, MAX_RESULTS_PER_QUERY)
        except Exception as e:
            print(f"  ⚠ Error fetching '{query}': {e}")
            return []

# ------------------ MONITORING ------------------
SEARCH_QUERIES = [
    "site:worldview.stratfor.com India OR LoC OR LAC OR Pakistan OR China",
    "site:worldview.stratfor.com India insurgency OR Naxal OR Maoist OR terrorism",
    "site:worldview.stratfor.com India civil unrest OR protest OR communal violence",
    "site:worldview.stratfor.com India power outage OR infrastructure failure OR grid collapse",
    "site:worldview.stratfor.com India cyberattack OR critical infrastructure hack",
    "site:worldview.stratfor.com India natural disaster OR cyclone OR flood OR earthquake",
    "site:worldview.stratfor.com India economic disruption OR food shortage OR fuel shortage OR Trump tarrifs",
]

async def run_agent_async():
    print("Starting Stratfor → India-focused monitoring agent (concurrent)\n")
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    tasks = [exa_search_and_fetch(q, sem) for q in SEARCH_QUERIES]
    results_per_query = await asyncio.gather(*tasks)

    # flatten
    all_articles = [item for sub in results_per_query for item in sub]

    # dedupe by URL
    seen, unique = set(), []
    for a in all_articles:
        if a["url"] and a["url"] not in seen:
            seen.add(a["url"])
            unique.append(a)

    # sort by severity score desc
    unique.sort(key=lambda x: x["score"], reverse=True)

    # write JSON
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(unique, f, indent=2, ensure_ascii=False)

    # print summary
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in unique:
        counts[a["label"]] += 1

    print("\n=== Summary ===")
    print(f"Total unique articles: {len(unique)}")
    print(f"By severity: {counts}")
    print(f"Output JSON: {os.path.abspath(OUTPUT_FILE)}")
    print("Done.")

def run_agent():
    asyncio.run(run_agent_async())

# ------------------ MAIN ------------------
if __name__ == "__main__":
    run_agent()
