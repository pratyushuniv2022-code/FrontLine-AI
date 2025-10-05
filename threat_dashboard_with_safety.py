# threat_dashboard_with_safety.py
import os
import re
import json
import uuid
import time
import hashlib
import random
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

import requests
import streamlit as st
import pandas as pd
from rake_nltk import Rake
from wordcloud import WordCloud
import matplotlib.pyplot as plt
import plotly.express as px
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
import io
import openpyxl  # ensure engine available

# =========================================================
# Setup & Config
# =========================================================
load_dotenv()  # so PUSHOVER_*, CEREBRAS_*, OPENAI_* etc. are available

st.set_page_config(page_title="India-Focused Threat Dashboard", layout="wide")

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USER_SNAPSHOTS_DIR = "user_snapshots"
os.makedirs(USER_SNAPSHOTS_DIR, exist_ok=True)

# Directories
BASE_DIR = Path(__file__).parent.resolve()
LLM_CACHE_DIR = BASE_DIR / "llm_cache"; LLM_CACHE_DIR.mkdir(exist_ok=True)
EXCEL_AGENT_DIR = BASE_DIR / "excel_agent_data"; EXCEL_AGENT_DIR.mkdir(exist_ok=True)
CRIME_LOG_DIR = BASE_DIR / "crime_agent_logs"; CRIME_LOG_DIR.mkdir(exist_ok=True)
SAFETY_LOG_DIR = BASE_DIR / "safety_logs"; SAFETY_LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR = BASE_DIR / "admin_reports"; REPORTS_DIR.mkdir(exist_ok=True)

SAFETY_JSONL = SAFETY_LOG_DIR / "safety_event_log.jsonl"
SAFETY_PRETTY = SAFETY_LOG_DIR / "last_safety_event.pretty.json"

DAILY_ROLLING = True

def is_valid_email(e: str) -> bool:
    return isinstance(e, str) and bool(EMAIL_REGEX.match(e))


# =========================================================
# Safety Monitor (stealth) — with optional LLM & Pushover
# =========================================================
UNSAFE_KEYWORDS = [
    "bomb", "blast", "attack", "assassinate", "terror", "explode",
    "weapon", "kill", "murder", "drugs", "gun", "nuke", "improvised explosive"
]
MED_RISK_PATTERNS = [
    r"\bdispose\s+of\b",
    r"\bhide\s+(?:the|a)\s+body\b",
    r"\bhow\s+to\s+avoid\s+(?:cameras|forensics|law\s+enforcement)\b",
    r"\bdisable\s+(?:alarms|cctv|security)\b",
    r"\b\d+\s*kg\s+of\s+meat\b",
]
MED_RISK_RE = re.compile("|".join(MED_RISK_PATTERNS), re.I)

def get_public_ip(timeout=5):
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=timeout)
        r.raise_for_status()
        return r.json().get("ip", "unknown")
    except Exception:
        return "unknown"

def get_geo_from_ip(ip: str, timeout=5):
    try:
        url = f"https://ipapi.co/{ip}/json/" if ip and ip != "unknown" else "https://ipapi.co/json/"
        r = requests.get(url, timeout=timeout)
        data = r.json() if r.ok else {}
        return {
            "country": data.get("country_name") or data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "org": data.get("org") or data.get("asn"),
        }
    except Exception:
        return {"country": None, "region": None, "city": None, "org": None}

def detect_unsafe_terms(query: str):
    if not isinstance(query, str) or not query.strip():
        return []
    q = query.lower()
    return [kw for kw in UNSAFE_KEYWORDS if re.search(rf"\b{re.escape(kw)}\b", q)]

def fast_rule_screen(query: str) -> str:
    hits = detect_unsafe_terms(query)
    if hits:
        return "high"
    if isinstance(query, str) and MED_RISK_RE.search(query or ""):
        return "medium"
    return "low"

def _get_llm_key() -> Optional[str]:
    # Optional LLM moderation; if no key, fallback to rule-only
    try:
        key = st.secrets.get("CEREBRAS_API_KEY") or st.secrets.get("OPENAI_API_KEY") or st.secrets.get("LLM_API_KEY")
    except Exception:
        key = None
    if not key:
        key = os.getenv("CEREBRAS_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
    return key

def call_llm_intent(query: str, model: Optional[str] = None, timeout: int = 40) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    key = _get_llm_key()
    if not key:
        return None, "No LLM key configured"
    use_cerebras = bool(os.getenv("CEREBRAS_API_KEY") or (hasattr(st, "secrets") and st.secrets.get("CEREBRAS_API_KEY")))
    endpoint = "https://api.cerebras.ai/v1/chat/completions" if use_cerebras else "https://api.openai.com/v1/chat/completions"
    model = model or ("llama-3.3-70b" if use_cerebras else "gpt-4o-mini")
    system = (
        "You are a security moderator. Analyze the user's SINGLE query and classify intent. "
        "Return STRICT JSON only with keys: risk_level (high|medium|low), "
        "intent (violent_harm|nonviolent_illegal|benign|uncertain), euphemism_detected (true/false), "
        "reason (short), action (block|warn|allow). "
        "If the query implies illegal acts via euphemism, set risk_level high and action block."
    )
    user = f"Query: {query}\n\nReturn JSON only."
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    payload = {"model": model, "messages": [{"role":"system","content":system},{"role":"user","content":user}],
               "temperature": 0.0, "max_tokens": 200}
    try:
        r = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
        if r.status_code >= 300:
            return None, f"LLM HTTP {r.status_code}: {r.text[:300]}"
        data = r.json()
        content = (data.get("choices", [{}])[0].get("message", {}).get("content", "") or "").strip()
        content = content.strip("`")
        try:
            parsed = json.loads(content)
        except Exception:
            m = re.search(r"(\{.*\})", content, flags=re.S)
            parsed = json.loads(m.group(1)) if m else {}
        return parsed, None
    except Exception as e:
        return None, str(e)

def assess_query(query: str, model: Optional[str] = None) -> Dict[str, Any]:
    rr = fast_rule_screen(query)
    if rr == "high":
        return {"action":"block","risk_level":"high","intent":"violent_harm",
                "reason":"High-risk keywords detected by rules","source":"rules","euphemism_detected":False}
    llm_out, err = call_llm_intent(query, model=model)
    if llm_out:
        action = llm_out.get("action", "warn")
        risk   = llm_out.get("risk_level", "medium")
        intent = llm_out.get("intent", "uncertain")
        euphem = bool(llm_out.get("euphemism_detected", False))
        reason = llm_out.get("reason", "LLM intent classification")
        if rr == "medium" and (risk == "low" or action == "allow"):
            risk, action = "medium", "warn"
        return {"action":action,"risk_level":risk,"intent":intent,"reason":reason,
                "source":"llm","euphemism_detected":euphem}
    if rr == "medium":
        return {"action":"warn","risk_level":"medium","intent":"uncertain",
                "reason":"LLM unavailable; medium-risk indicators by rules","source":"rules",
                "euphemism_detected":False}
    return {"action":"allow","risk_level":"low","intent":"benign","reason":"No risk indicators",
            "source":"rules","euphemism_detected":False}

def send_pushover_alert(title: str, message: str, priority: int = 0, url: str | None = None):
    user = os.getenv("PUSHOVER_USER_KEY"); token = os.getenv("PUSHOVER_APP_TOKEN")
    if not user or not token:
        print("Pushover: Missing PUSHOVER_USER_KEY/PUSHOVER_APP_TOKEN.")
        return False, "missing_creds"
    data = {"token": token, "user": user, "title": title, "message": message,
            "priority": priority, "sound": "siren" if priority == 1 else "gamelan"}
    if url:
        data["url"] = url; data["url_title"] = "View Logs"
    try:
        resp = requests.post("https://api.pushover.net/1/messages.json", data=data, timeout=10)
        ok = resp.ok and resp.json().get("status") == 1
        return ok, (None if ok else resp.text[:300])
    except Exception as e:
        return False, str(e)

def _write_safety_event(event: dict):
    with SAFETY_JSONL.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    with SAFETY_PRETTY.open("w", encoding="utf-8") as f:
        json.dump(event, f, indent=2, ensure_ascii=False)
    if DAILY_ROLLING:
        day = datetime.datetime.utcnow().strftime("%Y%m%d")
        daily_path = SAFETY_LOG_DIR / f"safety_events_{day}.jsonl"
        with daily_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

def safety_monitor_check(query: str, model_name: Optional[str] = None):
    if not query or not isinstance(query, str):
        return
    now = time.time(); cooldown_sec = 45
    last = st.session_state.get("_last_safety_alert_ts", 0)
    decision = assess_query(query, model=model_name)
    ip = "unknown"; geo = {"country": None, "region": None, "city": None, "org": None}
    try:
        ip = get_public_ip(timeout=5); time.sleep(0.7); geo = get_geo_from_ip(ip, timeout=5)
    except Exception:
        pass
    if decision.get("action") in ("block", "warn"):
        should_push = False
        if now - last >= cooldown_sec:
            st.session_state["_last_safety_alert_ts"] = now
            should_push = True
        event = {
            "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
            "session_id": st.session_state.get("_session_id") or uuid.uuid4().hex[:12],
            "ip": ip, "geo": geo,
            "query_excerpt": query[:160],
            "triggered_terms": detect_unsafe_terms(query),
            "decision": decision,
            "action": "flagged_and_alerted" if should_push else "flagged_logged_only",
        }
        st.session_state["_session_id"] = event["session_id"]
        try:
            _write_safety_event(event)
            if should_push:
                risk = decision.get("risk_level", "").upper()
                action = decision.get("action", "")
                city = geo.get("city") or "-"; region = geo.get("region") or "-"
                country = geo.get("country") or "-"; org = geo.get("org") or "-"
                triggered = ", ".join(event.get("triggered_terms", [])) or "None"
                title = f"⚠️ {risk} threat detected ({action})"
                msg = (f"Query: {query[:120]}\n"
                       f"🔎 Keywords: {triggered}\n"
                       f"🌍 Location: {city}, {region}, {country}\n"
                       f"🏢 Network: {org}\n"
                       f"🧭 IP: {ip}\n"
                       f"⏰ {event['timestamp_utc']}")
                send_pushover_alert(title, msg, priority=1 if decision.get('action') == 'block' else 0)
        except Exception as e:
            print(f"Safety alert error: {e}")


# =========================================================
# LLM cleanup/cache helpers (for article keyword refinement)
# =========================================================
def phrases_signature(df: pd.DataFrame, query: str) -> str:
    if df.empty:
        base = f"empty::{query or ''}"
    else:
        top = df[['phrase','score']].copy()
        top['phrase'] = top['phrase'].astype(str)
        top['score'] = pd.to_numeric(top['score'], errors='coerce').fillna(0).astype(int)
        top = top.head(50)
        base = json.dumps({"q": query or "", "items": top.to_dict(orient="records")}, sort_keys=True)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def load_llm_cache(sig: str) -> Optional[pd.DataFrame]:
    fp = LLM_CACHE_DIR / f"{sig}.json"
    if not fp.exists():
        return None
    try:
        df = pd.read_json(fp)
        if not {"normalized","weighted_score"}.issubset(df.columns):
            return None
        df["normalized"] = df["normalized"].astype(str)
        df["weighted_score"] = pd.to_numeric(df["weighted_score"], errors="coerce").fillna(0.0)
        return df
    except Exception:
        return None

def save_llm_cache(sig: str, df: pd.DataFrame) -> None:
    fp = LLM_CACHE_DIR / f"{sig}.json"
    try:
        df.to_json(fp, orient="records")
    except Exception:
        pass

def clear_llm_cache():
    for p in LLM_CACHE_DIR.glob("*.json"):
        try:
            p.unlink()
        except Exception:
            pass

def create_requests_session_with_retries(total_retries=3, backoff_factor=1.0, sfl=(500,502,503,504)):
    session = requests.Session()
    retries = Retry(total=total_retries, backoff_factor=backoff_factor,
                    status_forcelist=sfl, allowed_methods=frozenset(['POST','GET']),
                    raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter); session.mount("http://", adapter)
    return session

def call_llm_refine_with_retries(api_key: str, model: str, messages: List[Dict], timeout=90, max_tokens=800):
    url = "https://api.cerebras.ai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": 0.0}
    session = create_requests_session_with_retries(total_retries=3, backoff_factor=2.0)
    return session.post(url, headers=headers, json=payload, timeout=timeout)

def extract_json_from_text(text: str):
    if not isinstance(text, str): raise ValueError("No text to parse")
    s = text.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s, flags=re.I)
    s = re.sub(r"\s*```$", "", s)
    m = re.search(r"(\[\s*\{.*?\}\s*\])", s, flags=re.S) or re.search(r"(\[.*\])", s, flags=re.S) or re.search(r"(\{.*\})", s, flags=re.S)
    if m:
        return json.loads(m.group(1))
    if '[' in s and ']' in s:
        start, end = s.find('['), s.rfind(']')
        return json.loads(s[start:end+1])
    raise ValueError("No JSON found")

def get_llm_api_key():
    try:
        key = st.secrets.get("CEREBRAS_API_KEY") or st.secrets.get("LLM_API_KEY")
    except Exception:
        key = None
    if not key:
        key = os.getenv("CEREBRAS_API_KEY") or os.getenv("LLM_API_KEY")
    return key

def llm_clean_and_rank_phrases(top_phrases_df: pd.DataFrame, query: str, model: str = "llama-3.3-70b"):
    api_key = get_llm_api_key()
    if not api_key:
        return pd.DataFrame(), "No LLM API key"
    if top_phrases_df.empty:
        return pd.DataFrame(), "No phrases to refine"

    items = [{"phrase": str(r["phrase"]), "score": int(r.get("score", 1))} for _, r in top_phrases_df.head(20).iterrows()]

    system_msg = {
        "role": "system",
        "content": (
            "Clean messy keyphrases into short keywords/entities. Remove boilerplate "
            "(subscribe/read/ads/nav/PGP). Return JSON array ONLY with fields: "
            "original, normalized, category(geo|policy|military|economic|cyber|social|boilerplate|other), "
            "relevance_to_query (0..1 float)."
        )
    }
    user_msg = {
        "role": "user",
        "content": (
            f"Query: {query}\n"
            "Phrases (with counts):\n" + "\n".join([f"- {i['phrase']} (score {i['score']})" for i in items]) +
            "\nReturn JSON array only."
        )
    }

    try:
        resp = call_llm_refine_with_retries(api_key, model, [system_msg, user_msg], timeout=90, max_tokens=800)
    except Exception as e:
        return pd.DataFrame(), f"LLM HTTP error: {e}"

    raw = getattr(resp, "text", str(resp))
    if not (200 <= resp.status_code < 300):
        return pd.DataFrame(), f"LLM non-2xx {resp.status_code}: {raw[:800]}"

    try:
        parsed = extract_json_from_text(raw)
        df = pd.DataFrame(parsed)
    except Exception as e:
        return pd.DataFrame(), f"Parse error: {e}\nRAW:\n{raw[:1500]}"

    for c in ["original","normalized","category","relevance_to_query"]:
        if c not in df.columns: df[c] = None

    df["original"] = df["original"].astype(str)
    df["normalized"] = df["normalized"].astype(str)
    df["category"] = df["category"].astype(str)
    df["relevance_to_query"] = pd.to_numeric(df["relevance_to_query"], errors="coerce").fillna(0).clip(0,1)

    base_scores = dict(zip(top_phrases_df['phrase'].astype(str).str.lower(),
                           pd.to_numeric(top_phrases_df['score'], errors='coerce').fillna(0).astype(int)))
    df["base_score"] = df["original"].str.lower().map(base_scores).fillna(1).astype(int)
    df["weighted_score"] = (df["base_score"] * df["relevance_to_query"]).round(2)

    keep = (df["category"].str.lower() != "boilerplate") & (df["relevance_to_query"] >= 0.4)
    df = df[keep].copy()

    agg = (df.groupby("normalized", as_index=False)
             .agg({"weighted_score":"sum","base_score":"sum",
                   "relevance_to_query":"max","category":"first"})
             .sort_values("weighted_score", ascending=False)
             .reset_index(drop=True))
    return agg, None


# =========================================================
# Article Data loading & cleaning (GitHub-first JSON)
# =========================================================
@st.cache_data
def load_data_prefer_pipeline() -> pd.DataFrame:
    """
    Order of preference:
    1) GITHUB_JSON_URL env (raw URL to latest_summary.json in your repo)
    2) ./data/latest_summary.json
    3) ./stratfor_feed_india_extractive.json
    """
    gh = os.getenv("GITHUB_JSON_URL", "").strip()
    if gh:
        try:
            r = requests.get(gh, timeout=20)
            if r.ok:
                return pd.read_json(io.BytesIO(r.content))
        except Exception:
            pass

    candidates = [
        BASE_DIR / "data" / "latest_summary.json",
        BASE_DIR / "stratfor_feed_india_extractive.json",
    ]
    for fp in candidates:
        if fp.exists():
            try:
                return pd.read_json(fp)
            except Exception:
                pass
    return pd.DataFrame(columns=['title','summary','label','score','source','url'])

def sanitize_df(df: pd.DataFrame) -> pd.DataFrame:
    for col, default in [('title',''), ('summary',''), ('label','low'), ('score',0),
                         ('source','Unknown'), ('url','')]:
        if col in df.columns:
            if not isinstance(df[col], pd.Series):
                df[col] = pd.Series(df[col])
            df[col] = df[col].fillna(default)
        else:
            df[col] = default
    df['title'] = df['title'].astype(str).str.strip()
    df['summary'] = df['summary'].astype(str).str.strip()
    df['label'] = df['label'].astype(str).str.strip()
    df['source'] = df['source'].astype(str).str.strip()
    df['url'] = df['url'].astype(str).str.strip()
    df['score'] = pd.to_numeric(df['score'], errors='coerce').fillna(0).astype(int)
    return df

def clean_articles(df: pd.DataFrame) -> pd.DataFrame:
    boilerplate_patterns = [
        r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----',
        r'How to contact WikiLeaks',
        r'Tor is an encrypted anonymising network',
        r'Tips for Sources After Submitting',
        r'Contact If you need help using Tor',
        r'\bread (three )?free articles\b',
        r'\bsubscribe\b',
        r'\bshop\b',
        r'\bsign in\b',
        r'\bnavigation\b'
    ]
    combined = re.compile('|'.join(boilerplate_patterns), flags=re.DOTALL | re.IGNORECASE)
    def filt(x):
        if pd.isna(x): return ""
        return re.sub(combined, '', str(x)).strip()
    df = df.copy()
    df['title'] = df['title'].apply(filt)
    df['summary'] = df['summary'].apply(filt)
    df = df[(df['title']!='') | (df['summary']!='')]
    return df

df_raw = load_data_prefer_pipeline()
df_raw = sanitize_df(df_raw)
df = clean_articles(df_raw)


# =========================================================
# Analyst Summary (LLM-based, cached)
# =========================================================
def _llm_api_key_and_endpoint():
    key = os.getenv("CEREBRAS_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not key:
        return None, None
    endpoint = "https://api.cerebras.ai/v1/chat/completions" if os.getenv("CEREBRAS_API_KEY") \
               else "https://api.openai.com/v1/chat/completions"
    return key, endpoint

def _data_signature(df: pd.DataFrame) -> str:
    if df.empty:
        return "empty"
    sample = df[["title", "summary", "label", "score"]].fillna("").astype(str).head(200)
    return hashlib.sha256(sample.to_csv(index=False).encode("utf-8")).hexdigest()

def generate_analyst_summary_text(df: pd.DataFrame, model: Optional[str] = None) -> str:
    key, endpoint = _llm_api_key_and_endpoint()
    if not key:
        return "No LLM API key configured. Set CEREBRAS_API_KEY or OPENAI_API_KEY to enable the Analyst Brief."
    if df.empty:
        return "No recent articles available to analyze."

    rows = []
    for _, r in df.head(80).iterrows():
        rows.append(f"- {r.get('title','(no title)')}\n  {r.get('summary','')}")
    context = "\n".join(rows)[:12000]
    model = model or os.getenv("LLM_MODEL") or ("llama-3.3-70b" if os.getenv("CEREBRAS_API_KEY") else "gpt-4o-mini")

    system_prompt = (
        "You are a geopolitical and economic analyst. Using the recent Stratfor-style article snippets below, "
        "write a concise 100–200 word briefing on India's current situation: geopolitics (borders, China/Pakistan, IOR), "
        "defense posture, economy/energy/supply chains, and notable domestic risks (unrest, cyber, natural disasters). "
        "Be sober, realistic, and avoid hype. If evidence is thin on a dimension, say so briefly and try to add some real-time data especially figures or numbers if needed."
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Recent snippets:\n\n{context}"},
        ],
        "temperature": 0.4,
        "max_tokens": 700,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        r = requests.post(endpoint, headers=headers, json=payload, timeout=90)
        if r.status_code >= 300:
            return f"⚠️ LLM error {r.status_code}: {r.text[:300]}"
        data = r.json()
        return (data.get("choices", [{}])[0].get("message", {}).get("content", "") or "").strip()
    except Exception as e:
        return f"⚠️ Failed to generate Analyst Brief: {e}"

@st.cache_data(ttl=43200)
def get_analyst_summary(sig: str, model_hint: Optional[str] = None):
    return generate_analyst_summary_text(df_raw, model=model_hint)


# =========================================================
# PAGE HEADER
# =========================================================
st.title("🇮🇳 India-Focused Threat Dashboard")
st.subheader("📊 Analyst Brief (auto-updates)")
_analyst_sig = _data_signature(df_raw)
analyst_text = get_analyst_summary(_analyst_sig, model_hint=None)
st.write(analyst_text if analyst_text else "No brief available.")


# =========================================================
# Sidebar Filters + LLM refine for article keywords
# =========================================================
st.sidebar.header("Filters")
search_text = st.sidebar.text_input("Search text")
use_regex = st.sidebar.checkbox("Search using regex (advanced)", value=False)
sources = ['All'] + sorted(df['source'].unique().tolist())
selected_source = st.sidebar.selectbox("Filter by source", sources)

filtered = df.copy()
if search_text:
    try:
        if use_regex:
            m1 = filtered['title'].str.contains(search_text, case=False, na=False, regex=True)
            m2 = filtered['summary'].str_contains(search_text, case=False, na=False, regex=True)
        else:
            words = [w for w in search_text.lower().split() if w]
            m1 = filtered['title'].apply(lambda x: all(w in str(x).lower() for w in words))
            m2 = filtered['summary'].apply(lambda x: all(w in str(x).lower() for w in words))
        filtered = filtered[m1 | m2]
    except re.error as e:
        st.error(f"Invalid regex: {e}")
    except Exception as e:
        st.error(f"Search failed: {e}")

if selected_source != 'All':
    filtered = filtered[filtered['source'] == selected_source]

st.sidebar.subheader("LLM Refinement & Cache")
llm_model = st.sidebar.text_input("LLM model", value="llama-3.3-70b")
use_llm = st.sidebar.checkbox("Enable LLM refine", value=True)
use_cached = st.sidebar.checkbox("Use cached LLM result (if available)", value=True)
run_llm_now = st.sidebar.button("Clean once with LLM (cache result)")
if st.sidebar.button("Clear LLM cache"):
    clear_llm_cache()
    st.success("Cleared on-disk LLM cache.")

# Safety check for search box (never breaks UI)
try:
    safety_monitor_check(search_text, model_name=llm_model)
    st.session_state["_safety_last_error"] = None
except Exception as e:
    st.session_state["_safety_last_error"] = str(e)


# =========================================================
# Keyword Extraction (RAKE) + Wordcloud for articles
# =========================================================
@st.cache_data
def extract_keywords(df_in: pd.DataFrame) -> pd.DataFrame:
    if df_in.empty or df_in['summary'].astype(str).str.strip().eq('').all():
        return pd.DataFrame(columns=['phrase', 'count', 'score'])
    rake = Rake()
    counts: Dict[str, int] = {}
    for s in df_in['summary']:
        s = str(s).strip()
        if not s:
            continue
        rake.extract_keywords_from_text(s)
        for p in rake.get_ranked_phrases()[:5]:
            k = p.lower()
            counts[k] = counts.get(k, 0) + 1
    if not counts:
        return pd.DataFrame(columns=['phrase','count','score'])
    out = pd.DataFrame([{'phrase': k, 'count': v} for k, v in counts.items()])
    out['phrase'] = out['phrase'].astype(str)
    out['count'] = pd.to_numeric(out['count'], errors='coerce').fillna(0).astype(int)
    out['score'] = out['count']
    out = out.sort_values('score', ascending=False).reset_index(drop=True)
    return out

top_phrases = extract_keywords(filtered)
if not top_phrases.empty:
    top_phrases['phrase'] = top_phrases['phrase'].astype(str)
    top_phrases['score'] = pd.to_numeric(top_phrases['score'], errors='coerce').fillna(0).astype(int)

# LLM-cleaned results for current search
agg = None
if search_text and use_llm and not top_phrases.empty:
    sig = phrases_signature(top_phrases, search_text)
    if use_cached:
        cached = load_llm_cache(sig)
        if cached is not None and not cached.empty:
            agg = cached.copy()
            st.info("Using cached LLM-cleaned results.")
        elif run_llm_now:
            with st.spinner("Running LLM once and caching result..."):
                agg, err = llm_clean_and_rank_phrases(top_phrases, search_text, llm_model)
                if err:
                    st.warning(f"LLM note: {err}")
                else:
                    save_llm_cache(sig, agg)
    else:
        if run_llm_now:
            with st.spinner("Running LLM once and caching result..."):
                agg, err = llm_clean_and_rank_phrases(top_phrases, search_text, llm_model)
                if err: st.warning(f"LLM note: {err}")

st.subheader("Trending Keywords WordCloud")
if top_phrases.empty:
    st.warning("No articles or keywords match the current filters.")
else:
    wc_freq = None
    if agg is not None and not agg.empty and "normalized" in agg.columns and "weighted_score" in agg.columns:
        wc_freq = dict(zip(agg["normalized"].astype(str),
                           pd.to_numeric(agg["weighted_score"], errors='coerce').fillna(0.0)))
    if wc_freq is None:
        wc_freq = dict(zip(top_phrases["phrase"].astype(str),
                           pd.to_numeric(top_phrases["score"], errors='coerce').fillna(0).astype(int)))
    def simple_color_func(word, font_size, position, orientation, random_state=None, **kwargs):
        return random.choice(["#1f77b4", "#ff7f0e", "#2ca02c"])
    wc = WordCloud(width=1600, height=800, background_color='white', max_words=100, max_font_size=200, random_state=42)\
            .generate_from_frequencies(wc_freq)
    wc.recolor(color_func=simple_color_func)
    plt.figure(figsize=(16, 8), dpi=150)
    plt.imshow(wc, interpolation='bilinear'); plt.axis('off')
    st.pyplot(plt)

if agg is not None and not agg.empty:
    st.subheader(f"Top 10 (LLM-cleaned) for “{search_text}”")
    st.dataframe(agg.head(10), use_container_width=True)
    figc = px.bar(agg.head(10), x="normalized", y="weighted_score", text="weighted_score",
                  labels={"normalized":"Keyword","weighted_score":"Weighted Score"})
    st.plotly_chart(figc, use_container_width=True)

if (not use_llm or agg is None or agg.empty) and search_text:
    tokens = [t for t in search_text.lower().split() if t]
    if tokens:
        mask = top_phrases['phrase'].astype(str).str.lower().apply(lambda s: all(t in s for t in tokens))
        subset = top_phrases[mask].head(10)
        if not subset.empty:
            st.subheader(f"Top phrases containing “{search_text}” (heuristic)")
            st.dataframe(subset, use_container_width=True)

# KPIs & Top Articles
st.subheader("Summary KPIs")
st.markdown(f"- **Total articles:** {len(filtered)}")
st.markdown(f"- **By severity:** {filtered['label'].value_counts().to_dict() if not filtered.empty else {}}")
st.markdown(f"- **Sources:** {', '.join(filtered['source'].unique()) if not filtered.empty else '—'}")

st.subheader("Top Articles")
if filtered.empty:
    st.markdown("No articles match the current filters.")
else:
    def make_clickable(link):
        link = str(link) if link is not None else ""
        return f"[Link]({link})" if link else ""
    table_df = filtered[['title','summary','score','label','source','url']].copy()
    table_df['url'] = table_df['url'].apply(make_clickable)
    st.dataframe(table_df, use_container_width=True)

st.subheader("Top Keywords (Bar Chart)")
if not top_phrases.empty:
    fig = px.bar(top_phrases.head(10), x='phrase', y='score', text='score',
                 labels={'phrase': 'Keyword', 'score': 'Score'}, title="Top 10 Phrases")
    st.plotly_chart(fig, use_container_width=True)

st.subheader("🔎 Global Top 5 Key Phrases")
@st.cache_data
def extract_global_phrases(df_all):
    if df_all.empty: return pd.DataFrame(columns=['phrase', 'count'])
    rake = Rake(); counts = {}
    for summary in df_all['summary']:
        summary = str(summary).strip()
        if not summary: continue
        rake.extract_keywords_from_text(summary)
        for phrase in rake.get_ranked_phrases()[:5]:
            pl = phrase.lower(); counts[pl] = counts.get(pl, 0) + 1
    phrases_df = pd.DataFrame([{'phrase': k, 'count': v} for k, v in counts.items()])
    return phrases_df.sort_values('count', ascending=False).head(5).reset_index(drop=True)

global_phrases = extract_global_phrases(df_raw)
if global_phrases.empty:
    st.info("No phrases found in the entire dataset.")
else:
    top_5_md = "\n".join([f"**{i+1}.** {row['phrase'].title()} — _{row['count']} mentions_"
                          for i, row in global_phrases.iterrows()])
    if st.button("Show Global Top 5 Phrases"):
        st.markdown("### 🌍 Top 5 Most Frequent Phrases Across All Articles")
        st.markdown(top_5_md)
    with st.expander("See Top 5 Table"):
        st.dataframe(global_phrases, use_container_width=True)

# Export filtered articles
st.subheader("Export Filtered Data")
if filtered.empty:
    st.markdown("No data available for download.")
else:
    st.download_button("Download CSV", filtered.to_csv(index=False).encode('utf-8'),
                       file_name='filtered_articles.csv', mime='text/csv')


# =========================================================
# Canonical Excel Chat (GitHub source only) + Learning/Logs + Daily TXT report
# =========================================================
def _read_excel_one_sheet(bio_or_bytes, sheet_name: Optional[str]):
    bio = bio_or_bytes if hasattr(bio_or_bytes, "read") else io.BytesIO(bio_or_bytes)
    target = 0 if sheet_name in (None, "",) else sheet_name
    try:
        df_x = pd.read_excel(bio, sheet_name=target)
        if isinstance(df_x, dict):  # in case an engine returns dict unexpectedly
            bio2 = bio_or_bytes if hasattr(bio_or_bytes, "read") else io.BytesIO(bio_or_bytes)
            with pd.ExcelFile(bio2) as xls:
                return pd.read_excel(xls, sheet_name=xls.sheet_names[0])
        return df_x
    except ValueError as e:
        try:
            bio3 = bio_or_bytes if hasattr(bio_or_bytes, "read") else io.BytesIO(bio_or_bytes)
            with pd.ExcelFile(bio3) as xls:
                avail = ", ".join(xls.sheet_names)
            raise ValueError(f"{e}. Available sheets: {avail}")
        except Exception:
            raise

@st.cache_data(ttl=3600)
def load_canonical_excel() -> tuple[pd.DataFrame, str]:
    """
    Try (in order):
    1) GITHUB_XLSX_URL (+ optional GITHUB_XLSX_SHEET)
    2) st.secrets["GITHUB_XLSX_URL"]
    3) Generated synthetic sample
    Always returns a DataFrame and fid.
    """
    url = (os.getenv("GITHUB_XLSX_URL") or (st.secrets.get("GITHUB_XLSX_URL","") if hasattr(st, "secrets") else "")).strip()
    sheet = (os.getenv("GITHUB_XLSX_SHEET") or (st.secrets.get("GITHUB_XLSX_SHEET","") if hasattr(st, "secrets") else "")).strip()

    def _fid_from_bytes(b: bytes, meta: dict) -> str:
        return hashlib.sha256(b + json.dumps(meta, sort_keys=True).encode()).hexdigest()

    if url:
        try:
            r = requests.get(url, timeout=30); r.raise_for_status()
            content = r.content
            df_x = _read_excel_one_sheet(content, sheet or None)
            fid = _fid_from_bytes(content, {"sheet": sheet or None, "src": "gh"})
            st.info(f"Loaded canonical Excel from GitHub (sheet={sheet or 'first'}).")
            return df_x, fid
        except Exception as e:
            st.warning(f"Could not load GitHub Excel: {e}")

    # Synthetic fallback (still lets chat work)
    st.warning("Using synthetic sample data (no GITHUB_XLSX_URL set or fetch failed).")
    df_x = pd.DataFrame({
        "date": pd.date_range(end=pd.Timestamp.utcnow(), periods=120, freq="D"),
        "area": ["North", "South", "East", "West"] * 30,
        "crime_type": ["Theft","Assault","Fraud","Burglary"] * 30,
        "value": (pd.Series(range(120)) % 11 + 1).astype(int)
    })
    fid = hashlib.sha256(b"SYNTHETIC" + str(df_x.shape).encode()).hexdigest()
    return df_x, fid

def _smart_cols(df_x: pd.DataFrame):
    cols = list(df_x.columns); lo = {c: str(c).lower() for c in cols}
    date_cols = [c for c in cols if any(k in lo[c] for k in ["date","time","reported","created","occur","incident"])]
    area_cols = [c for c in cols if any(k in lo[c] for k in ["area","district","location","ward","zone","city","state","precinct","ps"])]
    type_cols = [c for c in cols if any(k in lo[c] for k in ["crime","type","category","offence","offense","ipc","act","section"])]
    sev_cols  = [c for c in cols if any(k in lo[c] for k in ["severity","level","grade","harm","loss","value","amount"])]
    num_cols  = df_x.select_dtypes(include="number").columns.tolist()
    return date_cols, area_cols, type_cols, sev_cols, num_cols

def _top_counts(df_x: pd.DataFrame, col: str, k: int = 12) -> Dict[str,int]:
    try:
        vc = df_x[col].astype(str).str.strip()
        vc = vc[vc.ne("")].value_counts().head(k)
        return vc.to_dict()
    except Exception:
        return {}

def _daily_trend(df_x: pd.DataFrame, date_cols: List[str], k_days: int = 90):
    for c in date_cols:
        try:
            d = pd.to_datetime(df_x[c], errors="coerce")
            s = d.dt.floor("D").value_counts().sort_index().tail(k_days)
            s = {str(k.date()): int(v) for k, v in s.items() if pd.notna(k)}
            if s: return {"column": c, "by_day": s}
        except Exception:
            pass
    return {}

def build_digest(df_x: pd.DataFrame) -> dict:
    date_cols, area_cols, type_cols, sev_cols, num_cols = _smart_cols(df_x)
    return {
        "shape": {"rows": int(df_x.shape[0]), "cols": int(df_x.shape[1])},
        "columns": list(map(str, df_x.columns)),
        "top_areas": _top_counts(df_x, area_cols[0], 12) if area_cols else {},
        "top_crime_types": _top_counts(df_x, type_cols[0], 12) if type_cols else {},
        "daily_trend": _daily_trend(df_x, date_cols, 90),
        "severity_hint": (sev_cols[0] if sev_cols else None),
        "numeric_cols": num_cols[:8],
    }

def _get_answer_from_llm(q: str, digest: dict) -> str:
    key = _get_llm_key()
    if not key:
        # Heuristic fallback
        areas = list((digest.get("top_areas") or {}).items())[:3]
        trend = digest.get("daily_trend", {}).get("by_day", {})
        last7 = sum(list(trend.values())[-7:]) if trend else "unknown"
        return (
            "**Heuristic summary (no LLM key):**\n"
            f"- Hotspots: {', '.join([f'{k} ({v})' for k,v in areas]) or 'n/a'}\n"
            f"- Last 7-day total (if dates present): {last7}\n"
            "- Try lighting/CCTV checks and targeted patrols at hotspots.\n"
        )
    use_cerebras = bool(os.getenv("CEREBRAS_API_KEY"))
    endpoint = "https://api.cerebras.ai/v1/chat/completions" if use_cerebras else "https://api.openai.com/v1/chat/completions"
    model = os.getenv("LLM_MODEL") or ("llama-3.3-70b" if use_cerebras else "gpt-4o-mini")
    system = (
        "You are a city safety data analyst. Answer ONLY using the JSON digest provided. "
        "Be concise (≤ 180 words). Provide up to 3 bullets; include a tiny markdown table if helpful. "
        "If evidence is weak, state what extra data would help (e.g., shift-wise patrol hours, lighting/CCTV coverage). "
        "No internal reasoning; just conclusions and recommendations."
    )
    user = "DATA DIGEST:\n" + json.dumps(digest, ensure_ascii=False)[:14000] + "\n\nQUESTION:\n" + q.strip()
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    payload = {"model": model, "messages":[{"role":"system","content":system},{"role":"user","content":user}],
               "temperature":0.2, "max_tokens": 550}
    try:
        r = requests.post(endpoint, headers=headers, json=payload, timeout=60)
        if r.status_code >= 300:
            return f"⚠️ LLM error {r.status_code}: {r.text[:240]}"
        data = r.json()
        return (data.get("choices",[{}])[0].get("message",{}).get("content","") or "_Empty model reply_").strip()
    except Exception as e:
        return f"⚠️ LLM exception: `{str(e)[:240]}`"

def log_path(fid: str) -> Path:
    day = datetime.datetime.utcnow().strftime("%Y%m%d")
    return CRIME_LOG_DIR / f"{fid}_{day}.txt"

def append_chat(fid: str, role: str, content: str):
    p = log_path(fid)
    ts = datetime.datetime.utcnow().isoformat()+"Z"
    line = f"[{ts}] {role.upper()}: {content}\n"
    try:
        with p.open("a", encoding="utf-8") as f: f.write(line)
    except Exception:
        pass

def mem_path(fid: str) -> Path:
    return EXCEL_AGENT_DIR / f"{fid}.json"

def load_mem(fid: str) -> dict:
    p = mem_path(fid)
    if p.exists():
        try: return json.loads(p.read_text(encoding="utf-8"))
        except Exception: return {}
    return {}

def save_mem(fid: str, state: dict):
    p = mem_path(fid)
    try: p.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception: pass

def update_learning(fid: str, q: str, a: str):
    state = load_mem(fid)
    qa = state.get("qa", [])
    qa.append({"t": datetime.datetime.utcnow().isoformat()+"Z", "q": q, "a": a})
    state["qa"] = qa[-500:]  # cap
    state["last_seen"] = datetime.datetime.utcnow().isoformat()+"Z"
    toks = re.findall(r"[A-Za-z]{3,}", q.lower())
    freq = state.get("kw_freq", {})
    for t in toks:
        freq[t] = int(freq.get(t,0)) + 1
    state["kw_freq"] = {k:v for k,v in sorted(freq.items(), key=lambda kv: kv[1], reverse=True)[:100]}
    save_mem(fid, state)

def _line_dt_ok(line: str, cutoff: datetime.datetime) -> bool:
    m = re.match(r"\[(.*?)\]", line)
    if not m: return False
    try:
        ts = datetime.datetime.fromisoformat(m.group(1).replace("Z",""))
        return ts >= cutoff
    except Exception:
        return False

def compile_admin_report(fid: str, hours: int = 48) -> str:
    """Summarize the last N hours of chats + learning needs."""
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
    logs = []
    for i in range(2):
        day = (datetime.datetime.utcnow() - datetime.timedelta(days=i)).strftime("%Y%m%d")
        p = CRIME_LOG_DIR / f"{fid}_{day}.txt"
        if p.exists():
            try: logs.append(p.read_text(encoding="utf-8"))
            except Exception: pass
    full = "\n".join(logs)
    turns = [ln for ln in full.splitlines() if ln.strip()]
    recent = [ln for ln in turns if _line_dt_ok(ln, cutoff)]
    state = load_mem(fid)
    top_kw = ", ".join([f"{k}({v})" for k,v in (state.get("kw_freq",{})).items()][:10]) or "—"
    needs = []
    if not _get_llm_key(): needs.append("LLM API key missing — only heuristic answers used.")
    if "severity" not in " ".join(state.get("kw_freq",{}).keys()): needs.append("Dataset lacks a clear severity/impact column; model suggests adding one.")
    if "time" not in " ".join(state.get("kw_freq",{}).keys()): needs.append("Shift-wise timestamps could improve actionable insights.")
    report = (
        f"**Admin Report (last {hours}h)**\n\n"
        f"- Total turns seen: **{len(recent)}**\n"
        f"- Top asked tokens: {top_kw}\n"
        f"- Suggested next steps:\n"
        + "".join([f"  - {n}\n" for n in needs]) +
        "\n**Sample last queries**\n"
        + "\n".join([f"- {ln[ln.find('USER:')+5:][:160].strip()}" for ln in recent if 'USER:' in ln][:8])
    )
    return report

def _report_path(fid: str) -> Path:
    return REPORTS_DIR / f"report_{fid[:12]}.txt"

def write_daily_report_if_due(fid: str, hours_window: int = 48, min_interval_hours: int = 24) -> Path:
    """Create/refresh a TXT report no more than once every min_interval_hours."""
    rp = _report_path(fid)
    need_write = True
    if rp.exists():
        try:
            mtime = datetime.datetime.fromtimestamp(rp.stat().st_mtime)
            if datetime.datetime.utcnow() - mtime < datetime.timedelta(hours=min_interval_hours):
                need_write = False
        except Exception:
            pass
    if need_write:
        txt = compile_admin_report(fid, hours=hours_window)
        try:
            rp.write_text(txt, encoding="utf-8")
        except Exception:
            pass
    return rp

def is_admin() -> bool:
    try:
        q = st.query_params
        token = q.get("admin_token", [""])[0] if isinstance(q.get("admin_token"), list) else q.get("admin_token","")
    except Exception:
        token = ""
    admin_secret = (st.secrets.get("ADMIN_TOKEN") if hasattr(st, "secrets") else os.getenv("ADMIN_TOKEN")) or ""
    return bool(admin_secret) and token == admin_secret


# ---------------- Canonical dataset load ----------------
st.markdown("---")
st.header("📈 Canonical Excel (from GitHub) — Shared Chat")

# Sidebar debug expander for data source
with st.sidebar.expander("Debug (data source)"):
    st.write("GITHUB_XLSX_URL:", os.getenv("GITHUB_XLSX_URL", "—"))
    st.write("GITHUB_XLSX_SHEET:", os.getenv("GITHUB_XLSX_SHEET", "—"))

try:
    df_x, fid = load_canonical_excel()
except Exception as e:
    st.error("Failed to load the canonical Excel. Set `GITHUB_XLSX_URL` (and optional `GITHUB_XLSX_SHEET`).")
    st.stop()

st.session_state["excel_df"] = df_x
st.session_state["excel_fid"] = fid

digest = build_digest(df_x)

# Auto-generate admin TXT report once per 24h
report_file = write_daily_report_if_due(fid, hours_window=48, min_interval_hours=24)

# Overview + Pie charts
colA, colB, colC = st.columns([2,2,1.8])

with colA:
    st.subheader("Dataset Overview")
    st.markdown(f"- **Rows:** {digest['shape']['rows']}")
    st.markdown(f"- **Columns:** {digest['shape']['cols']}")
    st.caption("Using the GitHub-hosted Excel as the single source of truth.")

with colB:
    areas = digest.get("top_areas") or {}
    if areas:
        st.subheader("Top Areas (share)")
        pie_df = pd.DataFrame({"label": list(areas.keys()), "value": list(areas.values())})
        fig = px.pie(pie_df, names="label", values="value", title="Areas by count")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No area-like column detected for a pie chart.")

with colC:
    types_ = digest.get("top_crime_types") or {}
    if types_:
        st.subheader("Top Crime Types")
        pie2 = pd.DataFrame({"label": list(types_.keys()), "value": list(types_.values())})
        fig2 = px.pie(pie2, names="label", values="value", title="Types by count")
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No crime-type column detected.")

st.markdown("---")

# Shared Chat
st.header("💬 Ask the Data")
if "chat" not in st.session_state:
    st.session_state["chat"] = []

for t in st.session_state["chat"]:
    with st.chat_message(t["role"]):
        st.markdown(t["content"])

q = st.chat_input("Ask about this dataset…")
if q:
    st.session_state["chat"].append({"role":"user","content":q})
    append_chat(fid, "user", q)
    with st.chat_message("user"):
        st.markdown(q)
    try:
        safety_monitor_check(q, model_name=os.getenv("LLM_MODEL") or "llama-3.3-70b")
    except Exception as _se:
        st.info(f"Safety note: {str(_se)[:120]}")
    with st.chat_message("assistant"):
        box = st.empty()
        try:
            ans = _get_answer_from_llm(q, digest)
            box.markdown(ans)
            st.session_state["chat"].append({"role":"assistant","content":ans})
            append_chat(fid, "assistant", ans)
            update_learning(fid, q, ans)
        except Exception as e:
            err = f"⚠️ Answer failed: `{str(e)[:280]}`"
            box.markdown(err)
            st.session_state["chat"].append({"role":"assistant","content":err})
            append_chat(fid, "assistant", err)

# Admin sidebar — report download
with st.sidebar.expander("Admin: Daily Report"):
    rp = _report_path(st.session_state.get("excel_fid",""))
    if rp and rp.exists():
        st.download_button("Download latest report", data=rp.read_bytes(),
                           file_name=rp.name, mime="text/plain")
    else:
        st.caption("Report not generated yet.")

# =========================================================
# Registration (kept; no emails are sent)
# =========================================================
st.sidebar.subheader("Register for Updates")
users_csv_path = "registered_users.csv"
try:
    users_df = pd.read_csv(users_csv_path)
    if 'email' not in users_df.columns: users_df['email'] = None
    if 'reason' not in users_df.columns: users_df['reason'] = ""
except FileNotFoundError:
    users_df = pd.DataFrame(columns=['email','reason'])

with st.sidebar.form("user_registration"):
    email = st.text_input("Enter your email address")
    reason = st.text_area("Why do you want to use this agent?")
    submitted = st.form_submit_button("Register")
    if submitted:
        if email and reason:
            if not is_valid_email(email):
                st.error("Please enter a valid email address (example@domain.com).")
            elif email in users_df['email'].astype(str).tolist():
                st.info("This email is already registered.")
            else:
                new_row = pd.DataFrame([{'email': str(email), 'reason': str(reason)}])
                users_df = pd.concat([users_df, new_row], ignore_index=True)
                users_df.to_csv(users_csv_path, index=False)

                snap_file = os.path.join(USER_SNAPSHOTS_DIR, f"{str(email).replace('@','_at_')}.csv")
                if not top_phrases.empty:
                    top_phrases.head(10).to_csv(snap_file, index=False)
                else:
                    pd.DataFrame(columns=['phrase','score']).to_csv(snap_file, index=False)

                st.success(f"Registered {email}.")
        else:
            st.error("Please provide both email and reason.")


# =========================================================
# Admin-only diagnostics (?admin_token=YOUR_SECRET)
# =========================================================
def _is_admin():
    try:
        q = st.query_params  # Streamlit >=1.30
        token = q.get("admin_token", [""])[0] if isinstance(q.get("admin_token"), list) else q.get("admin_token","")
    except Exception:
        token = ""
    admin_secret = (st.secrets.get("ADMIN_TOKEN") if hasattr(st, "secrets") else os.getenv("ADMIN_TOKEN")) or ""
    return bool(admin_secret) and token == admin_secret

if _is_admin():
    with st.expander("🔐 Latest Safety Event (admin)"):
        try:
            if SAFETY_PRETTY.exists():
                st.code(SAFETY_PRETTY.read_text(encoding="utf-8"), language="json")
            else:
                st.info("No safety events yet.")
        except Exception as e:
            st.warning(f"Could not read safety log: {e}")
            st.sidebar.markdown(f"🛡️ Registered users: **{len(users_df)}**")

    with st.expander("🛠 Safety logging debug"):
        st.write("**cwd:**", os.getcwd())
        st.write("**BASE_DIR:**", str(BASE_DIR))
        st.write("**SAFETY_LOG_DIR:**", str(SAFETY_LOG_DIR))
        st.write("**JSONL exists:**", SAFETY_JSONL.exists())
        st.write("**PRETTY exists:**", SAFETY_PRETTY.exists())
        st.write("**Dir listing:**", [p.name for p in SAFETY_LOG_DIR.glob("*")])
        st.write("**Last error:**", st.session_state.get("_safety_last_error"))

        if st.button("Write test safety event"):
            dummy = {
                "timestamp_utc": datetime.datetime.utcnow().isoformat()+"Z",
                "session_id": "testsession",
                "ip": "1.2.3.4",
                "geo": {"country":"India","region":"Odisha","city":"Bhubaneswar","org":"Reliance Jio"},
                "query_excerpt": "bomb",
                "triggered_terms": ["bomb"],
                "decision": {"action":"block","risk_level":"high","intent":"violent_harm","reason":"test","source":"rules","euphemism_detected":False},
                "action": "flagged_and_alerted"
            }
            _write_safety_event(dummy)
            st.success(f"Wrote to: {SAFETY_JSONL}")

    with st.expander("🔔 Pushover test"):
        if st.button("Send test Pushover"):
            ok, info = send_pushover_alert("Test alert", "Hello from your dashboard ✅", priority=0)
            st.write("Pushover:", "OK" if ok else f"Error: {info}")
