# trial_excel_chat.py
import os, io, json, hashlib, datetime, time
import streamlit as st
import pandas as pd
import plotly.express as px
import requests

st.set_page_config(page_title="Excel Chat Trial", layout="wide")

# ---------- Helpers ----------
def _read_excel_one_sheet(bio_or_bytes, sheet_name: str | None):
    bio = bio_or_bytes if hasattr(bio_or_bytes, "read") else io.BytesIO(bio_or_bytes)
    target = 0 if not sheet_name else sheet_name
    try:
        df = pd.read_excel(bio, sheet_name=target)
        if isinstance(df, dict):  # rare fallback
            bio2 = bio_or_bytes if hasattr(bio_or_bytes, "read") else io.BytesIO(bio_or_bytes)
            with pd.ExcelFile(bio2) as xls:
                return pd.read_excel(xls, sheet_name=xls.sheet_names[0])
        return df
    except ValueError as e:
        try:
            bio3 = bio_or_bytes if hasattr(bio_or_bytes, "read") else io.BytesIO(bio_or_bytes)
            with pd.ExcelFile(bio3) as xls:
                avail = ", ".join(xls.sheet_names)
            raise ValueError(f"{e}. Available sheets: {avail}")
        except Exception:
            raise

def _excel_fingerprint(content: bytes, extra: dict | None = None) -> str:
    base = hashlib.sha256(content).hexdigest()
    if extra:
        base = hashlib.sha256((base + json.dumps(extra, sort_keys=True)).encode()).hexdigest()
    return base

def _smart_cols(df: pd.DataFrame):
    cols = list(df.columns)
    lo = {c: str(c).lower() for c in cols}
    date_cols = [c for c in cols if any(k in lo[c] for k in ["date","time","reported","created","occur"])]
    area_cols = [c for c in cols if any(k in lo[c] for k in ["area","district","location","ward","zone","city","state","precinct","ps"])]
    type_cols = [c for c in cols if any(k in lo[c] for k in ["crime","type","category","offence","offense","ipc","act","section"])]
    return date_cols, area_cols, type_cols

def _digest(df: pd.DataFrame) -> dict:
    date_cols, area_cols, type_cols = _smart_cols(df)
    def _top(df, col, k=12):
        try:
            vc = df[col].astype(str).str.strip()
            vc = vc[vc.ne("")].value_counts().head(k)
            return vc.to_dict()
        except Exception:
            return {}
    daily = {}
    for c in date_cols:
        try:
            d = pd.to_datetime(df[c], errors="coerce")
            s = d.dt.floor("D").value_counts().sort_index().tail(90)
            daily = {str(k.date()): int(v) for k, v in s.items() if pd.notna(k)}
            if daily: break
        except Exception:
            pass
    return {
        "shape": {"rows": int(df.shape[0]), "cols": int(df.shape[1])},
        "columns": list(map(str, df.columns)),
        "top_areas": _top(df, area_cols[0]) if area_cols else {},
        "top_crime_types": _top(df, type_cols[0]) if type_cols else {},
        "daily_trend": daily,
    }

def _llm_answer(question: str, digest: dict) -> str:
    # Optional LLM (Cerebras > OpenAI > none)
    api_key = os.getenv("CEREBRAS_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        # Heuristic fallback (no LLM key)
        areas = list((digest.get("top_areas") or {}).items())[:3]
        trend = digest.get("daily_trend", {})
        last7 = sum(list(trend.values())[-7:]) if trend else "unknown"
        return (
            "**Heuristic summary (no LLM key):**\n"
            f"- Hotspots: {', '.join([f'{k} ({v})' for k,v in areas]) or 'n/a'}\n"
            f"- Last 7-day total: {last7}\n"
            "- Try lighting/CCTV checks and patrol concentration at hotspots.\n"
        )

    use_cerebras = bool(os.getenv("CEREBRAS_API_KEY"))
    endpoint = "https://api.cerebras.ai/v1/chat/completions" if use_cerebras else "https://api.openai.com/v1/chat/completions"
    model = os.getenv("LLM_MODEL") or ("llama-3.3-70b" if use_cerebras else "gpt-4o-mini")
    system = (
        "You are a data analyst. Answer ONLY using the JSON digest provided. "
        "Be concise (<= 150 words); up to 3 bullets; if data is missing, say what you'd need."
    )
    user = "DIGEST:\n" + json.dumps(digest, ensure_ascii=False)[:14000] + "\n\nQUESTION:\n" + question.strip()
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": model, "messages": [{"role":"system","content":system},{"role":"user","content":user}],
               "temperature": 0.2, "max_tokens": 450}
    try:
        r = requests.post(endpoint, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        data = r.json()
        ans = (data.get("choices",[{}])[0].get("message",{}).get("content","") or "").strip()
        return ans or "_No content from model_"
    except Exception as e:
        return f"⚠️ LLM error: `{str(e)[:200]}`"

# ---------- UI ----------
st.title("🧪 Excel → Chat Trial")

with st.sidebar:
    st.header("Dataset")
    reset = st.button("Reset state")

if reset:
    for k in ("excel_df", "excel_fid", "chat"):
        st.session_state.pop(k, None)
    st.success("State cleared. Upload or fetch again.")

tab1, tab2, tab3 = st.tabs(["Upload .xlsx", "GitHub raw URL", "Chat"])

with tab1:
    up = st.file_uploader("Upload Excel (.xlsx)", type=["xlsx"])
    sheet1 = st.text_input("Optional sheet name", value="")
    if up and st.button("Analyze (Upload)"):
        content = up.read()
        try:
            df = _read_excel_one_sheet(content, sheet1 or None)
        except Exception as e:
            st.error(f"Read failed: {e}")
            df = None
        if df is not None:
            fid = _excel_fingerprint(content, {"sheet": sheet1 or None})
            st.session_state["excel_df"] = df
            st.session_state["excel_fid"] = fid
            st.success(f"Loaded: rows={len(df)}, cols={len(df.columns)} (fid {fid[:10]}…)")

with tab2:
    url = st.text_input("GitHub raw URL to .xlsx")
    sheet2 = st.text_input("Optional sheet name ", key="sheet2")
    if url and st.button("Analyze (URL)"):
        try:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            content = r.content
            df = _read_excel_one_sheet(content, sheet2 or None)
            fid = _excel_fingerprint(content, {"sheet": sheet2 or None, "src": "gh"})
            st.session_state["excel_df"] = df
            st.session_state["excel_fid"] = fid
            st.success(f"Loaded: rows={len(df)}, cols={len(df.columns)} (fid {fid[:10]}…)")
        except Exception as e:
            st.error(f"Fetch/read failed: {e}")

with tab3:
    df = st.session_state.get("excel_df")
    fid = st.session_state.get("excel_fid")
    if df is None:
        st.info("Load a dataset in the other tabs first.")
    else:
        # Quick profile
        st.subheader("Profile")
        st.write(f"**Shape:** {df.shape[0]} × {df.shape[1]}")
        nulls = df.isna().sum()
        with st.expander("Nulls by column"):
            st.dataframe(nulls.to_frame("nulls"))
        try:
            # Simple preview chart if any numeric column
            nums = df.select_dtypes(include="number").columns.tolist()
            if nums:
                fig = px.histogram(df, x=nums[0], nbins=30, title=f"Histogram: {nums[0]}")
                st.plotly_chart(fig, use_container_width=True)
        except Exception:
            pass

        # Chat (persisted)
        if "chat" not in st.session_state:
            st.session_state["chat"] = []
        for t in st.session_state["chat"]:
            with st.chat_message(t["role"]):
                st.markdown(t["content"])

        q = st.chat_input("Ask about this dataset…")
        if q:
            # Build digest once per rerun
            dig = _digest(df)
            # Render + store user
            st.session_state["chat"].append({"role":"user","content":q})
            with st.chat_message("user"):
                st.markdown(q)
            # Answer safely
            with st.chat_message("assistant"):
                box = st.empty()
                try:
                    ans = _llm_answer(q, dig)
                    box.markdown(ans)
                    st.session_state["chat"].append({"role":"assistant","content":ans})
                except Exception as e:
                    err = f"⚠️ Answer failed: `{str(e)[:300]}`"
                    box.markdown(err)
                    st.session_state["chat"].append({"role":"assistant","content":err})
