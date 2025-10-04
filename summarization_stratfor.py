#!/usr/bin/env python3
"""
summarization_stratfor.py

Extractive-only summarizer (offline, automated) that:
 - Cleans links (markdown and raw URLs) from article text
 - Uses Sumy TextRank to extract top N sentences per article
 - Optionally truncates to a max word count
 - Periodically saves progress so runs can resume safely
 - Fully compatible with GitHub Actions pipeline (no runtime NLTK downloads)

Input/Output:
  - INPUT_JSON  : "data/latest_raw.json" (from scraper)
  - OUTPUT_JSON : "data/latest_summary.json"
"""

import os
import json
import re
import traceback
from typing import List

# Sumy
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.text_rank import TextRankSummarizer

# ---------------- CONFIG ----------------
BASE_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(BASE_DIR, exist_ok=True)

INPUT_JSON = os.path.join(BASE_DIR, "latest_raw.json")
OUTPUT_JSON = os.path.join(BASE_DIR, "latest_summary.json")
PARTIAL_SAVE = os.path.join(BASE_DIR, "extractive_partial_progress.json")

# Configurable parameters via environment variables
EXTRACT_SENTENCES = int(os.getenv("EXTRACT_SENTENCES", 8))
MAX_SUMMARY_WORDS = int(os.getenv("MAX_SUMMARY_WORDS", 250))
SAVE_INTERVAL = 10
REMOVE_FULL_TEXT = True

# ---------------- HELPERS ----------------
def clean_text(text: str) -> str:
    """Remove links, HTML, and excess whitespace from text."""
    if not text:
        return ""
    s = str(text)
    s = re.sub(r"\[([^\]]+)\]\((?:https?:\/\/|mailto:|ftp:)?[^\)]+\)", r"\1", s)
    s = re.sub(r"\([hH][tT][tT][pP][^\)]*\)", "", s)
    s = re.sub(r"<a[^>]*>(.*?)</a>", r"\1", s, flags=re.IGNORECASE | re.DOTALL)
    s = re.sub(r"https?:\/\/\S+", "", s)
    s = re.sub(r"www\.\S+", "", s)
    s = re.sub(r"#\S+", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def extractive_summary(text: str, n_sentences: int = EXTRACT_SENTENCES) -> str:
    """Return an extractive summary using Sumy TextRank, with fallback."""
    if not text or not text.strip():
        return ""
    try:
        parser = PlaintextParser.from_string(text, Tokenizer("english"))
        summarizer = TextRankSummarizer()
        sentences = summarizer(parser.document, n_sentences)
        joined = " ".join(str(s) for s in sentences).strip()
        if joined:
            return joined
    except Exception as e:
        print(f"  ⚠ Sumy extraction failed; fallback used: {e}")
    parts = re.split(r'(?<=[\.\?\!])\s+', text)
    chosen = parts[:n_sentences]
    return " ".join(chosen).strip()

def truncate_to_word_limit(text: str, max_words: int) -> str:
    """Truncate summary to max_words (with ellipsis)."""
    if not text or max_words is None:
        return text
    words = text.split()
    if len(words) <= max_words:
        return text
    return " ".join(words[:max_words]).rstrip() + "..."

# ---------------- MAIN ----------------
def main():
    if not os.path.exists(INPUT_JSON):
        print(f"❌ ERROR: Input file not found → {INPUT_JSON}")
        return

    print(f"🔍 Summarizer configuration → Sentences per article: {EXTRACT_SENTENCES}, "
          f"Max words: {MAX_SUMMARY_WORDS}")

    # Load data (resume if partial)
    if os.path.exists(PARTIAL_SAVE):
        print(f"Resuming from partial progress file: {PARTIAL_SAVE}")
        with open(PARTIAL_SAVE, "r", encoding="utf-8") as f:
            articles = json.load(f)
    else:
        with open(INPUT_JSON, "r", encoding="utf-8") as f:
            articles = json.load(f)

    total = len(articles)
    print(f"📄 Loaded {total} articles for summarization.")

    for idx, article in enumerate(articles, start=1):
        # Skip if already summarized
        if article.get("summary"):
            continue

        title = article.get("title", f"article-{idx}")
        print(f"[{idx}/{total}] Summarizing: {title[:80]}")

        try:
            raw_text = article.get("full_text") or article.get("text") or article.get("snippet") or ""
            cleaned = clean_text(raw_text)
            if len(cleaned.split()) < 20 and raw_text:
                cleaned = raw_text

            extracted = extractive_summary(cleaned, n_sentences=EXTRACT_SENTENCES)
            final_summary = truncate_to_word_limit(extracted, MAX_SUMMARY_WORDS) if MAX_SUMMARY_WORDS else extracted

            article["summary"] = final_summary

            if REMOVE_FULL_TEXT and "full_text" in article:
                article.pop("full_text", None)

        except Exception as e:
            print(f"  ⚠ Error summarizing '{title}': {e}")
            traceback.print_exc()
            article["summary"] = f"⚠ Error: {str(e)[:200]}"
            if REMOVE_FULL_TEXT and "full_text" in article:
                article.pop("full_text", None)

        # Periodic save
        if idx % SAVE_INTERVAL == 0:
            with open(PARTIAL_SAVE, "w", encoding="utf-8") as f:
                json.dump(articles, f, indent=2, ensure_ascii=False)
            print(f"💾 Saved partial progress ({idx}/{total})")

    # Final save
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(articles, f, indent=2, ensure_ascii=False)

    if os.path.exists(PARTIAL_SAVE):
        try:
            os.remove(PARTIAL_SAVE)
        except Exception:
            pass

    print(f"✅ Done. Summaries saved to → {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
