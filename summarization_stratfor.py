#!/usr/bin/env python3
"""
extractive_summarize_clean.py

Extractive-only summarizer (offline) that:
 - Cleans links (markdown and raw URLs) from article text
 - Uses Sumy TextRank to extract top N sentences per article
 - Optionally truncates the resulting summary to a max word count (e.g., 200-300 words)
 - Periodically saves progress so you can resume on interruption
 - Auto-downloads NLTK 'punkt' tokenizer if missing

Usage:
  1. Activate your venv (where sumy & nltk are installed)
  2. pip install sumy nltk
  3. python extractive_summarize_clean.py

Input/Output:
  - INPUT_JSON  : expected input file with articles (default: stratfor_feed_india.json)
  - OUTPUT_JSON : written output with an added "summary" field (default: stratfor_feed_india_extractive.json)
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
INPUT_JSON  = os.path.join(os.path.dirname(__file__), "..", "data", "latest_raw.json")
OUTPUT_JSON = os.path.join(os.path.dirname(__file__), "..", "data", "latest_summary.json")
PARTIAL_SAVE = os.path.join(os.path.dirname(__file__), "..", "data", "extractive_partial_progress.json")
os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)

# How many sentences to extract per article (tune: 3-12)
EXTRACT_SENTENCES = 8

# Optional: cap final summary length in words. Set to None to keep sentence-based length.
MAX_SUMMARY_WORDS = 250  # e.g., 200-300 words desired

# Save progress every N articles
SAVE_INTERVAL = 10

# If True, remove 'full_text' from saved JSON to reduce size
REMOVE_FULL_TEXT = True

# ---------------- Helpers ----------------
def ensure_nltk_punkt():
    """Make sure NLTK punkt tokenizer is available; download if missing."""
    try:
        import nltk
        try:
            nltk.data.find("tokenizers/punkt")
        except LookupError:
            print("NLTK punkt not found — downloading (this may take a few seconds)...")
            nltk.download("punkt")
            print("NLTK punkt downloaded.")
    except Exception as e:
        print("Warning: NLTK not available or failed to download punkt:", e)
        # Sumy may fall back or fail; we will still attempt extractive summarization.

def clean_text(text: str) -> str:
    """
    Remove links and excessive whitespace from text:
      - Remove markdown links: [text](url)
      - Remove inline HTML links <a ...>...</a>
      - Remove raw URLs (http://, https://, www.)
      - Collapse whitespace
    """
    if not text:
        return ""
    s = str(text)
    # remove markdown-style [text](url)
    s = re.sub(r"\[([^\]]+)\]\((?:https?:\/\/|mailto:|ftp:)?[^\)]+\)", r"\1", s)
    # remove possible leftover parentheses urls
    s = re.sub(r"\([hH][tT][tT][pP][^\)]*\)", "", s)
    # remove HTML anchor tags but keep inner text
    s = re.sub(r"<a[^>]*>(.*?)</a>", r"\1", s, flags=re.IGNORECASE | re.DOTALL)
    # remove raw URLs
    s = re.sub(r"https?:\/\/\S+", "", s)
    s = re.sub(r"www\.\S+", "", s)
    # remove typical stray tokens like '#' anchors
    s = re.sub(r"#\S+", "", s)
    # collapse whitespace
    s = re.sub(r"\s+", " ", s).strip()
    return s

def extractive_summary(text: str, n_sentences: int = EXTRACT_SENTENCES) -> str:
    """Return an extractive summary (n_sentences) using Sumy TextRank. Falls back to naive split on failure."""
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
        # fallback: naive split by periods (not ideal but safe)
        print("  ⚠ Sumy extraction failed, using naive fallback. Error:", e)
    # fallback: first n_sentences using simple split
    parts = re.split(r'(?<=[\.\?\!])\s+', text)
    chosen = parts[:n_sentences]
    return " ".join(chosen).strip()

def truncate_to_word_limit(text: str, max_words: int) -> str:
    """Truncate text to max_words and append ellipsis if truncated."""
    if not text or max_words is None:
        return text
    words = text.split()
    if len(words) <= max_words:
        return text
    return " ".join(words[:max_words]).rstrip() + "..."

# ---------------- Main ----------------
def main():
    ensure_nltk_punkt()

    if not os.path.exists(INPUT_JSON):
        print(f"ERROR: Input file not found: {INPUT_JSON}")
        return

    # Load existing partial progress if present (resume capability)
    if os.path.exists(PARTIAL_SAVE):
        print(f"Partial progress file found ({PARTIAL_SAVE}). Resuming from it...")
        with open(PARTIAL_SAVE, "r", encoding="utf-8") as f:
            articles = json.load(f)
    else:
        with open(INPUT_JSON, "r", encoding="utf-8") as f:
            articles = json.load(f)

    total = len(articles)
    print(f"Loaded {total} articles. Starting extractive summarization (TextRank) with link cleaning.")

    for idx, article in enumerate(articles, start=1):
        # skip if already has 'summary' (supports resume)
        if article.get("summary"):
            print(f"[{idx}/{total}] Skipping (already summarized): {article.get('title','(no title)')}")
            continue

        title = article.get("title", article.get("url", f"article-{idx}"))
        print(f"[{idx}/{total}] Processing: {title}")

        try:
            raw_text = article.get("full_text") or article.get("text") or article.get("snippet") or ""
            cleaned = clean_text(raw_text)

            # If cleaned text is too short, fallback to original raw_text for extraction
            if len(cleaned.split()) < 20 and raw_text:
                cleaned = raw_text  # keep raw if cleaning removed too much

            # Step 1: extractive summary
            extracted = extractive_summary(cleaned, n_sentences=EXTRACT_SENTENCES)

            # Step 2 (optional): truncate to max words for dashboard
            if MAX_SUMMARY_WORDS:
                final_summary = truncate_to_word_limit(extracted, MAX_SUMMARY_WORDS)
            else:
                final_summary = extracted

            article["summary"] = final_summary

            # Optionally remove full_text to reduce output size (dashboard uses 'summary')
            if REMOVE_FULL_TEXT and "full_text" in article:
                article.pop("full_text", None)

        except Exception as e:
            print(f"  ⚠ Error summarizing article '{title}': {e}")
            traceback.print_exc()
            article["summary"] = f"⚠ Error during summarization: {str(e)[:200]}"
            if REMOVE_FULL_TEXT and "full_text" in article:
                article.pop("full_text", None)

        # periodic partial save for resume
        if idx % SAVE_INTERVAL == 0:
            print(f"  → Saving partial progress to {PARTIAL_SAVE} (processed {idx}/{total})")
            with open(PARTIAL_SAVE, "w", encoding="utf-8") as f:
                json.dump(articles, f, indent=2, ensure_ascii=False)

    # final save
    print(f"Finished. Writing output to {OUTPUT_JSON} ...")
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(articles, f, indent=2, ensure_ascii=False)

    # remove partial if exists
    if os.path.exists(PARTIAL_SAVE):
        try:
            os.remove(PARTIAL_SAVE)
        except Exception:
            pass

    print("Done. Extractive summaries are available in the 'summary' field of the output JSON.")


if __name__ == "__main__":
    main()
