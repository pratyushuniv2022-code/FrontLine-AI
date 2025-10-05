🚨 Project Title
🇮🇳 India-Focused Threat Intelligence & Safety Monitoring Dashboard

Youtube video link of live presentation 
https://youtu.be/oE9aobRJSOo

🧠 Objective

To build an autonomous, LLM-assisted threat analysis dashboard that continuously:

🛰️ Scrapes and aggregates open-source intelligence (OSINT) related to India (from GitHub datasets, Stratfor feeds, or APIs).

🧩 Summarizes and analyzes the latest geopolitical, security, and economic developments.

🔐 Detects and flags potentially unsafe or malicious content in user queries (AI safety layer).

📊 Visualizes all processed insights in an interactive Streamlit dashboard for analysts or researchers.

⚙️ Integrates automation via Zapier and Hook0 for triggers, and Docker + Fly.io for deployment.

🚀 Note: The deployed version of this dashboard will be added soon once final testing and optimization are complete.

🛰️ Data Sources

This project uses two key data streams — one for real-time geopolitical intelligence and another for crime analytics.
Both are processed through specialized AI agents within the system.

🌍 1. Geopolitical Data (Threat Intelligence)

Source: Stratfor Worldview

Purpose:
Used as the primary data feed for analyzing India’s geopolitical, economic, and security-related developments.

Process Overview:

The scraper fetches the latest news briefs, situation reports, and articles related to India from Stratfor.

The Insight Agent summarizes the current geo-financial scenario of the country.

The Scoring & Keyword Agent ranks the summarized items by criticality and highlights key topics, regions, and phrases.

Example Outputs:

📜 Analyst brief summarizing regional trends

🔑 Top keywords (e.g., “trade route,” “defense cooperation,” “energy policy”)

🧩 Automated categorization into economic / military / cyber / policy / social dimensions

🧠 2. Crime Data (Domestic Safety Intelligence)

Source: Indian Crimes Dataset – Kaggle

Purpose:
Used by the Crime Intelligence Agent to study patterns of crime across Indian states and districts, supporting analysis on public safety, law enforcement trends, and crime reduction strategies.

Process Overview:

The dataset is loaded into the system for profiling, trend analysis, and visualization.

The Crime Agent identifies hotspots, frequency patterns, and time-based trends.

Includes a chat-based analyzer where users can ask:

“Which cities have the highest crime rates?”

“Is there a seasonal trend in offenses?”

“What type of crimes are rising in urban regions?”

Example Outputs:

🥧 Pie charts for top crime types and regions

📈 Time-series charts for daily/weekly trends

🤖 LLM-based narrative insights about emerging crime clusters

🔒 Data Ethics & Attribution

All scraped data from Stratfor is used strictly for educational and research purposes under fair use, with no redistribution of raw content.

The Kaggle crime dataset remains governed by its original open license and attribution terms.

No private, confidential, or personally identifiable information (PII) is collected or stored.

🧩 Combined Use in the Project
Data Source	Responsible Agent	Purpose
Stratfor Worldview	Insight & Scoring Agents	Summarization, risk scoring, keyword extraction
Indian Crimes Dataset (Kaggle)	Crime Intelligence Agent	Crime profiling, hotspot detection, safety analysis
⚙️ System Architecture
1️⃣ Data Collection / Scraping Layer

Periodically fetches updated JSON/Excel feeds from:

GitHub repositories

Web pipelines (e.g., latest_summary.json)

Stratfor-style public intelligence feeds

Employs retry-based requests (requests + urllib3 Retry Adapter) for stability.

Cleans data to remove boilerplate, PGP blocks, and non-relevant text.

💡 Ensures fresh geopolitical summaries are available every 12 hours without manual refresh.

2️⃣ NLP & Summarization Layer

Uses RAKE (Rapid Automatic Keyword Extraction) for initial keyword extraction.

Generates WordClouds and keyword bar charts for visual insights.

Optionally uses LLMs (Cerebras or OpenAI) for:

Cleaning and deduplicating extracted phrases.

Categorizing into geo / policy / military / economic / cyber / social classes.

Ranking by weighted importance to search queries.

Models Used:

🧠 llama-3.3-70b (Cerebras)

⚡ gpt-4o-mini (OpenAI fallback)

3️⃣ Automated Analyst Brief (LLM Summarizer)

Creates concise 150-word briefings summarizing India’s:

Geopolitical posture (China, Pakistan, IOR region)

Economic and energy security trends

Domestic risks (cyber threats, unrest, natural disasters)

Auto-refresh every 12 hours (via Streamlit caching / Zapier webhook).

Displays a safe message (“No LLM API key configured…”) if keys are unavailable.

4️⃣ Safety & Threat Monitoring System

Built-in Safety Monitor inspects user queries in real time.

Detects risky or violent intent using:

Regex rule-based filters (e.g., bomb, attack, murder, explosive, etc.)

Optional LLM-based intent classifier for nuanced euphemisms.

Classifies queries as Low / Medium / High Risk.

Logs flagged events with:

Timestamp

IP & geolocation (ipapi.co)

Triggered terms and AI decision

Sends instant push notifications (via Pushover) for high-risk alerts.

✅ Ensures the system remains LLM-safe and OSINT-compliant.

5️⃣ Visualization & Dashboard Layer

Built entirely in Streamlit, featuring:

🧭 Sidebar Filters – search text, regex search, source filters

📊 Interactive Visualizations – Plotly bar charts, WordClouds, KPI counters

🧠 LLM Refinement Toggle – switch between rule-based and AI-cleaned results

📘 Excel Analyzer (Beta) – upload or connect GitHub Excel datasets to:

Profile columns

Detect outliers

Suggest improvements

Generate AI-driven summaries (“Ask your dataset”)

The UI auto-updates every 12 hours and hides sensitive admin-only details.

6️⃣ Automation & Integration Layer

Zapier + Hook0 Integration for:

Webhook-based data refresh triggers

Sending summaries to Slack/Email

Remote cache updates

GitHub-hosted NLTK Data:

To keep Docker lightweight, all NLTK corpora (stopwords, punkt, punkt_tab) are hosted on GitHub and downloaded during container startup.

7️⃣ Deployment Architecture

Containerized using Docker

Base: python:3.11-slim

Optimized environment (PYTHONOPTIMIZE=2, limited threads)

Uses docker_entrypoint.sh for runtime setup

Deployed on Fly.io with:

Persistent logs

Secret management (OPENAI_API_KEY, CEREBRAS_API_KEY, PUSHOVER_USER_KEY, etc.)

Built-in health checks (auto-restart if Streamlit is unresponsive)

💡 Core Innovations
Component	Innovation
Scraping → Summarization → Visualization	Fully automated 12-hour pipeline with fallback cache
LLM Curation	Cleans, categorizes, and ranks key phrases intelligently
Safety Monitor	Hybrid rule + LLM model for real-time risk classification
Push Alerts	Instant Pushover alerts for high-risk detections
Excel Analyzer	ML-assisted profiling and chat interface for structured datasets
Lightweight Deployment	Docker + Fly.io + GitHub hosting for efficient deployment
🧰 Tech Stack
Layer	Tools / Libraries
Language & Environment	Python 3.11, Docker
Frameworks	Streamlit, Plotly, Matplotlib
NLP & AI	NLTK, RAKE, WordCloud, LLM APIs (Cerebras/OpenAI)
Networking	requests, urllib3.Retry
Automation	Zapier, Hook0, Fly.io
Data Handling	pandas, openpyxl
Alerting	Pushover API
Deployment	Fly.io, Docker Hub
Version Control	GitHub (auto-updating datasets)
🧭 Conceptual Summary

This project acts as a 24/7 digital analyst that:

Continuously scans, summarizes, and interprets open-source data.

Scores and classifies risks in real time.

Monitors for threats, ensuring AI safety compliance.

Visualizes all findings through an elegant, interactive dashboard.

It demonstrates:

Autonomous LLM pipelines for real-time intelligence.

End-to-end integration: data ingestion → NLP → visualization → safety → deployment.

Scalable, containerized design ready for real-world use.

🚀 Future Extensions

🔗 Integrate LangChain for multi-source contextual summarization

🧮 Add Neo4j or DuckDB for historical trend tracking

🧠 Implement LLM-driven clustering for theme evolution detection

🌏 Extend to multi-country threat comparison dashboards

🤖 Introduce a multi-agent MCP (Model Control Protocol) layer for asynchronous coordination between:

Scraper Agent

Summarizer Agent

Safety Agent

Dashboard Agent

Crime Intelligence Agent

🧩 Deployment Note

🌐 Deployed version of the dashboard will be added soon after final optimization and container testing.
