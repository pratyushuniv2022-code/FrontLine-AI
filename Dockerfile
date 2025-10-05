# ==== Base image ====
FROM python:3.11-slim

# Environment setup
ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create non-root user
RUN useradd -m appuser

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential wget \
 && rm -rf /var/lib/apt/lists/*

# Workdir
WORKDIR /app

# Copy and install dependencies first
COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Install + preload NLTK resources for rake_nltk
RUN python -m nltk.downloader stopwords punkt punkt_tab \
 && mkdir -p /home/appuser/nltk_data \
 && python -m nltk.downloader -d /home/appuser/nltk_data stopwords punkt punkt_tab

# Copy your main code and data
COPY threat_dashboard_with_safety.py /app/
COPY data/ /app/data/

# Create persistent directories
RUN mkdir -p /app/llm_cache /app/excel_agent_data /app/crime_agent_logs /app/safety_logs /app/admin_reports \
 && chown -R appuser:appuser /app

# Switch to appuser
USER appuser

# Expose port
EXPOSE 8501

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD \
  wget -qO- http://127.0.0.1:8501/ >/dev/null 2>&1 || exit 1

# Start the Streamlit app
CMD ["streamlit", "run", "threat_dashboard_with_safety.py", "--server.port=8501", "--server.address=0.0.0.0"]
