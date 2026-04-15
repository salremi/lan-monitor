FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data/db /data/logs/zeek /data/logs/suricata /data/logs/router

ENV PYTHONPATH=/app
ENV DATABASE_URL=sqlite:////data/db/lan_monitor.db

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
