FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose listeners and dashboard
EXPOSE 22 80 443 8080

# Default environment
ENV SSH_PORT=22 \
    HTTP_PORT=80 \
    HTTPS_PORT=443 \
    DASHBOARD_PORT=8080 \
    LOG_PATH=logs/events.jsonl \
    MAX_CONCURRENT_CLIENTS=100 \
    RATE_LIMIT_PER_MIN=10 \
    RESPOND_WITH_REDIRECT_PROB=0.3

CMD ["python", "-m", "honeypot"]


