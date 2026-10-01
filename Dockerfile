FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home analyst
USER analyst
WORKDIR /home/analyst

EXPOSE 8000
# Generates synthetic logs, runs detection, then serves the dashboard on :8000
CMD ["intellidetect", "demo", "--out", "out", "--serve", "--host", "0.0.0.0", "--port", "8000"]
