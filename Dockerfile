# syntax=docker/dockerfile:1
FROM python:3.11-slim

# System deps (optional): curl for health checks/debugging
RUN apt-get update -y && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Create data directory for mounted volume
RUN mkdir -p /data/specs

# Copy application code
COPY . .

ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

EXPOSE 8000

# Use uvicorn to run the FastAPI app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
