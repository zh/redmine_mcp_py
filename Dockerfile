FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py ./
COPY auth ./auth

# Hugging Face Spaces routes public HTTPS to the container's port 7860.
EXPOSE 7860

CMD ["uvicorn", "server:app", \
     "--host", "0.0.0.0", \
     "--port", "7860", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
