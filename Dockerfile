FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --home-dir /app appuser \
    && mkdir -p /app/data && chown 10001:10001 /app/data
COPY app ./app
COPY web ./web
COPY VERSION .
USER 10001:10001
EXPOSE 9099
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","9099","--no-proxy-headers","--no-server-header"]
