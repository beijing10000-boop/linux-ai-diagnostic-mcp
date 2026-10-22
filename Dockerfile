FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -r -u 10001 appuser && mkdir -p /app/data && chown appuser:appuser /app/data
USER appuser
EXPOSE 8088
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8088"]
