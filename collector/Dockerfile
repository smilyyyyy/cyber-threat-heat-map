FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt
COPY app/ ./app/
# Default: run forever, collecting every COLLECT_INTERVAL_HOURS
CMD ["python", "-m", "app.main"]
