FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "psycopg[binary]" PyYAML kubernetes
COPY collector /app/collector
CMD ["python", "-u", "/app/collector/collector.py"]
