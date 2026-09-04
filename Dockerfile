FROM python:3.12-slim
WORKDIR /app
RUN addgroup --system pgscope \
    && adduser --system --ingroup pgscope pgscope \
    && pip install --no-cache-dir "psycopg[binary]" PyYAML kubernetes
COPY --chown=pgscope:pgscope collector /app/collector
USER 100:101
CMD ["python", "-u", "/app/collector/collector.py"]
