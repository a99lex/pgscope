FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "psycopg[binary]" \
    fastapi \
    "uvicorn[standard]" \
    kubernetes

COPY main.py /app/main.py
COPY plan_regression.py /app/plan_regression.py
COPY oracle_router.py /app/oracle_router.py

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
