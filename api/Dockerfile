FROM python:3.12-slim

WORKDIR /app

RUN addgroup --system pgscope \
    && adduser --system --ingroup pgscope pgscope

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY --chown=pgscope:pgscope main.py /app/main.py
COPY --chown=pgscope:pgscope plan_regression.py /app/plan_regression.py
COPY --chown=pgscope:pgscope oracle_router.py /app/oracle_router.py

USER pgscope

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
