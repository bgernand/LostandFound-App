FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY lfapp /app/lfapp
COPY templates /app/templates

# runtime dirs (also mounted by volumes)
RUN mkdir -p /app/data /app/uploads
RUN useradd --system --create-home --uid 10001 appuser && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
