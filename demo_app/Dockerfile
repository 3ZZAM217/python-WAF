FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask==3.0.3 markupsafe==2.1.5

COPY app.py .

EXPOSE 5000

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" \
    || exit 1

CMD ["python", "app.py"]
