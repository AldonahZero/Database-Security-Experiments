FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN pip install --no-cache-dir flask==3.0.3 psycopg2-binary==2.9.9
COPY app.py /app/app.py

EXPOSE 8081
CMD ["python", "/app/app.py"]
