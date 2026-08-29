FROM python:3.12-slim

WORKDIR /app
COPY internal.py /app/internal.py

ENV PYTHONUNBUFFERED=1
EXPOSE 9000

CMD ["python", "/app/internal.py"]
