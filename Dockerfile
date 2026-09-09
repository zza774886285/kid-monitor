FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir paramiko requests
COPY *.py *.json ./
CMD ["python3", "kid_refresh_server.py"]
