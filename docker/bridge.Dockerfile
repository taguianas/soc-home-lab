FROM python:3.10-alpine
COPY bridge.py /app/bridge.py
CMD ["python", "/app/bridge.py"]
