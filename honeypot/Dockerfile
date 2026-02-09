FROM python:3.11-slim

WORKDIR /app

COPY honeypot.py .

# Create logs directory
RUN mkdir -p /app/logs
RUN pip install paramiko

EXPOSE 22

CMD ["python", "-u", "honeypot.py"]
