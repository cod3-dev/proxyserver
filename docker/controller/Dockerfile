FROM python:3.11-slim
WORKDIR /app
COPY requirement.txt ./
RUN pip install --no-cache-dir -r requirement.txt
COPY . .
EXPOSE 9100
CMD ["python", "observerbility/controller.py"]
