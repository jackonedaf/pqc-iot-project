FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt \
    && groupadd -g 10001 lab && useradd -u 10001 -g lab -M lab
COPY pyproject.toml ./
COPY pqc_iot ./pqc_iot
COPY tests ./tests
USER 10001:10001
CMD ["python", "-m", "pqc_iot.gateway"]
