# Build from the repository root: docker build -f backend/Dockerfile .
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY backend/src backend/src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SHIELD_DB_PATH=/data/promptshield.db
RUN useradd --create-home --uid 10001 shield && mkdir /data && chown shield /data
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER shield
VOLUME ["/data"]
EXPOSE 5380
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5380/healthz')"]
CMD ["promptshield", "serve", "--host", "0.0.0.0", "--port", "5380"]
