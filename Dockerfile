# syntax=docker/dockerfile:1
# CraftPass — multi-stage build for linux/arm64 (and amd64 for CI).
#
#   css     → compiles static/src/main.css into static/app.css with the
#             Tailwind standalone CLI (arch-matched, no Node required)
#   wheels  → builds the package + dependencies as wheels
#   runtime → slim, non-root, offline install from the wheelhouse

ARG PYTHON_IMAGE=python:3.13-slim

# ---------------------------------------------------------------- compile css
FROM ${PYTHON_IMAGE} AS css
ARG TARGETARCH
WORKDIR /build
COPY craftpass/ ./craftpass/
RUN set -eux; \
    case "${TARGETARCH}" in \
        arm64) url="https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-arm64" ;; \
        *)     url="https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64" ;; \
    esac; \
    python -c "import urllib.request as u; u.urlretrieve('${url}', '/usr/local/bin/tailwindcss')"; \
    chmod +x /usr/local/bin/tailwindcss; \
    cd craftpass; \
    tailwindcss -i static/src/main.css -o static/app.css --minify

# ---------------------------------------------------------------- build wheels
FROM ${PYTHON_IMAGE} AS wheels
# Real version is injected by CI (git describe); plain local builds get 0.0.0.
ARG APP_VERSION=0.0.0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${APP_VERSION}
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY craftpass/ ./craftpass/
COPY --from=css /build/craftpass/static/app.css ./craftpass/static/app.css
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="CraftPass" \
      org.opencontainers.image.description="Self-hosted SSO: Caddy forward-auth gateway + OIDC provider" \
      org.opencontainers.image.source="https://github.com/LabCraft-dev/CraftPass" \
      org.opencontainers.image.licenses="MIT"

RUN useradd --system --uid 1000 --user-group --home /app craftpass
COPY --from=wheels /wheels /tmp/wheels
RUN pip install --no-cache-dir --no-index --find-links /tmp/wheels craftpass \
    && rm -rf /tmp/wheels

ENV DATA_DIR=/data \
    PYTHONUNBUFFERED=1
USER craftpass
WORKDIR /app
EXPOSE 8000
VOLUME /data

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request as u, sys; sys.exit(0 if u.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status == 200 else 1)"]

CMD ["uvicorn", "craftpass.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
