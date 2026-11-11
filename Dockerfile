# API and web UI. On start the service generates the seeded synthetic logs and runs the pipeline (about a minute).
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --from=builder --chown=app /app/.venv /app/.venv
# The app writes case statuses and feedback (state.json) and the audit log (audit.jsonl) here at runtime.
RUN mkdir -p /app/data && chown app:app /app/data
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    UEBA_DATA=/app/data \
    UEBA_SCALE=1.0 \
    PORT=8892
USER app
EXPOSE 8892
HEALTHCHECK --interval=15s --timeout=5s --start-period=180s --retries=3 \
    CMD ["uebalab", "healthcheck"]
CMD ["uebalab", "serve", "--host", "0.0.0.0", "--port", "8892"]
