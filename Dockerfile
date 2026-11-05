FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN useradd --create-home --uid 10001 analyst

COPY pyproject.toml README.md LICENSE ./
COPY socdetect ./socdetect

RUN pip install --no-cache-dir .

USER analyst

EXPOSE 8000

ENTRYPOINT ["socdetect"]
CMD ["--help"]
