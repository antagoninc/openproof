ARG BASE=python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
FROM ${BASE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY openproof_ref.py openproof_trust.py worker.py /app/
USER 65532:65532
ENTRYPOINT ["python", "-I", "/app/worker.py"]
