# PyFNetwork Toolbox -- one image, one process, one port:
# webui/app.py (FastAPI/uvicorn) serves the cli_scripts/ UI directly and
# mounts each apps/<name>/ ASGI app in-process at /app/<name> (see
# webui/mounts.py) -- no subprocess, no extra port, no HTTP proxy hop.
FROM python:3.12-slim

WORKDIR /srv/toolbox

# fonts-dejavu-core: Pillow text rendering used by the switch-visualizer
# app (Segoe UI isn't available on Linux).
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Each apps/<name>/ with its own installable package needs its own pip
# install line -- see README's "Adding an app module" section.
RUN pip install --no-cache-dir -r webui/requirements.txt && \
    pip install --no-cache-dir ./apps/switch-visualizer

ENV PYTHONUNBUFFERED=1

# Just the one port -- every app is mounted in-process, nothing else to expose.
EXPOSE 5000

CMD ["python3", "webui/app.py"]
