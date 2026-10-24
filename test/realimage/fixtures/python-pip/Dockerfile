# Real-image fixture: Python with a real requirements.txt (FR-47, FR-48, FR-49).
#
# Not part of FR-50 (pin status check): pip pins aren't OS package pins, and
# PyPI never removes a published version, so unlike the other three fixtures
# this one needs no dynamic version resolution -- the pinned version here
# stays installable forever.
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python3", "-c", "import requests; print(requests.__version__)"]
