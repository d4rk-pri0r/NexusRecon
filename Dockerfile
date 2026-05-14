FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="NexusRecon"
LABEL org.opencontainers.image.description="Agentic OSINT orchestration framework"
LABEL org.opencontainers.image.licenses="Proprietary"

# ── System deps ───────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget jq dnsutils whois \
    libmagic1 libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libffi-dev libssl-dev \
    build-essential ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Go toolchain for binary deps ──────────────────────────────
RUN wget -q https://go.dev/dl/go1.22.3.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:${PATH}"

# ── Go-based OSINT tools ──────────────────────────────────────
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true
RUN go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true
RUN go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true
RUN go install github.com/sensepost/gowitness@latest 2>/dev/null || true

# ── gitleaks ──────────────────────────────────────────────────
RUN GITLEAKS_VERSION=8.18.4 && \
    curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar xz -C /usr/local/bin gitleaks || true

# ── trufflehog ────────────────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin 2>/dev/null || true

# ── amass ─────────────────────────────────────────────────────
RUN AMASS_VERSION=4.2.0 && \
    curl -sL "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_linux_amd64.zip" \
    -o /tmp/amass.zip && unzip -jo /tmp/amass.zip "*/amass" -d /usr/local/bin/ && rm /tmp/amass.zip || true

# ── Python application ────────────────────────────────────────
WORKDIR /app
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -e . || pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e . 2>/dev/null || true

# ── Runtime config ────────────────────────────────────────────
ENV NEXUS_OUTPUT_DIR=/data/campaigns
ENV NEXUS_DB_PATH=/data/nexusrecon.db
ENV NEXUS_LOG_FORMAT=json

VOLUME ["/data", "/app/.env"]

ENTRYPOINT ["nexusrecon"]
CMD ["--help"]
