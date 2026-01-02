# YARA-EDR Build Container
# Multi-stage build for minimal final image

# ==============================================================================
# Stage 1: Build Environment
# ==============================================================================
FROM rust:1.83-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    automake \
    libtool \
    make \
    gcc \
    pkg-config \
    libssl-dev \
    libmagic-dev \
    libjansson-dev \
    flex \
    bison \
    git \
    wget \
    clang \
    libclang-dev \
    llvm-dev \
    && rm -rf /var/lib/apt/lists/*

# Build YARA from source
WORKDIR /tmp
RUN wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.2.tar.gz \
    && tar -xzf v4.5.2.tar.gz \
    && cd yara-4.5.2 \
    && ./bootstrap.sh \
    && ./configure --enable-cuckoo --enable-magic --enable-dotnet \
    && make -j$(nproc) \
    && make install \
    && ldconfig

# Set library path for Rust linker
ENV LIBRARY_PATH=/usr/local/lib
ENV LD_LIBRARY_PATH=/usr/local/lib

# Create app directory
WORKDIR /app

# Copy dependency files first (for caching)
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo

# Create dummy src to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Copy actual source code
COPY src ./src
COPY rules ./rules
COPY config ./config

# Build the application
RUN cargo build --release

# ==============================================================================
# Stage 2: Runtime Environment
# ==============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libmagic1 \
    libjansson4 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy YARA library from builder
COPY --from=builder /usr/local/lib/libyara.so* /usr/local/lib/
RUN ldconfig

# Create app user
RUN useradd -r -s /bin/false yara-edr

# Create necessary directories
RUN mkdir -p /etc/yara-edr/rules \
    && mkdir -p /var/lib/yara-edr/quarantine \
    && mkdir -p /var/log/yara-edr \
    && chown -R yara-edr:yara-edr /var/lib/yara-edr /var/log/yara-edr

# Copy binary and assets
COPY --from=builder /app/target/release/yara-edr /usr/local/bin/
COPY --from=builder /app/rules /etc/yara-edr/rules

# Create container config with correct paths
RUN echo '[general]\n\
log_level = "info"\n\
log_file = "/var/log/yara-edr/edr.log"\n\
pid_file = "/var/run/yara-edr.pid"\n\
workers = 0\n\
\n\
[rules]\n\
paths = ["/etc/yara-edr/rules"]\n\
auto_reload = true\n\
reload_interval = 300\n\
scan_timeout = 60\n\
\n\
[file_monitor]\n\
enabled = false\n\
watch_paths = ["/scan"]\n\
recursive = true\n\
extensions = []\n\
exclude_patterns = ["*.log", "*.tmp"]\n\
max_file_size = 104857600\n\
debounce_ms = 500\n\
\n\
[process_monitor]\n\
enabled = false\n\
scan_on_exec = false\n\
scan_interval = 3600\n\
memory_scan = false\n\
scan_cmdline = true\n\
exclude_names = ["systemd", "init"]\n\
\n\
[response]\n\
quarantine_path = "/var/lib/yara-edr/quarantine"\n\
auto_quarantine = false\n\
auto_kill = false\n\
preserve_metadata = true\n\
\n\
[alerts]\n\
output = "stdout"\n\
file_path = "/var/log/yara-edr/alerts.json"\n\
include_match_data = true\n\
max_match_data = 256\n\
severity_threshold = "info"' > /etc/yara-edr/config.toml

# Set permissions
RUN chmod +x /usr/local/bin/yara-edr

# Default command
ENTRYPOINT ["yara-edr"]
CMD ["--help"]

# ==============================================================================
# Stage 3: Development Environment (optional)
# ==============================================================================
FROM builder AS development

# Install development tools
RUN apt-get update && apt-get install -y \
    gdb \
    valgrind \
    strace \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install Rust tools
RUN rustup component add rustfmt clippy rust-analyzer

WORKDIR /app

# Keep container running for development
CMD ["bash"]
