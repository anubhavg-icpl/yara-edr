# Contributing to YARA-EDR

Thank you for your interest in contributing to YARA-EDR! This guide will help you get started with development.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
  - [Option 1: Local Development](#option-1-local-development)
  - [Option 2: Docker Development](#option-2-docker-development)
- [Building](#building)
- [Testing](#testing)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)

---

## Development Environment Setup

### Option 1: Local Development

#### Prerequisites

| Dependency | Version | Purpose |
|------------|---------|---------|
| Rust | 1.70+ | Programming language |
| YARA | 4.3+ | Pattern matching engine |
| GCC/Clang | Any recent | C compiler for YARA bindings |
| pkg-config | Any | Build configuration |
| OpenSSL | 1.1+ | TLS support |

#### Step 1: Install Rust

```bash
# Install rustup (Rust toolchain manager)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Reload shell
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

#### Step 2: Install System Dependencies

**Arch Linux:**
```bash
sudo pacman -S base-devel openssl pkg-config automake libtool flex bison
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential automake libtool make gcc pkg-config \
    libssl-dev libmagic-dev flex bison git
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc gcc-c++ make automake libtool pkgconfig \
    openssl-devel file-devel flex bison git
```

#### Step 3: Install YARA Library

```bash
# Clone YARA
git clone https://github.com/VirusTotal/yara.git
cd yara

# Build and install
./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet
make -j$(nproc)
sudo make install

# Update library cache
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/yara.conf
sudo ldconfig

# Verify installation
yara --version
```

#### Step 4: Clone and Build YARA-EDR

```bash
# Clone repository
git clone https://github.com/anubhavg-icpl/yara-edr.git
cd yara-edr

# Build debug version (faster compilation)
cargo build

# Build release version (optimized)
cargo build --release

# Run tests
cargo test

# Verify it works
./target/release/yara-edr --version
./target/release/yara-edr -c ./config/config.toml validate
```

---

### Option 2: Docker Development

If you prefer containerized development or don't want to install dependencies locally:

#### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+ (optional)

#### Quick Start with Docker

```bash
# Clone repository
git clone https://github.com/anubhavg-icpl/yara-edr.git
cd yara-edr

# Build development container
docker build --target development -t yara-edr:dev .

# Run development shell
docker run -it --rm \
    -v $(pwd):/app \
    -v cargo-cache:/usr/local/cargo/registry \
    yara-edr:dev bash

# Inside container: build and test
cargo build --release
cargo test
```

#### Using Docker Compose

```bash
# Start development environment
docker-compose run --rm dev

# Inside container
cargo build --release
cargo test
./target/release/yara-edr --version
```

#### Build Production Image

```bash
# Build production image
docker build -t yara-edr:latest .

# Run scanner
docker run --rm -v /path/to/scan:/scan:ro yara-edr:latest \
    -c /etc/yara-edr/config.toml scan /scan

# Check version
docker run --rm yara-edr:latest --version
```

---

## Building

### Build Commands

```bash
# Debug build (faster compilation, includes debug symbols)
cargo build

# Release build (optimized, slower compilation)
cargo build --release

# Build with all features
cargo build --release --all-features

# Check code without building
cargo check

# Clean build artifacts
cargo clean
```

### Build Troubleshooting

**Error: `unable to find library -lyara`**

The linker can't find YARA. Solutions:

```bash
# Option 1: Set LIBRARY_PATH
LIBRARY_PATH=/usr/local/lib cargo build --release

# Option 2: Add to ldconfig (permanent)
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/yara.conf
sudo ldconfig
```

**Error: `yara.h not found`**

YARA headers not installed:

```bash
# Check if headers exist
ls /usr/local/include/yara/

# If not, reinstall YARA with headers
cd /path/to/yara
sudo make install
```

---

## Testing

### Run Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run tests in specific module
cargo test config::tests

# Run ignored tests
cargo test -- --ignored
```

### Manual Testing

```bash
# Test EICAR detection
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
./target/release/yara-edr -c ./config/config.toml scan /tmp/eicar.txt

# Test validation
./target/release/yara-edr -c ./config/config.toml validate

# Test process scanning
./target/release/yara-edr -c ./config/config.toml scan-process $$
```

---

## Code Style

### Formatting

```bash
# Check formatting
cargo fmt --check

# Auto-format code
cargo fmt
```

### Linting

```bash
# Run clippy linter
cargo clippy

# Run clippy with warnings as errors
cargo clippy -- -D warnings
```

### Pre-commit Checklist

Before submitting a PR, ensure:

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy` has no warnings
- [ ] `cargo test` passes
- [ ] `cargo build --release` succeeds
- [ ] New code has appropriate tests
- [ ] Documentation is updated if needed

---

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Make** your changes
4. **Test** your changes: `cargo test`
5. **Format** code: `cargo fmt`
6. **Lint** code: `cargo clippy`
7. **Commit** with clear message: `git commit -am 'Add my feature'`
8. **Push** to your fork: `git push origin feature/my-feature`
9. **Open** a Pull Request

### Commit Message Format

```
type: short description

Longer description if needed.

- Bullet points for multiple changes
- Another change
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `build`, `ci`

Examples:
- `feat: Add network packet scanning`
- `fix: Handle empty rule files gracefully`
- `docs: Update installation instructions`

---

## Project Structure

```
yara-edr/
├── .cargo/
│   └── config.toml      # Cargo build configuration
├── config/
│   └── config.toml      # Default EDR configuration
├── rules/
│   ├── default.yar      # Base detection rules
│   ├── linux.yar        # Linux-specific rules
│   ├── malwatch.yar     # Webshell/backdoor rules
│   ├── elastic_linux.yar # Elastic Security rules
│   ├── community_linux.yar # Community rules
│   └── toolkit.yar      # Hacking tool detection
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library exports
│   ├── config.rs        # Configuration parsing
│   ├── daemon.rs        # Daemon mode
│   ├── engine/          # YARA scanning engine
│   ├── monitors/        # File/process monitors
│   ├── detection/       # Detection logic
│   ├── response/        # Response actions
│   ├── alerts/          # Alert handling
│   └── utils/           # Utility functions
├── Cargo.toml           # Rust dependencies
├── Dockerfile           # Container build
├── docker-compose.yml   # Container orchestration
└── README.md            # Project documentation
```

---

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/anubhavg-icpl/yara-edr/issues)
- **Discussions**: [GitHub Discussions](https://github.com/anubhavg-icpl/yara-edr/discussions)

Thank you for contributing!
