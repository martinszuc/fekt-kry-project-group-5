FROM python:3.11-slim

# Build tools for liboqs native library
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake build-essential git libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs shared library
RUN git clone --depth 1 --branch 0.15.0 \
        https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /tmp/liboqs/build --parallel 4 \
    && cmake --install /tmp/liboqs/build \
    && ldconfig \
    && rm -rf /tmp/liboqs

WORKDIR /app

# Install Python deps (cached layer — only rebuilds when requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
