FROM intel/sgx-sdk:2.17.100.3-ubuntu20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    libglog-dev \
    cmake \
    build-essential \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build in Hardware mode
# We need to ensure the bin directories exist and build everything
RUN make clean && \
    make SGX_MODE=HW

# Organize binaries into a single bin directory for easier access in K8s
RUN mkdir -p /app/bin_final && \
    # Server binaries
    cp server/bin/appserver /app/bin_final/ && \
    cp server/bin/*.signed.so /app/bin_final/ && \
    # Client binaries
    cp client/bin/apprequester /app/bin_final/ && \
    cp client/bin/*.signed.so /app/bin_final/ && \
    # User binaries
    cp user/bin/appinsertor /app/bin_final/ && \
    cp user/bin/*.signed.so /app/bin_final/ || true

# Move the consolidated bin to /app/bin (overwriting the source bin folders if they conflict, but here we just want a clean run dir)
# The K8s scripts expect binaries in /app/bin
RUN rm -rf /app/bin && mv /app/bin_final /app/bin

# Set library path to include SGX libraries and local libs
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/intel/sgxsdk/lib64:/usr/local/lib

# Default command
CMD ["/bin/bash"]
