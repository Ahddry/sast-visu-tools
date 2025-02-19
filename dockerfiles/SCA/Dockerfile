FROM node:18-bullseye-slim

# Install Python & pip
RUN apt-get update && apt-get install -y python3 python3-pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Verify installation
RUN python3 --version && npm --version

# Install cdxgen
RUN npm install -g @cyclonedx/cdxgen

# Install depscan
RUN pip install owasp-depscan

# Ensure the binaries are in the PATH
ENV PATH="/usr/local/bin:${PATH}"

# Verify installation
RUN cdxgen --version
RUN depscan --version

# Download and cache depscan database
RUN depscan --cache --sync

# Set the entrypoint to bash for interactive use
ENTRYPOINT ["/bin/bash"]