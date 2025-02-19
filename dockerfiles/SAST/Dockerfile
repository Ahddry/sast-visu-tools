FROM python:3.10-slim

# Set environment variables
ENV VISU_SEMGREP_CI_URL="https://github.com/Ahddry/sast-visu-tools/releases/download/0.5.0/visu-semgrep-ci"
ENV SEMGREP_CUSTOM_URL="https://github.com/Ahddry/sast-visu-tools/releases/download/0.5.0/semgrep-custom"

# Install wget and other dependencies
RUN apt-get update && apt-get install -y wget

# Download visu-semgrep-ci and semgrep-custom
RUN wget -O /usr/local/bin/visu-semgrep-ci $VISU_SEMGREP_CI_URL && \
    wget -O /usr/local/bin/semgrep-custom $SEMGREP_CUSTOM_URL

# Make the binaries executable
RUN chmod +x /usr/local/bin/visu-semgrep-ci /usr/local/bin/semgrep-custom

# Install semgrep using pip
RUN pip install semgrep

# Ensure the binaries are in the PATH
ENV PATH="/usr/local/bin:${PATH}"

# Verify installation
RUN visu-semgrep-ci -t

# Set the entrypoint to bash for interactive use
ENTRYPOINT ["/bin/bash"]