FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV TERM=xterm

SHELL ["/bin/bash", "-lc"]

WORKDIR /opt/greed

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    curl \
    git \
    sudo \
    bash \
    file \
    pkg-config \
    autoconf \
    automake \
    libtool \
    gcc \
    g++ \
    make \
    cmake \
    gperf \
    bison \
    flex \
    clang \
    build-essential \
    doxygen \
    mcpp \
    zlib1g-dev \
    libgmp-dev \
    libffi7 \
    libffi-dev \
    libz3-dev \
    libncurses5-dev \
    libsqlite3-dev \
    libboost-all-dev \
    sqlite3 \
    genisoimage \
    time \
    && rm -rf /var/lib/apt/lists/*

# Install Miniconda
ENV CONDA_DIR=/opt/conda
RUN wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O /tmp/miniconda.sh && \
    bash /tmp/miniconda.sh -b -p $CONDA_DIR && \
    rm -f /tmp/miniconda.sh

ENV PATH=$CONDA_DIR/bin:$PATH

# Accept ToS
RUN conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main && \
    conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r

# Create Python 3.10 environment
RUN conda create -y -n greed python=3.10 && \
    conda clean -afy

# Make python/pip default to conda env
ENV CONDA_DEFAULT_ENV=greed
ENV PATH=$CONDA_DIR/envs/greed/bin:$PATH

# Verify
RUN python --version && python3 --version && pip --version

# Install Soufflé 2.4 for Ubuntu 20.04
RUN wget -O /tmp/souffle.deb \
    https://github.com/souffle-lang/souffle/releases/download/2.4/x86_64-ubuntu-2004-souffle-2.4-Linux.deb && \
    apt-get update && \
    apt-get install -y /tmp/souffle.deb && \
    rm -f /tmp/souffle.deb && \
    rm -rf /var/lib/apt/lists/*

# python virtualenv
ENV CONDA_DEFAULT_ENV=greed
ENV VIRTUAL_ENV=$CONDA_DIR/envs/greed
ENV PATH="$CONDA_DIR/envs/greed/bin:$CONDA_DIR/bin:$PATH"

RUN python --version && python3 --version && pip --version
# Avoid setuptools 81 which breaks ethpwn installation
RUN python -m pip install "setuptools<81"

COPY . /opt/skanf
RUN python -m pip install -r /opt/skanf/requirements.txt
RUN git clone --branch skanf https://github.com/hackingdecentralized/greed-skanf.git /opt/greed 
RUN chmod +x /opt/greed/setup.sh

RUN source $CONDA_DIR/etc/profile.d/conda.sh && \
    conda activate greed && \
    cd /opt/greed && \
    bash /opt/greed/setup.sh -j "$(nproc)"

WORKDIR /opt/skanf

CMD ["/bin/bash", "-l"]
