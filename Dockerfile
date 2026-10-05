# syntax=docker/dockerfile:1.7
# PacRipper 1.0 ROM-free OCI/Docker image
# Created by Jacob Hodgkins

FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        g++ \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY Makefile ./
COPY config/ ./config/
COPY src/ ./src/

RUN make clean \
    && make \
        CXXFLAGS="-O2 -DNDEBUG -std=c++17 -Wall -Wextra -Wpedantic -Werror" \
        all \
    && ./bin/PacRipper --version

FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="PacRipper" \
      org.opencontainers.image.description="ROM-free Pac-Man/Puckman disassembly and reconstruction tool" \
      org.opencontainers.image.version="1.0" \
      org.opencontainers.image.source="https://github.com/HodgkinsStudios/PacRipper" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PACRIPPER_PYTHON=/usr/bin/python3

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libarchive13 \
        libgcc-s1 \
        libstdc++6 \
        p7zip-full \
        python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

RUN mkdir -p /opt/pacripper/bin

COPY --from=build /src/bin/PacRipper /opt/pacripper/bin/PacRipper
COPY --from=build /src/bin/PacRipperCore /opt/pacripper/bin/PacRipperCore

COPY scripts/ /opt/pacripper/scripts/
COPY semantic/ /opt/pacripper/semantic/
COPY config/ /opt/pacripper/config/
COPY docs/ /opt/pacripper/docs/
COPY VERSION README.md BUILDING.md CHANGELOG.md LICENSE THIRD_PARTY_NOTICES.md RELEASE_MANIFEST.txt SECURITY.md CITATION.cff /opt/pacripper/

RUN chmod 0755 /opt/pacripper/bin/PacRipper /opt/pacripper/bin/PacRipperCore \
    && find /opt/pacripper/scripts -type f -name '*.py' -exec chmod 0755 {} + \
    && /opt/pacripper/bin/PacRipper --version \
    && python3 -m compileall -q /opt/pacripper/scripts \
    && find /opt/pacripper -type d -name __pycache__ -prune -exec rm -rf {} +

ENTRYPOINT ["/opt/pacripper/bin/PacRipper"]
CMD ["--version"]
