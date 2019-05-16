# we do not use the rust image because it's based on Debian stretch
# where nettle and rustc are too old
FROM debian:buster AS build

COPY . /home/builder/sequoia

# create a sandbox user for the build (in ~builder) and install (in /opt)
# give it permissions to the build dir and home
# upgrade everything
# add dependencies, as specified by the Sequoia README.md file
RUN groupadd -r builder && \
    useradd --no-log-init -r -g builder builder && \
    chown -R builder:builder /home/builder /opt && \
    apt update && apt upgrade -yy && \
    apt install -y --no-install-recommends \
        ca-certificates \
        capnproto \
        cargo \
        clang \
        git \
        libsqlite3-dev \
        libssl-dev \
        make \
        nettle-dev \
        pkg-config \
        python3-dev \
        python3-setuptools \
        python3-cffi \
        python3-pytest \
        rustc

# switch to the sandbox user
USER builder

# retry build because cargo sometimes segfaults during download (#918854)
#
# the `build-release` target is used instead of the default because
# `install` calls it after anyways
RUN make -C /home/builder/sequoia build-release; \
    make -C /home/builder/sequoia build-release; \
    make -C /home/builder/sequoia build-release && \
    make -C /home/builder/sequoia install DESTDIR=/opt/

FROM debian:buster-slim

COPY --from=build /opt/ /
