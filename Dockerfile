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
        rustc && \
    apt clean

# switch to the sandbox user
USER builder

# retry build because cargo sometimes segfaults during download (#918854)
#
# the `build-release` target is used instead of the default because
# `install` calls it after anyways
RUN cd /home/builder/sequoia && \
        PYTHON=disable CARGO_TARGET_DIR=target cargo build --release --all && \
        PYTHON=disable CARGO_TARGET_DIR=target cargo build --release --package sequoia-sqv && \
        PYTHON=disable CARGO_TARGET_DIR=target cargo build --release --package sequoia-sq && \
        install -d /opt/usr/local/bin && \
        install -t /opt/usr/local/bin target/release/sq && \
        install -t /opt/usr/local/bin target/release/sqv

FROM debian:buster-slim AS sq-base

RUN groupadd -r user && \
    useradd --no-log-init -r -g user user && \
    mkdir /home/user && \
    chown -R user:user /home/user && \
    apt update && apt upgrade -y && \
    apt install -y libssl1.1 libsqlite3-0 && \
    apt clean && \
    rm -fr -- /var/lib/lists/* /var/cache/*

FROM sq-base AS sqv

COPY --from=build /opt/usr/local/bin/sqv /usr/local/bin/sqv

USER user

ENTRYPOINT /usr/local/bin/sqv

FROM sqv AS sq

COPY --from=build /opt/usr/local/bin/sq /usr/local/bin/sq

ENTRYPOINT /usr/local/bin/sq

