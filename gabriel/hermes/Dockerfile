FROM nousresearch/hermes-agent@sha256:9c5561579f3ffdf333401797094ac3a743738d6c25d40f4331c7bf77b694238d AS upstream
USER 0:0
COPY gabriel/hermes/prepare_runtime.py /prepare-runtime.py
COPY gabriel/hermes/requirements.lock /expected-requirements.lock
RUN /opt/hermes/.venv/bin/python /prepare-runtime.py

FROM python@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e AS sqlite-build
ARG SQLITE_AUTOCONF_VERSION=3540100
ARG SQLITE_SHA3_256=b6ced585c750916b1052667239a12c25a7ff34e7f06e1e6e01ecb0427657d9c4
RUN apk add --no-cache build-base curl \
    && curl --fail --location --proto '=https' --tlsv1.2 \
        "https://sqlite.org/2026/sqlite-autoconf-${SQLITE_AUTOCONF_VERSION}.tar.gz" -o /tmp/sqlite.tar.gz \
    && python -c "import hashlib,pathlib; p=pathlib.Path('/tmp/sqlite.tar.gz'); assert hashlib.sha3_256(p.read_bytes()).hexdigest()=='${SQLITE_SHA3_256}'" \
    && tar -xzf /tmp/sqlite.tar.gz -C /tmp \
    && cd "/tmp/sqlite-autoconf-${SQLITE_AUTOCONF_VERSION}" \
    && CFLAGS='-O2 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_SESSION -DSQLITE_SECURE_DELETE' \
        ./configure --prefix=/opt/sqlite-fixed --disable-static \
    && make -j"$(nproc)" \
    && make install

FROM python@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 HOME=/tmp HERMES_HOME=/tmp HERMES_DISABLE_LAZY_INSTALLS=1
RUN apk upgrade --no-cache \
    && apk del --no-network sqlite-libs
COPY --from=sqlite-build /opt/sqlite-fixed/lib/libsqlite3.so* /usr/lib/
COPY --from=upstream /payload/hermes /opt/hermes
COPY --from=upstream /payload/requirements.lock /opt/gabriel-hermes/requirements.lock
COPY --from=upstream /payload/image-provenance.json /etc/hermes/image-provenance.json
RUN python -m venv /opt/hermes/.venv \
    && /opt/hermes/.venv/bin/pip install --no-cache-dir --no-deps --no-compile -r /opt/gabriel-hermes/requirements.lock \
    && /opt/hermes/.venv/bin/pip check \
    && /opt/hermes/.venv/bin/python -c "import sqlite3; assert sqlite3.sqlite_version == '3.54.1'"
COPY gabriel/hermes/runtime.py gabriel/hermes/server.py gabriel/hermes/prepare_runtime.py gabriel/hermes/Dockerfile /opt/gabriel-hermes/
USER 10001:10001
WORKDIR /opt/gabriel-hermes
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "/opt/gabriel-hermes/server.py"]
