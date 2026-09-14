FROM node:20-trixie-slim AS scanner-build

ARG CRS_COMMIT=3b89d5a05322f448b4b74b9cadc5fb05ac6915ad
ARG CRS_VERSION=4.25.1
ARG MODSECURITY_VERSION=v3.0.16

RUN apt-get -o Acquire::Retries=5 -o Acquire::ForceIPv4=true update \
    && apt-get -o Acquire::Retries=5 -o Acquire::ForceIPv4=true install -y --no-install-recommends \
      ca-certificates \
      autoconf \
      automake \
      bison \
      build-essential \
      flex \
      git \
      libpcre2-dev \
      libtool \
      libxml2-dev \
      libyajl-dev \
      nlohmann-json3-dev \
      pkgconf \
      zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 --branch "${MODSECURITY_VERSION}" \
      --recurse-submodules --shallow-submodules \
      https://github.com/owasp-modsecurity/ModSecurity.git /build/ModSecurity \
    && cd /build/ModSecurity \
    && ./build.sh \
    && ./configure --prefix=/opt/modsecurity --with-pcre2 --with-libxml2 --with-yajl \
      --without-curl --without-geoip --without-lmdb --without-lua \
      --without-maxmind --without-ssdeep --disable-static \
    && make -j2 \
    && make install

COPY scanner/modsecurity_scanner.cpp ./modsecurity_scanner.cpp
RUN g++ -std=c++17 -O2 -Wall -Wextra \
      -DCRS_VERSION=\"${CRS_VERSION}\" \
      -I/opt/modsecurity/include \
      modsecurity_scanner.cpp -L/opt/modsecurity/lib -lmodsecurity \
      -Wl,-rpath,/opt/modsecurity/lib -o modsecurity-scanner

RUN git init -q /opt/owasp-crs \
    && git -C /opt/owasp-crs remote add origin https://github.com/coreruleset/coreruleset.git \
    && git -C /opt/owasp-crs fetch -q --depth 1 origin "${CRS_COMMIT}" \
    && git -C /opt/owasp-crs checkout -q --detach FETCH_HEAD \
    && rm -rf /opt/owasp-crs/.git \
    && cp /opt/owasp-crs/crs-setup.conf.example /opt/owasp-crs/crs-setup.conf

FROM node:20-trixie-slim

RUN apt-get -o Acquire::Retries=5 -o Acquire::ForceIPv4=true update \
    && apt-get -o Acquire::Retries=5 -o Acquire::ForceIPv4=true install -y --no-install-recommends \
      ca-certificates libpcre2-8-0 libxml2 libyajl2 zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --from=scanner-build /build/modsecurity-scanner /app/bin/modsecurity-scanner
COPY --from=scanner-build /opt/modsecurity /opt/modsecurity
COPY --from=scanner-build /opt/owasp-crs /opt/owasp-crs
COPY . .

EXPOSE 8080

CMD ["node", "server.js"]
