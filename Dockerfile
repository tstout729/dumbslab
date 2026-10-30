# syntax=docker/dockerfile:1
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
ARG DUMBSLAB_GIT_SHA
RUN DUMBSLAB_GIT_SHA="$DUMBSLAB_GIT_SHA" cargo build --release -p dumbslab

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data dumbslab && mkdir -p /data && chown dumbslab /data
COPY --from=build /src/target/release/dumbslab /usr/local/bin/dumbslab
USER dumbslab
VOLUME /data
ENV DUMBSLAB_DB=/data/dumbslab.db DUMBSLAB_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["dumbslab"]
CMD ["serve"]
