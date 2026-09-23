FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /goreg .

FROM alpine:3.20
RUN adduser -D -u 10001 goreg && mkdir -p /data && chown goreg:goreg /data
COPY --from=build /goreg /usr/local/bin/goreg
USER goreg
VOLUME ["/data"]
EXPOSE 5000
ENV GOREG_CONFIG=/etc/goreg/goreg.json
ENTRYPOINT ["/usr/local/bin/goreg", "serve", "-config", "/etc/goreg/goreg.json"]
