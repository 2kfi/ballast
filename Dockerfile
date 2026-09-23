FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ballast .

FROM alpine:3.20
RUN adduser -D -u 10001 ballast && mkdir -p /data && chown ballast:ballast /data
COPY --from=build /ballast /usr/local/bin/ballast
USER ballast
VOLUME ["/data"]
EXPOSE 5000
ENV BALLAST_CONFIG=/etc/ballast/ballast.json
ENTRYPOINT ["/usr/local/bin/ballast", "serve", "-config", "/etc/ballast/ballast.json"]
