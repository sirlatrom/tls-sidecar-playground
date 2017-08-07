FROM        golang:alpine as build
COPY        httpproxy.crt /usr/local/share/ca-certificates/
RUN         apk add --update git ca-certificates && update-ca-certificates
COPY        vendor/ /go/src/
RUN         cd /go/src && CGO_ENABLED=0 go install -v ./...

COPY        *.go /go/src/github.com/sirlatrom/outproxy/
RUN         cd /go/src/github.com/sirlatrom/outproxy && CGO_ENABLED=0 go install -v

FROM        scratch
COPY --from=build \
            /go/bin/outproxy /outproxy
ENTRYPOINT  ["/outproxy"]
