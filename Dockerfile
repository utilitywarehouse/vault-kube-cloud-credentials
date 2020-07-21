FROM golang:1.13-alpine AS build
WORKDIR /go/src/github.com/utilitywarehouse/vault-kube-cloud-credentials
COPY . /go/src/github.com/utilitywarehouse/vault-kube-cloud-credentials
ENV CGO_ENABLED 0
RUN apk --no-cache add git &&\
    go get -t ./... &&\
    go test ./... &&\
    go build -o /vault-kube-cloud-credentials .

FROM alpine:3.10
RUN apk --no-cache add tini
COPY --from=build /vault-kube-cloud-credentials /vault-kube-cloud-credentials

ENTRYPOINT ["/sbin/tini", "--"]
CMD [ "/vault-kube-cloud-credentials" ]
