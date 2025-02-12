FROM golang:1.23-alpine AS build

WORKDIR /go/src/github.com/utilitywarehouse/vault-kube-cloud-credentials
COPY . /go/src/github.com/utilitywarehouse/vault-kube-cloud-credentials

ENV CGO_ENABLED=0
RUN apk --no-cache add git \
      && go get -t ./... \
      && go test ./... \
      && go build -o /vault-kube-cloud-credentials .

FROM alpine:3.21
COPY --from=build /vault-kube-cloud-credentials /vault-kube-cloud-credentials

# ref: https://github.com/kubernetes/git-sync/blob/master/Dockerfile.in#L68
#
# By default we will run as this user...
RUN echo "default:x:1000:1000::/tmp:/sbin/nologin" >> /etc/passwd
# ...but the user might choose a different UID and pass --add-user
# which needs to be able to write to /etc/passwd.
RUN chmod 0666 /etc/passwd
# Add the default GID to /etc/group for completeness.
RUN echo "default:x:1000:default" >> /etc/group
# Run as non-root by default.  There's simply no reason to run as root.
USER 1000:1000

ENTRYPOINT [ "/vault-kube-cloud-credentials" ]
