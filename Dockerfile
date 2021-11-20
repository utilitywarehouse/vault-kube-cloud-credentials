FROM golang:1.16-alpine AS build

WORKDIR /go/src/github.com/utilitywarehouse/vault-kube-cloud-credentials
COPY . /go/src/github.com/utilitywarehouse/vault-kube-cloud-credentials

ENV CGO_ENABLED 0
RUN apk --no-cache add git \
  && go get -t ./... \
  && go test ./... \
  && go build -o /vault-kube-cloud-credentials .

FROM alpine:3.14
COPY --from=build /vault-kube-cloud-credentials /vault-kube-cloud-credentials

# ref: https://github.com/kubernetes/git-sync/blob/release-3.x/Dockerfile.in#L68
#
# By default we will run as this user...
RUN echo "default:x:65533:65533::/tmp:/sbin/nologin" >> /etc/passwd
# ...but the user might choose a different UID and pass --add-user
# which needs to be able to write to /etc/passwd.
RUN chmod 0666 /etc/passwd
# Add the default GID to /etc/group for completeness.
RUN echo "default:x:65533:default" >> /etc/group
# Run as non-root by default.  There's simply no reason to run as root.
USER 65533:65533

ENTRYPOINT [ "/vault-kube-cloud-credentials" ]
