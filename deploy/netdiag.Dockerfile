# netdiag server image - the diagnostic oracle that logs the source IP:port it
# observes. Built from the repo root (the compose service sets the build
# context), so the COPY paths below are repo-relative.
#
# The container runs with host networking (see the compose service): with
# Docker bridge NAT the client packets would reach the VPS from 172.17.0.x
# and the NAT report - the whole point of the tool - would be wrong.
#
# GOPROXY is an ARG because the LGA VPS network blocks proxy.golang.org;
# pass GOPROXY=https://goproxy.cn,direct from the compose service there.
FROM golang:1.26 AS build
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/netdiag-server ./cmd/server

FROM scratch
COPY --from=build /out/netdiag-server /netdiag-server
ENTRYPOINT ["/netdiag-server"]
