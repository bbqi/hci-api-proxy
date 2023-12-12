FROM golang:alpine

ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.io,direct

WORKDIR /go/src/sarp
COPY . .
RUN go env && go build -o server .

FROM alpine:latest
LABEL MAINTAINER="puyu@bbqi.cc"

WORKDIR /go/src/sarp
COPY --from=0 /go/src/sarp/server ./
COPY --from=0 /go/src/sarp/config.yaml ./

EXPOSE 12002

ENTRYPOINT ./server
