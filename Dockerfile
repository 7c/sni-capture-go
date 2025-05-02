FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y curl gcc build-essential libpcap-dev git ca-certificates \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu 
    # binutils-aarch64-linux-gnu
# Install Go
RUN curl -LO https://go.dev/dl/go1.23.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.5.linux-amd64.tar.gz && \
    rm go1.23.5.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
# Pre-fetch Go modules by preparing a dummy project
RUN mkdir /tmp/dummy
WORKDIR /tmp/dummy

# RUN go mod init dummy 
COPY go.mod /tmp/dummy/
COPY go.sum /tmp/dummy/
RUN go get -u github.com/7c/mygobase
RUN go get -u github.com/alecthomas/kingpin/v2
RUN go get -u github.com/go-chi/chi/v5
RUN go get -u github.com/dreadl0ck/ja3
RUN go get -u github.com/dreadl0ck/tlsx
RUN go get -u github.com/fatih/color
RUN go get -u github.com/google/gopacket
RUN go get -u github.com/go-resty/resty/v2
RUN go get -u gopkg.in/natefinch/lumberjack.v2
RUN go get -u github.com/alecthomas/units
RUN go get -u github.com/xhit/go-str2duration/v2
RUN go get -u golang.org/x/crypto
RUN go get -u github.com/mattn/go-colorable
RUN go get -u github.com/mattn/go-isatty
# RUN cd /tmp/dummy && go mod download


# Install Goreleaser
RUN curl -sL https://github.com/goreleaser/goreleaser/releases/latest/download/goreleaser_Linux_x86_64.tar.gz \
    | tar xz -C /usr/local/bin goreleaser

WORKDIR /app
# ENTRYPOINT ["goreleaser", "release", "--skip=publish", "--clean", "--skip=validate"]
ENTRYPOINT ["goreleaser", "release", "--clean", "--skip=validate"]
# ENTRYPOINT ["bash"]