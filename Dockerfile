FROM ubuntu:20.04

RUN apt-get update && \
  apt install -y build-essential libssl-dev uuid-dev libsecp256k1-dev

CMD ["/bin/bash"]
