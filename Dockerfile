FROM ubuntu:20.04

SHELL ["/bin/bash", "-c"]

RUN apt-get update && \
  apt install -y build-essential libssl-dev uuid-dev libsecp256k1-dev

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get install -y python3 cmake git

RUN git clone https://github.com/emscripten-core/emsdk.git

RUN chmod +x /emsdk/emsdk
RUN /emsdk/emsdk install latest
# Make the "latest" SDK "active" for the current user. (writes .emscripten file)
RUN /emsdk/emsdk activate latest
# Activate PATH and other environment variables in the current terminal
RUN source /emsdk/emsdk_env.sh

CMD ["/bin/bash"]
