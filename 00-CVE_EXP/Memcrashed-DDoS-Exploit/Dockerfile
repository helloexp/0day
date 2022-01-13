FROM alpine:latest

RUN apk add --update python3 py3-pip git tcpdump

RUN git clone https://github.com/649/Memcrashed-DDoS-Exploit.git Memcrashed
WORKDIR Memcrashed
# COPY requirements.txt .
# COPY api.txt .
# COPY bots.txt .
RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "Memcrashed.py"]
