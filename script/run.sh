#!/bin/sh
echo "TSA KMC"
../build/tsa-kmc-v1.0.0-linux-amd64 \
    --etcd-endpoints="http://10.10.10.219:2379,http://10.10.10.220:2379,http://10.10.10.221:2379" \
    --data-center="testing-dc" \
    --rpc-cert-path="../../tsa/data/certs" \
    --rpc-bind="0.0.0.0:1357" \
    --bind-eth="eth0" \
    --kmc-path="../../tsa/data/cert.db" \
    --kmc-reset=false
