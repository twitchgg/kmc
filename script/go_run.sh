#!/bin/sh

go run ../main.go \
    --etcd-endpoints="http://192.168.138.98:2379" \
    --data-center="testing-dc" \
    --rpc-cert-path="../../data/certs" \
    --rpc-bind="0.0.0.0:1357" \
    --bind-eth="eth0" \
    --kmc-path="../test/data/cert.db" \
    --kmc-reset=false
