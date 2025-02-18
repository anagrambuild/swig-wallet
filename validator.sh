#!/bin/bash
set -x
export COPYFILE_DISABLE=1
cargo --version
cargo build-sbf && solana-test-validator \
   --limit-ledger-size 0 \
   --bind-address 0.0.0.0 \
   --bpf-program Swig111111111111111111111111111111111111111 target/deploy/swig.so  \
    -r