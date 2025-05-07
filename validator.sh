#!/bin/bash
set -x
export COPYFILE_DISABLE=1
cargo --version
cargo build-sbf && solana-test-validator \
   --limit-ledger-size 0 \
   --bind-address 0.0.0.0 \
   --bpf-program swigDk8JezhiAVde8k6NMwxpZfgGm2NNuMe1KYCmUjP target/deploy/swig.so  \
    -r