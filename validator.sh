#!/bin/bash
set -x
export COPYFILE_DISABLE=1
cargo --version
cargo build-sbf --arch v1 && solana-test-validator \
   --limit-ledger-size 0 \
   --bind-address 0.0.0.0 \
   --bpf-program swigypWHEksbC64pWKwah1WTeh9JXwx8H1rJHLdbQMB target/deploy/swig.so  \
    -r \
    --ticks-per-slot 10 \
    --slots-per-epoch 64
