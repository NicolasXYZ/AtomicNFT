Build instructions
==================

1. Start the docker with `./start-docker.sh`. The source code is mounted to `/root/sgx`
3. Go to the source code dir: `cd /root/sgx`
4. Build the enclave image: `make -BC sgx/enclave`. This will build the enclave image and put the artifact in `/sgxdcnet/lib/enclave.signed.so`. Note that `-B` is needed to force make to rebuild.  
5. Run the test script: `./run_tests.h`

### Note

> Make is not smart enough to rebuild the enclave image. So always do Step 4 whenever you change the `interface` and `enclave` crates.
