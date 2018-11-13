This directory contains the sgx related code for PoET2 consensus engine.

rust_sgxffi - Rust APIs for the SGX enclave  
rust_sgx_bridge - Rust-C++ SGX bridge code  
libpoet_bridge, poet_enclave_sgx - Enclave code (untrusted)  
libpoet_enclave - Enclave code (trusted)  
testEnclave - Unit test code for enclave  
libpoet_shared - Shared Utility functions  

NOTE: Below steps are not needed for docker builds. Only applicable for standalone development builds

Steps to build PoET2 SGX Enclave in standalone mode in SIMUATOR mode
1. Install SGX binaries
	1. Download SGX SDK binary from below link
	   https://download.01.org/intel-sgx/linux-2.3/ubuntu16.04-server/sgx_linux_x64_sdk_2.3.100.46354.bin
	2. assign exec permission to binary and execute
	   chmod +x sgx_linux_x64_sdk_2.3.100.46354.bin
	   ./sgx_linux_x64_sdk_2.3.100.46354.bin 
	3. set SGX SDK lib path
	   chmod +x <SGX_bin_path>/sgxsdk/environment
	   source <SGX_bin_path>/sgxsdk/environment

2.  Install libclang-dev and libjson-c-dev libraries
	apt-get install libclang-dev/libjson-c-dev

3. Build SGX code
	1. create build folder and build SGX code from the folder
	   eg. mkdir <sawtooth-poet2-home>/src/build 
	       cd  <sawtooth-poet2-home>/src/build/
	2. cmake ../sgx
	3. make

Steps to run Unit test
1. set SGX binary path
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<sawtooth-poet2-home>/src/build/bin
2. execute unit tests using cargo
	cd <sawtooth-poet2-home>/sawtooth-poet2/src/sgx/rust_sgxffi
	cargo test -- --nocapture

3. C++ unit test cases
    cd <sawtooth-poet2-home>/src/build/bin
    ./testEnclave
    
