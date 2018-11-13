#!/bin/bash
WORK_DIR=/project/sawtooth-poet2/src
SGX_DIR=/tmp/sgxsdk

#setting SGX environment
source $SGX_DIR/environment

#building SGX bridge and Enclave
cd $WORK_DIR
mkdir build
cd build
cmake $WORK_DIR/sgx
make 

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$WORK_DIR/build/bin
cd $WORK_DIR/core
