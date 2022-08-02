# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

include $(CURDIR)/buildenv.mk

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

SGX_COMMON_CFLAGS += -fstack-protector

######## CUSTOM Settings ########

CUSTOM_LIBRARY_PATH := /sgxdcnet/lib
CUSTOM_EDL_PATH := ./vendor/edl
CUSTOM_COMMON_PATH := ./vendor/common

######## Cargo Settings ########
# The tmp dir to hold intermediate compilation output
# this must correspond to .cargo/config.toml
TARGET_DIR := /tmp/sgxdcnet/target/debug

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

ifeq ($(MITIGATION-CVE-2020-0551), LOAD)
export MITIGATION_CVE_2020_0551=LOAD
else ifeq ($(MITIGATION-CVE-2020-0551), CF)
export MITIGATION_CVE_2020_0551=CF
endif

Crypto_Library_Name := sgx_tcrypto
KeyExchange_Library_Name := sgx_tkey_exchange
ProtectedFs_Library_Name := sgx_tprotected_fs

.PHONY: all
all: untrusted enclave

######## EDL Objects ########

Enclave_EDL_Files := $(TARGET_DIR)/Enclave_t.c $(TARGET_DIR)/Enclave_t.h $(TARGET_DIR)/Enclave_u.c $(TARGET_DIR)/Enclave_u.h

$(Enclave_EDL_Files): $(SGX_EDGER8R) Enclave.edl
	$(SGX_EDGER8R) --trusted Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --trusted-dir $(TARGET_DIR)
	$(SGX_EDGER8R) --untrusted Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --untrusted-dir $(TARGET_DIR)
	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## Enclave Wrapper Objects ########

$(TARGET_DIR)/Enclave_u.o: $(Enclave_EDL_Files)
	@$(CC) $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -I./include -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH) -c $(TARGET_DIR)/Enclave_u.c -o $@
	@echo "CC   <=  $<"

$(CUSTOM_LIBRARY_PATH)/libEnclaveWrapper.a: $(TARGET_DIR)/Enclave_u.o
	mkdir -p $(CUSTOM_LIBRARY_PATH)
	$(AR) rcsD $@ $^

.PHONY: untrusted
untrusted: $(CUSTOM_LIBRARY_PATH)/libEnclaveWrapper.a

######## Enclave Objects ########


RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I ./enclave -I./include
RustEnclave_Link_Libs := -L$(TARGET_DIR) -ldcnetenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) $(ENCLAVE_CFLAGS) $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,--version-script=Enclave.lds \
	$(ENCLAVE_LDFLAGS)

$(TARGET_DIR)/Enclave_t.o: $(Enclave_EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c $(TARGET_DIR)/Enclave_t.c -o $@
	@echo "CC   <=  $<"

$(TARGET_DIR)/enclave.so: $(TARGET_DIR)/Enclave_t.o
	@cargo build
	@$(CXX) $(TARGET_DIR)/Enclave_t.o -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

${CUSTOM_LIBRARY_PATH}/enclave.signed.so: $(TARGET_DIR)/enclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave_private.pem -enclave $(TARGET_DIR)/enclave.so -out $@ -config Enclave.config.xml
	@echo "SIGN =>  $@"

.PHONY: enclave
enclave: ${CUSTOM_LIBRARY_PATH}/enclave.signed.so

.PHONY: clean
clean:
	@cargo clean
	@rm -f $(CUSTOM_LIBRARY_PATH)/*.a
	@rm -rf ${CUSTOM_LIBRARY_PATH}/enclave.signed.so