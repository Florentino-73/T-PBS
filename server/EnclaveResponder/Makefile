include ../buildenv.mk

ifneq ($(SGX_MODE), HW)
        Trts_Library_Name := sgx_trts_sim
        Service_Library_Name := sgx_tservice_sim
else
        Trts_Library_Name := sgx_trts
        Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

ENCLAVE_NAME := libenclave_responder.so
SIGNED_ENCLAVE_NAME := libenclave_responder.signed.so

$(SIGNED_ENCLAVE_NAME) : $(ENCLAVE_NAME)
	@$(SGX_ENCLAVE_SIGNER) sign -key EnclaveResponder_private_test.pem -enclave $(ENCLAVE_NAME) -out $@ -config EnclaveResponder.config.xml
	@cp $(SIGNED_ENCLAVE_NAME) $(TOPDIR)/$(OUTDIR)/
	@echo "SIGN =>  $@"

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
ENCLAVE_LINK_FLAGS := $(Enclave_Security_Link_Flags) \
     -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) -L/opt/intel/oneapi/ippcp/latest/lib/intel64 \
             -Wl,--whole-archive -lsgx_tswitchless -l$(Trts_Library_Name) -Wl,--no-whole-archive \
             -Wl,--whole-archive -lsgx_tcmalloc -Wl,--no-whole-archive \
			 -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -lippcp -lsgx_tprotected_fs \
             -Wl,--end-group \
             -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
             -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
             -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
             -Wl,--version-script=EnclaveResponder.lds 

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wconversion -Wredundant-decls
SGX_COMMON_FLAGS += -D_LOG

SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I../Include -I../EnclaveResponder -I/opt/intel/oneapi/ippcp/latest/include -I./ShieldStore
Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -mno-avx -mno-avx2

# TCMALLOC 
TCMALLOC_Default_Include_Paths := -I./ShieldStore/gperftools/gperftools-2.5/src
TCMALLOC_Include_Paths := $(TCMALLOC_Default_Include_Paths) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx


am__append_2 = -Wall -Wwrite-strings -Woverloaded-virtual \
               -Wno-sign-compare \
 	       -fno-builtin-malloc -fno-builtin-free -fno-builtin-realloc \
               -fno-builtin-calloc -fno-builtin-cfree \
               -fno-builtin-memalign -fno-builtin-posix_memalign \
               -fno-builtin-valloc -fno-builtin-pvalloc

am__append_3 = -fno-builtin
am__append_5 = -Wno-unused-result
am__append_8 = -DNO_FRAME_POINTER

# note:define not debug;
# TCMALLOC_CFlags := -Wall -DHAVE_CONFIG_H -DNO_TCMALLOC_SAMPLES -DNDEBUG -DNO_HEAP_CHECK -DTCMALLOC_SGX -DTCMALLOC_NO_ALIASES -fstack-protector -ffreestanding -nostdinc -fvisibility=hidden -fPIC $(am__append_2) $(am__append_3) $(am__append_5) $(am__append_8)

TCMALLOC_CFlags := -Wall -DHAVE_CONFIG_H -DNO_TCMALLOC_SAMPLES -DNO_HEAP_CHECK -DTCMALLOC_SGX -DTCMALLOC_NO_ALIASES -fstack-protector -ffreestanding -nostdinc -fvisibility=hidden -fPIC $(am__append_2) $(am__append_3) $(am__append_5) $(am__append_8)


# TCMALLOC_CFlags := -Wall -DHAVE_CONFIG_H -DNO_TCMALLOC_SAMPLES -DNO_HEAP_CHECK -DTCMALLOC_SGX -DTCMALLOC_NO_ALIASES -fstack-protector -ffreestanding -nostdinc -fvisibility=hidden -fPIC $(am__append_2) $(am__append_3) $(am__append_5) $(am__append_8)

SYSTEM_ALLOC_CC = ./ShieldStore/gperftools/gperftools-2.5/src/system-alloc.cc
libtcmalloc_minimal_internal_la_SOURCES = ./ShieldStore/gperftools/gperftools-2.5/src/common.cc \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/internal_logging.cc \
                                          $(SYSTEM_ALLOC_CC) \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/central_freelist.cc \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/page_heap.cc \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/sampler.cc \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/span.cc \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/stack_trace_table.cc \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/static_vars.cc \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/symbolize.cc \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/thread_cache.cc \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/malloc_hook.cc \
                                          ./ShieldStore/gperftools/gperftools-2.5/src/maybe_threads.cc \
 					  ./ShieldStore/gperftools/gperftools-2.5/src/malloc_extension.cc \
					  ./ShieldStore/gperftools/gperftools-2.5/src/tcmalloc.cc \

TCMALLOC_Objects := $(libtcmalloc_minimal_internal_la_SOURCES:.cc=.o) ShieldStore/gperftools/gperftools-2.5/src/base/spinlock.o ShieldStore/gperftools/gperftools-2.5/src/base/sgx_utils.o
# TCMALLOC




CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
        Enclave_C_Flags += -fstack-protector
else
        Enclave_C_Flags += -fstack-protector-strong
endif
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

Enclave_Cpp_Files := $(wildcard *.cpp) $(wildcard MerkleTree/*.cpp) $(wildcard KeyGen/*.cpp) $(wildcard ShieldStore/*.cpp)
ENCLAVE_CPP_OBJECTS := $(Enclave_Cpp_Files:.cpp=.o)

.PHONY = all clean target

target = $(SIGNED_ENCLAVE_NAME)

all: 
	@make target

clean:
	@rm -f  $(ENCLAVE_NAME) $(SIGNED_ENCLAVE_NAME) *.o *_t.c *_t.h *_u.c *_u.h MerkleTree/*.o KeyGen/*.o ShieldStore/*.o

$(ENCLAVE_NAME):EnclaveResponder_t.o $(ENCLAVE_CPP_OBJECTS) $(TCMALLOC_Objects)
	@$(CXX) -g $(TCMALLOC_CFlags) $^ -o $@ $(ENCLAVE_LINK_FLAGS)
	@echo "LINK => $@"



############# TCMALLOC OBJECTES ######################


#For TCMALLOC
ShieldStore/gperftools/gperftools-2.5/src/base/sgx_utils.o: ShieldStore/gperftools/gperftools-2.5/src/base/sgx_utils.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/base/spinlock.o: ShieldStore/gperftools/gperftools-2.5/src/base/spinlock.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/maybe_threads.o: ShieldStore/gperftools/gperftools-2.5/src/maybe_threads.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"


ShieldStore/gperftools/gperftools-2.5/src/common.o: ShieldStore/gperftools/gperftools-2.5/src/common.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/internal_logging.o: ShieldStore/gperftools/gperftools-2.5/src/internal_logging.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@ 
	@echo "CXX  <= $<"

#OCALL is needed in system-alloc.cc
ShieldStore/gperftools/gperftools-2.5/src/system-alloc.o: ShieldStore/gperftools/gperftools-2.5/src/system-alloc.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(Enclave_Cpp_Flags) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/central_freelist.o: ShieldStore/gperftools/gperftools-2.5/src/central_freelist.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/page_heap.o: ShieldStore/gperftools/gperftools-2.5/src/page_heap.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/sampler.o: ShieldStore/gperftools/gperftools-2.5/src/sampler.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/span.o: ShieldStore/gperftools/gperftools-2.5/src/span.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/stack_trace_table.o: ShieldStore/gperftools/gperftools-2.5/src/stack_trace_table.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/static_vars.o: ShieldStore/gperftools/gperftools-2.5/src/static_vars.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) -fpermissive $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/symbolize.o: ShieldStore/gperftools/gperftools-2.5/src/symbolize.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/thread_cache.o: ShieldStore/gperftools/gperftools-2.5/src/thread_cache.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/malloc_hook.o: ShieldStore/gperftools/gperftools-2.5/src/malloc_hook.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/malloc_extension.o: ShieldStore/gperftools/gperftools-2.5/src/malloc_extension.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

ShieldStore/gperftools/gperftools-2.5/src/tcmalloc.o: ShieldStore/gperftools/gperftools-2.5/src/tcmalloc.cc
	@$(CXX) $(SGX_COMMON_CFLAGS) $(TCMALLOC_CFlags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <= $<"

#########################################################


######## Enclave Objects ########

EnclaveResponder_t.h: $(SGX_EDGER8R) EnclaveResponder.edl
	@$(SGX_EDGER8R) --trusted EnclaveResponder.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

EnclaveResponder_t.c: EnclaveResponder_t.h

EnclaveResponder_t.o: EnclaveResponder_t.c
	@$(CC) -g $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

%.o: %.cpp EnclaveResponder_t.h
	@$(CXX) -g $(SGX_COMMON_CXXFLAGS) $(TCMALLOC_CFlags) $(Enclave_Cpp_Flags)  $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX  <=  $<"

# DCAP DH compilation rule
tdcap_dh.o: tdcap_dh.cpp EnclaveResponder_t.h
	@$(CXX) -g $(SGX_COMMON_CXXFLAGS) $(TCMALLOC_CFlags) $(Enclave_Cpp_Flags) $(TCMALLOC_Include_Paths) -c $< -o $@
	@echo "CXX (DCAP) <= $<"

