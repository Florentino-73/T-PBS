include ../buildenv.mk

# TARGET = appinitiator 
TARGET = apprequester
BIN_DIR = ../bin

RM = rm -f

ifneq ($(SGX_MODE), HW)
	URTS_LIB_NAME := sgx_urts_sim
	UAE_SERVICE_LIB := sgx_uae_service_sim
else
	URTS_LIB_NAME := sgx_urts
	UAE_SERVICE_LIB := sgx_uae_service
endif

INC:=-I$(SGX_SDK)/include -I../Include -I../EnclaveInitiator -I/usr/local/include
LIB := -l$(URTS_LIB_NAME) -l$(UAE_SERVICE_LIB) -L$(SGX_SDK)/lib64 -lpthread -L/opt/openssl/1.1.1q/include -lssl -lcrypto -lsgx_uprotected_fs -lglog -lsgx_dcap_ql -lsgx_dcap_quoteverify
CXXFLAGS += $(INC) $(LIB)
CFLAGS += $(INC) $(LIB)

ifeq ($(SGX_DEBUG), 1)
        CXXFLAGS += -DDEBUG -UNDEBUG -UEDEBUG
        CFLAGS += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        CXXFLAGS += -DEDEBUG -DNDEBUG -UDEBUG
        CFLAGS += -DEDEBUG -DNDEBUG -UDEBUG
else
        CXXFLAGS += -DNDEBUG -UEDEBUG -UDEBUG
        CFLAGS += -DNDEBUG -UEDEBUG -UDEBUG
endif

SRC_CPP=$(wildcard *.cpp)
SRC_CPP+= $(wildcard ../util/*.cpp)
SRC_C= $(wildcard ../util/*.c)
SRC_C+= EnclaveInitiator_u.c
SRC_C+= EnclaveExecutor_u.c

SRC_OBJ += $(SRC_CPP:.cpp=.o)
SRC_OBJ += $(SRC_C:.c=.o)
# SRC_OBJ += ../EnclaveInitiator/Utility_E1.o
SRC_OBJ += Utility_E1_u.o


.PHONY = all clean

all: $(BIN_DIR)/$(TARGET)

debug_print:
	@echo "SRC_OBJ = $(SRC_OBJ)"

$(BIN_DIR)/$(TARGET): $(SRC_OBJ) | $(BIN_DIR)
	@$(CXX) $^ -o $@ $(CXXFLAGS)
	@echo "LINK =>  $@"

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

%.o: %.cpp EnclaveInitiator_u.h EnclaveExecutor_u.h
	@$(CXX) -g $(CXXFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

SGX_COMMON_CFLAGS := -I$(SGX_SDK)/include

EnclaveExecutor_u.o: EnclaveExecutor_u.c
	@$(CC) -g  $(CFLAGS) -I../Include -c $< -o $@
	@echo "CC  <=  $<"

EnclaveExecutor_u.h: $(SGX_EDGER8R) ../EnclaveExecutor/EnclaveExecutor.edl
	@$(SGX_EDGER8R) --untrusted ../EnclaveExecutor/EnclaveExecutor.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

EnclaveExecutor_u.c: EnclaveExecutor_u.h

GWAS.o: GWAS.cpp EnclaveExecutor_u.h
	@$(CXX) -g  $(CXXFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

EnclaveInitiator_u.h: $(SGX_EDGER8R) ../EnclaveInitiator/EnclaveInitiator.edl
	@$(SGX_EDGER8R) --untrusted ../EnclaveInitiator/EnclaveInitiator.edl --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

EnclaveInitiator_u.c: EnclaveInitiator_u.h

EnclaveInitiator_u.o: EnclaveInitiator_u.c
	@$(CC) -g $(CFLAGS) -I../Include -c $< -o $@
	@echo "CC   <=  $<"

../EnclaveInitiator/Utility_E1.o: ../EnclaveInitiator/Utility_E1.cpp ../EnclaveInitiator/EnclaveInitiator_t.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

../EnclaveInitiator/EnclaveInitiator_t.h:
	cd ../EnclaveInitiator && $(MAKE) EnclaveInitiator_t.h

clean:
	@$(RM) $(BIN_DIR)/$(TARGET) *.o *_u.c *_u.h

Utility_E1_u.o: ../EnclaveInitiator/Utility_E1.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@
