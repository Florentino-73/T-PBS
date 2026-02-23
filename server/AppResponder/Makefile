include ../buildenv.mk

TARGET = appserver 
BIN_DIR = ../bin

RM = rm -f

ifneq ($(SGX_MODE), HW)
	URTS_LIB_NAME := sgx_urts_sim
	UAE_SERVICE_LIB := sgx_uae_service_sim
else
	URTS_LIB_NAME := sgx_urts
	UAE_SERVICE_LIB := sgx_uae_service
endif

INC:=-I$(SGX_SDK)/include -I../Include  -I/usr/local/include
# LIB := -l$(URTS_LIB_NAME) -l$(UAE_SERVICE_LIB) -L$(SGX_SDK)/lib64 -lpthread -lsqlite3 -lssl -lcrypto -lsgx_uprotected_fs
LIB :=   -l$(UAE_SERVICE_LIB) -L$(SGX_SDK)/lib64 \
		-l$(URTS_LIB_NAME) -lpthread -lssl -lcrypto -lsgx_uprotected_fs -lglog

ifneq ($(SGX_MODE), SIM)
LIB += -lsgx_dcap_ql -lsgx_quote_ex -lsgx_dcap_quoteverify
endif 


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
SRC_CPP += $(wildcard MerkleTree/*.cpp)

SRC_C= $(wildcard ../util/*.c)

SRC_OBJ += $(SRC_CPP:.cpp=.o)
SRC_OBJ += $(SRC_C:.c=.o)


.PHONY = all clean

all: $(BIN_DIR)/$(TARGET)

SGX_COMMON_CFLAGS := -I$(SGX_SDK)/include

spinlock.o: spinlock.c
	@$(CC) -g $(SGX_COMMON_CFLAGS) $(App_Compile_CFlags) -c $< -o $@
	@echo "CC   <=  $<"

App.o: App.cpp
	@$(CXX)  -g $(CXXFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

Thread.o: Thread.cpp
	@$(CXX)  -g $(CXXFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

CPTask.o: CPTask.cpp
	@$(CXX) -g  $(CXXFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

CPServer.o: CPServer.cpp
	@$(CXX)  -g $(CXXFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

UntrustedEnclaveMessageExchange.o: UntrustedEnclaveMessageExchange.cpp
	@$(CXX) -g  $(CXXFLAGS) -c $< -o $@
	@echo "CXX  <=  $<"

EnclaveResponder_u.o: EnclaveResponder_u.c
	@$(CC) -g  $(CFLAGS) -I../Include -c $< -o $@
	@echo "CC  <=  $<"

EnclaveResponder_u.c: $(SGX_EDGER8R) ../EnclaveResponder/EnclaveResponder.edl
	@$(SGX_EDGER8R) --untrusted ../EnclaveResponder/EnclaveResponder.edl --search-path $(SGX_SDK)/include

$(BIN_DIR)/$(TARGET): EnclaveResponder_u.o spinlock.o UntrustedEnclaveMessageExchange.o $(SRC_OBJ) | $(BIN_DIR)
	@$(CXX) -g $^ $(SGX_COMMON_CFLAGS) $(CXXFLAGS) -o $@
	@echo "LINK =>  $@"

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

clean:
	@$(RM) $(BIN_DIR)/$(TARGET) *.o *_u.c *_u.h
	rm -f MerkleTree/*.o 
