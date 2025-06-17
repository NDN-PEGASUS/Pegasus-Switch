ifndef SDE_INSTALL
$(error SDE_INSTALL is not set)
endif
CURDIR := $(shell pwd)
P4_PROG = pclndnrouter

CLI_LIB = bfshell_plugin_pclndn.so
PCL_LIB = libpclndn.so

ARCH = $(arch)
PROFILE := test
DEBUGLEVEL = 1
CXXFLAGS += -D$(sde_version) -D$(asic)
ifeq ($(profile), debug)
  CXXFLAGS += -DDEBUGLEVEL=$(DEBUGLEVEL)
  CXXFLAGS += -DPCLNDN_DEBUG
endif

C_SOURCES = src/pcl_ndn_cmd.c
CPP_SOURCES = src/pcl_ndn_cp.cpp src/pcl_ndn_lib.cpp
CLI_SOURCES = src/pcl_ndn_cli.c
MAIN_SOURCES = src/pcl_ndn_switch.cpp

CC = gcc

CFLAGS  = -DSDE_INSTALL=\"$(SDE_INSTALL)\" -D$(sde_version) -D$(asic)  \
          -I$(SDE_INSTALL)/include                      \
          -I$(SDE_INSTALL)/include/$(ARCH)/pdfixed

ifeq ($(sde_version), SDE_9XX_OLD)
BF_LIBS  = -lbf_switchd_lib        \
           -lpi                    \
           -lpi_dummy              \
           -lpifeproto             \
           -ltofinopdfixed_thrift  \
           -lavago                 \
           -ldriver                \
           -lbfutils               \
           -lbfsys                 \
           -lpython3.4m            \
           -lpclndn
else
BF_LIBS  = -lbf_switch             \
           -lpi                    \
           -lpi_dummy              \
           -lpifeproto             \
           -lavago                 \
           -ldriver                \
           -lbfutils               \
           -ltarget_sys            \
           -lpclndn
endif

LDFLAGS  = -Wl,-rpath,$(SDE_INSTALL)/lib
LDLIBS   = -L$(SDE_INSTALL)/lib -L$(SDE_INSTALL)/lib/$(ARCH)pd/$(P4_PROG) -L$(CURDIR)
LDLIBS  += -Wl,--start-group $(BF_LIBS) -Wl,--end-group
LDLIBS  += -lm -pthread -lpcap -lstdc++ -ldl -levent -lthrift

all: $(CLI_LIB) $(PCL_LIB) $(P4_PROG) 

$(PCL_LIB):
	$(CC) -shared -fPIC $(CFLAGS) $(CXXFLAGS) $(C_SOURCES) $(CPP_SOURCES) -o $(PCL_LIB)
	@echo ' Successfully CLI lib building.'

$(P4_PROG): 
	$(CC) $(CFLAGS) $(CXXFLAGS) $(MAIN_SOURCES) -o $(P4_PROG) $(LDLIBS) $(LDFLAGS)
	@echo ' Successfully control plane building.'

$(CLI_LIB):
	$(CC) -shared -fPIC $(CFLAGS) $(CLI_SOURCES) -o $(CLI_LIB)
	@echo ' Successfully CLI lib building.'

clean:
	rm $(P4_PROG) $(CLI_LIB) $(PCL_LIB)
