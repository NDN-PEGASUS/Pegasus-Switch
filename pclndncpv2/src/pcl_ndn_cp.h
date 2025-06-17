/***************************************************************
 * Name:      pcl_ndn_cp.h
 * Purpose:   Control plane related processing statement
 **************************************************************/
#ifndef __PCL_NDN_CP_H__
#define __PCL_NDN_CP_H__
#include <bf_rt/bf_rt_info.hpp>
#include <bf_rt/bf_rt_init.hpp>
#include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_table_key.hpp>
#include <bf_rt/bf_rt_table_data.hpp>
#include <bf_rt/bf_rt_table_operations.hpp>
#include <bf_rt/bf_rt_table.hpp>
#include <bfutils/dynamic_hash/bfn_hash_algorithm.h>
#include <getopt.h>
#include<sys/time.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include<vector>
#include <string>
#include <arpa/inet.h>
extern "C"
{
#include <bf_pm/bf_pm_intf.h>
#include <pkt_mgr/pkt_mgr_intf.h>
#include <bf_switchd/bf_switchd.h>
#ifdef SDE_9XX_OLD
#include <bfutils/clish/shell.h>
#else
#include <target-utils/clish/shell.h>
#endif
}
#include "pcl_ndn_cmd.h"

using namespace std;

#define THRIFT_PORT_NUM 7777
#define ALL_PIPES 0xffff
#define PCL_NDN_PORT_CFG_FILE "port.cfg"
#define PCL_NDN_FIB_TBL_FILE "fibtbl.txt"
#define PCL_NDN_PATH_SEPRATOR "/"
#define PCL_NDN_CHAR_SEPRATOR '/'
#define PCL_NDN_CHAR_SPACE " "
#define PCL_NDN_LINE_BUF_LEN 256
#define PCL_NDN_DEFAULT_PORT_CHNL 0
#define PCL_NDN_MAX_PORT_ID 16
#define PCL_NDN_MAX_NAME_LABLE 4
#define PCL_NDN_NAME_BUF_LEN 64
#define PCL_NDN_NAME_LEN_PER_LABLE 15
#define PCL_NDN_BOOL_STRIG(isvalid) ((isvalid) ? "True" : "False")
#define PCL_NDN_TABLE_DATA_SIZE_UINT64 64
#define PCL_NDN_MAX_TABLE_TYPE 33
#define PCLNDN_IF_SUPPORT_USAGE(tableType) (((tableType) != bfrt::BfRtTable::TableType::COUNTER) && ((tableType) != bfrt::BfRtTable::TableType::METER) && ((tableType) != bfrt::BfRtTable::TableType::REGISTER))
#define PCL_NDN_NAME_HASH_INDEX_MASK 0x3FFFF
#define PCL_NDN_MAX_DATA_BYTE 64
#define PCL_SWITCHD_MAX_AGENTS 5
#define PCL_NDN_GET_FROM_HW  bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_HW
#define PCL_MAC_ADDR_LEN 6
#define PCL_MAC_PORT_NUM 128
#define PCL_MAX_PORT_BITMAP_BITS 8
#define PCL_MAX_GROUP_BITS 262143
#define PCL_MAX_PORT_AREA_NUM 8
#define PCL_PORT_LANES_DEFAULT 4
#define PCL_MAX_SERVER_NUM 128
#define PCL_MAX_DEFAULT_SERVER 1

typedef enum {
    PCL_NDN_INIT_WITH_CFG_FILE = 0, /* Create ports according to the configuration file, etc. */
    PCL_NDN_INIT_WITH_DEFAULT,      /* Configure all ports by default */
    PCL_NDN_INIT_BUT
} PclNdnInitType;
typedef enum {
    PCL_NDN_NAME_LABLE_INDEX_1 = 0,
    PCL_NDN_NAME_LABLE_INDEX_2,
    PCL_NDN_NAME_LABLE_INDEX_3,
    PCL_NDN_NAME_LABLE_INDEX_4,
    PCL_NDN_NAME_LABLE_BUT
} PclNdnNameLableIndex;

typedef enum {
    PCL_NDN_ENTRY_ADD_ONLY = 0,
    PCL_NDN_ENTRY_ADD_MOD,
    PCL_NDN_ENTRY_DEL,
    PCL_NDN_ENTRY_SHOW,
    PCL_NDN_ENTRY_OP_BUT
} PclNdnEntryOpType;

typedef enum {
    PCL_NDN_FIB_SHOW_ALL = 0,
    PCL_NDN_FIB_SHOW_NDN_NAME,
    PCL_NDN_FIB_SHOW_TABLE,
    PCL_NDN_FIB_SHOW_BUT
} PclNdnFibShowType;
typedef enum {
    PCL_NDN_PORT_BITMAP_SHOW_ALL = 0,
    PCL_NDN_PORT_BITMAP_SHOW_PORT,
    PCL_NDN_PORT_BITMAP_SHOW_BUT
} PclNdnPortBitmapShowType;

typedef enum {
    PCL_NDN_PRE_SHOW_ALL = 0,
    PCL_NDN_PRE_SHOW_KEY,
    PCL_NDN_PRE_SHOW_BUT
} PclNdnPreTableShowType;

typedef enum {
    PCL_NDN_TABLE_FIELD_KEY = 0,
    PCL_NDN_TABLE_FIELD_DATA,
    PCL_NDN_TABLE_FIELD_BUT
} PclNdnTableFieldType;

typedef enum {
    PCL_NDN_PIT_SHOW_ALL = 0,
    PCL_NDN_PIT_SHOW_REG1,
    PCL_NDN_PIT_SHOW_REG2,
    PCL_NDN_PIT_SHOW_BUT
} PclNdnPitTableShowType;

typedef enum {
    PCL_NDN_PIT_TABLE_ALL = 0,
    PCL_NDN_PIT_TABLE_FINGER,
    PCL_NDN_PIT_TABLE_PORT,
    PCL_NDN_PIT_TABLE_BUT
} PclNdnPitTableType;

typedef enum {
    PCLNDN_DATA_INT_ARR = 0, /* corresponds to bfrt::DataType::INT_ARR */
    PCLNDN_DATA_BOOL_ARR, /* corresponds to bfrt::DataType::BOOL_ARR */
    PCLNDN_DATA_UINT64, /* corresponds to bfrt::DataType::UINT64 */
    PCLNDN_DATA_BYTE_STREAM, /* corresponds to bfrt::DataType::BYTE_STREAM */
    PCLNDN_DATA_FLOAT, /* corresponds to bfrt::DataType::FLOAT */
    PCLNDN_DATA_CONTAINER, /* corresponds to bfrt::DataType::CONTAINER */
    PCLNDN_DATA_STRING, /* corresponds to bfrt::DataType::STRING */
    PCLNDN_DATA_BOOL, /* corresponds to bfrt::DataType::BOOL */
    PCLNDN_DATA_BUT
} PclNdnTableDataType;
typedef enum {
    PCLNDN_KEY_INVALID = 0, /* corresponds to bfrt::KeyFieldType::INVALID */
    PCLNDN_KEY_EXACT, /* corresponds to bfrt::KeyFieldType::EXACT */
    PCLNDN_KEY_TERNARY, /* corresponds to bfrt::KeyFieldType::TERNARY */
    PCLNDN_KEY_RANGE, /* corresponds to bfrt::KeyFieldType::RANGE */
    PCLNDN_KEY_LPM, /* corresponds to bfrt::KeyFieldType::LPM */
    PCLNDN_KEY_BUT
} PclNdnTableKeyType;

typedef enum {
    PCL_NDN_ENTRY_NORMAL = 0,
    PCL_NDN_ENTRY_DEFAULT,
    PCL_NDN_ENTRY_BUT
} PclNdnEntryType;

#pragma pack(1)
typedef struct {
  UINT8 ethdstAddr[6];
  UINT8 ethsrcAddr[6];
  UINT16 ethtype;
} PclNdnMacLayerHeader;

typedef struct {
  UINT8 tlv_type;
  UINT8 tlv_length;
  UINT16 outport;
} PclNdnOutFromCpuInfo;
#pragma pack()

typedef struct {
    VOID *clishContext;
    bfrt::BfRtTable* tcamTable;
    bfrt::BfRtTableKey *tableKey;
    bfrt::BfRtTableData *tableData;
    UINT32 tableId;
    UINT32 tableType;
    UINT32 tableSize;
    UINT32 usedCount;
    UINT32 index;
    UINT32 keyType;
    UINT32 dataType;
    size_t fieldSize;
    bf_rt_id_t fieldId;
    UINT8 showType;
    UINT8 hideAttr;
    UINT8 rsvd[2];
    UINT32 leftEntry;
    UINT32 entryType;
} PclNdnTableFiledShowInfo;

typedef struct {
    UINT32 keyType;
    UINT32 dataType;
    size_t fieldSize;
    UINT32 ifPtr;
    string fieldName;
} PclNdnTableKeyInfo;
typedef struct {
    UINT32 dataType;
    size_t fieldSize;
    UINT32 ifPtr;
    UINT32 ifMandatory;
    UINT32 ifReadOnly;
    string fieldName;
} PclNdnTableDataInfo;

typedef struct {
    string dataTypeName;
    string keyTypeName;
} PclNdnTableFieldNameInfo;

typedef struct {
    VOID *clishContext;     /* command line context */
    UINT32 portId;          /* result of fingerprint hash */
    UINT32 portDevId;       /* devId corresponds to outport */
    UINT32 showType;        /* show type */
    UINT32 rsvd;            /* reserve for alignment */
} PclNdnPortBitmapInfo;

typedef struct {
    void *clishContext;     /* command line context */
    UINT32 hashResult;      /* result of fingerprint hash */
    UINT32 portDevId;       /* devId corresponds to outport */
    UINT32 labelNum;        /* number of name components */
    UINT32 hashLength;      /* length of data involved in hash */
    UINT32 showType;        /* show type */
    UINT32 rsvd;            /* reserve for alignment */
    UINT32 lableLength[PCL_NDN_MAX_NAME_LABLE];
    char lableNames[PCL_NDN_MAX_NAME_LABLE][PCL_NDN_NAME_LEN_PER_LABLE];
} PclNdnNameInfo;

typedef enum {
    PCCT_CMD_ARG_SKIP = 0,      /* Parameters to be ignored */
    PCCT_CMD_ARG_NAME,          /* NDN name */
    PCCT_CMD_ARG_INDEX,         /* index */
    PCCT_CMD_ARG_BUT
} PclPcctCmdArgsType;

typedef enum {
    PCCT_SUBKEY_NONE = 0,       /* without key */
    PCCT_SUBKEY_NAME,           /* NDN name */
    PCCT_SUBKEY_INDEX,          /* index */
    PCCT_SUBKEY_BUT
} PclPcctSubKeyType;

typedef struct {
    VOID *clishContext;     /* command line context */
    UINT8 subCmd;           /* subcommand */
    UINT8 subkey;           /* show subtype */
    UINT8 tableType;        /* show table type */
    UINT8 regType;          /* show reg type */
    UINT32 index;           /* index */
    bfrt::BfRtTable *g_regTable;
    bfrt::BfRtTableKey *g_regKey;
    bfrt::BfRtTableData *g_regData;
    bf_rt_id_t keyId;
    bf_rt_id_t valueId;
    string ndnName;
} PclNdnPitInfo;

typedef struct {
    UINT8 initType;         /* initial type, corresponds to PclNdnInitType */
    UINT8 fibSupport;       /* is FIB support required? */
    UINT8 serverNumber;
    UINT8 maxArea;
    UINT32 rsvd1;
} PclNdnMngInfo;

typedef struct {
    UINT32 tableId;
    UINT32 tableSize;
    UINT32 tableType;
    UINT32 usedCount;
} PclNdnTableInfo;

typedef UINT32 (*PCLNDNCMDPROC)(const PclNdnCmdInfo *cmdInfo);
typedef struct {
    string cmdName; /* command name */
    PCLNDNCMDPROC cmdProc; /* command process function */
} PclNdnCmdProcMngInfo;

typedef enum {
    CMD_SUB_SKIP = 0,  /* skip subcommand */
    CMD_SUB_CONFIG,    /* config subcommand */
    CMD_SUB_SHOW,      /* show subcommand */
    CMD_SUB_BUT
} PclCmdSubType;

typedef enum {
    CMD_CONFIG_INVALID = 0,  /* invalid type */
    CMD_CONFIG_ADD,          /* add command */
    CMD_CONFIG_MOD,          /* mod command */
    CMD_CONFIG_DEL,          /* del subcommand */
    CMD_CONFIG_SHOW,         /* show command */
    CMD_CONFIG_BUT
} PclCmdConfigType;

typedef enum {
    CMD_SHOW_ALL = 0,      /* Default to show all */
    CMD_SHOW_INDEX,        /* show by index */
    CMD_SHOW_BUT
} PclCmdShowType;

typedef enum {
    MAC_CMD_ARG_SKIP = 0,       /* Parameters to be ignored */
    MAC_CMD_ARG_SERVER,         /* mac address */
    MAC_CMD_ARG_MAC_ADDR,       /* mac address */
    MAC_CMD_ARG_PORTID,         /* outport ID */
    MAC_CMD_ARG_BUT
} PclMacCmdArgsType;
typedef enum {
    MAC_SUBKEY_NONE = 0,        /* without key */
    MAC_SUBKEY_SERVER,          /* server index key */
    MAC_SUBKEY_DMAC,            /* mac address key */
    MAC_SUBKEY_BUT
} PclMacSubKeyType;

typedef struct {
    UINT8 serverIndex; /* server index */
    UINT8 rsvd[5];
    UINT16 outport; /* outport */
    UINT64 dmacAddr; /* dmac address */
} PclMacTransInfo;

typedef struct {
    VOID *clishContext;         /* command line context */
    UINT8 subCmd;               /* subcommand */
    UINT8 subkey;               /* show subtype */
    UINT8 serverIndex;          /* server index */
    UINT8 rsvd1[5];
    UINT16 outport;             /* outport */
    UINT16 rsvd;                /* reserve for alignment */
    UINT32 parseResult;         /* parse result, 0 is OK, others are failure */
    UINT64 dmacAddr;            /* dmac address */
    string dstMacStr;           /* Save a mac address string */
} PclMacTransCmdInfo;

typedef enum {
    BITMAP_CMD_ARG_SKIP = 0,    /* Parameters to be ignored */
    BITMAP_CMD_ARG_PORT_INDEX,  /* port index */
    BITMAP_CMD_ARG_AREAID,      /* group id index */
    BITMAP_CMD_ARG_BUT
} PclBitmapCmdArgsType;
typedef enum {
    BITMAP_SUBKEY_NONE = 0,     /* without key */
    BITMAP_SUBKEY_PORT,         /* with port key */
    BITMAP_SUBKEY_AREA,         /* with group key */
    BITMAP_SUBKEY_BUT
} PclBitmapSubKeyType;

typedef struct {
    VOID *clishContext; /* command line context */
    UINT8 subCmd;       /* subcommand */
    UINT8 subkey;       /* show subtype */
    UINT8 areaId;       /* group index corresponds to bitmap */
    UINT8 rsvd;         /* reserve for alignment */
    UINT32 connId;      /* index corresponds to panel */
    UINT32 chnlId;      /* subindex corresponds to panel */
    UINT32 portDevId;   /* devID corresponds to port */
    UINT32 bitmapId;    /* calculated bitmap value */
    UINT32 parseResult; /* parse result, 0 is OK, others are failure */
} PclBitmapCmdInfo;

typedef struct {
    UINT8  used;        /* is used */
    UINT8  pipeId;      /* pipe ID */
    UINT8  areaId;      /* group ID, groups ports into multicast groups */
    UINT8  rsvd1;       /* reserve for alignment */
    UINT32 connId;      /* index corresponds to panel */
    UINT32 chnlId;      /* subindex corresponds to panel */
    UINT32 portDevId;   /* devID corresponds to port */
    UINT32 bitmapId;    /* calculated bitmap value */
    UINT32 rsvd;        /* reserve for alignment */
} PclPortMngInfo;

typedef enum {
    PORT_CMD_ARG_SKIP = 0,      /* Parameters to be ignored */
    PORT_CMD_ARG_PORTID,        /* port index */
    PORT_CMD_ARG_AREAID,        /* area index */
    PORT_CMD_ARG_BUT
} PclPortCmdArgsType;

typedef enum {
    PORT_SUBKEY_NONE = 0,      /* without key */
    PORT_SUBKEY_PORT,          /* with port key */
    PORT_SUBKEY_AREA,          /* with area key */
    PORT_SUBKEY_BUT
} PclPortSubKeyType;

typedef struct {
    VOID *clishContext; /* command line context */
    UINT8 subCmd;       /* subcommand */
    UINT8 subkey;       /* show subtype */
    UINT8 areaId;       /* group index corresponds to bitmaps */
    UINT8 rsvd;         /* reserve for alignment */
    UINT32 connId;      /* index corresponds to panel */
    UINT32 chnlId;      /* subindex corresponds to panel */
    UINT32 portDevId;   /* devID corresponds to port */
    UINT32 parseResult; /* parse result, 0 is OK, others are failure */
    UINT32 mapKey;      /* indexkey */
} PclPortCmdInfo;


typedef enum {
    GROUP_CMD_ARG_SKIP = 0,     /* Parameters to be ignored */
    GROUP_CMD_ARG_AREA_ID,      /* area index */
    GROUP_CMD_ARG_MASK_ID,      /* MASK index */
    GROUP_CMD_ARG_BUT
} PclGroupCmdArgsType;
typedef enum {
    GROUP_SUBKEY_NONE = 0,      /* without key */
    GROUP_SUBKEY_AREA_ID,      /* area index */
    GROUP_SUBKEY_MASK_ID,      /* MASK index */
    GROUP_SUBKEY_BUT
} PclGroupSubKeyType;

typedef struct {
    UINT8  areaId;      /* area ID */
    UINT8  bitmap;      /* reserve for alignment */
    UINT8  rsvd1[2];    /* reserve for alignment */
    UINT32 bitmask;     /* mask value */
} PclMultiGroupInfo;

typedef struct {
    VOID  *clishContext;    /* command line context */
    UINT8  subCmd;          /* subcommand */
    UINT8  subkey;          /* show subtype */
    UINT8  areaId;          /* area ID */
    UINT8  bitmap;          /* reserve for alignment */
    UINT32 bitmask;         /* calculated bitmap value */
    UINT32 parseResult;     /* parse result, 0 is OK, others are failure */
    UINT32 rsvd;
} PclMultiGroupCmdInfo;

typedef enum {
    SERVER_CMD_ARG_SKIP = 0,        /* Parameters to be ignored */
    SERVER_CMD_ARG_NUMBER,          /* number of servers */
    SERVER_CMD_ARG_BUT
} PclServerCmdArgsType;
typedef enum {
    SERVER_SUBKEY_NONE = 0,         /* without key */
    SERVER_SUBKEY_NUMBER,           /* number of servers */
    SERVER_SUBKEY_BUT
} PclServerSubKeyType;

typedef struct {
    VOID *clishContext; /* command line context */
    UINT8 subCmd;       /* subcommand */
    UINT8 subkey;       /* show subtype */
    UINT8 serverNumber; /* group index corresponds to bitmaps */
    UINT8 rsvd;         /* reserve for alignment */
    UINT32 parseResult; /* parse result, 0 is OK, others are failure */
} PclServerCmdInfo;

void PCLNDN_InitDeviceManager(const char *appPath, UINT32 initType);
void PCLNDN_InitPort();
void PCLNDN_InitPktDriverCallback();
bf_status_t PCLNDN_SetUpBfrt(const char *progname);
void PCLNDN_InitTables();
void PCLNDN_InitTableEntry();
void PCLNDN_LibExitProc();

#endif // __PCL_NDN_CP_H__
