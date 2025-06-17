/***************************************************************
 * Name:      pcl_ndn_cp.cpp
 * Purpose:   control plane related functions
 **************************************************************/
#include "pcl_ndn_cp.h"
#include <math.h>
#include <string.h>
#include <unistd.h>
#include "pcl_ndn_cmd.h"

using namespace std;

PclNdnMngInfo g_pclndnMngInfo = {0};
string g_appWorkPath = "";
map<UINT32, PclPortMngInfo> g_mapPortMngInfo;
map<UINT32, PclMultiGroupInfo> g_mapGroupInfo;
map<UINT8, map<UINT64, PclMacTransInfo> > g_macMacTranInfo;

bfn_hash_algorithm_t g_fingerHashAlgorithm;
UINT8* g_hashMatrix[256];
UINT8  g_hashMatrixData[256][8];

bf_rt_target_t g_dev_target = {0};
const bfrt::BfRtInfo *g_bfrtInfo = nullptr;
std::shared_ptr<bfrt::BfRtSession> g_session;

/* Port-bitmap table operations */
const bfrt::BfRtTable *g_portBitmapTable = nullptr;
std::unique_ptr<bfrt::BfRtTableKey> g_portBitmapTableKey;
std::unique_ptr<bfrt::BfRtTableData> g_portBitmapTableData;
bf_rt_id_t g_keyInPort = 0;
bf_rt_id_t g_portBitmapActionId = 0;
bf_rt_id_t g_portBitmapValue = 0;

/* Multicast group Node table operations */
const bfrt::BfRtTable *g_preNodeTable = nullptr;
std::unique_ptr<bfrt::BfRtTableKey> g_preNodeTableKey;
std::unique_ptr<bfrt::BfRtTableData> g_preNodeTableData;
bf_rt_id_t g_preNodeKeyNodeId = 0;
bf_rt_id_t g_preNodeActionId = 0;
bf_rt_id_t g_preNodeGroupIdValue = 0;
bf_rt_id_t g_preNodePortListValue = 0;

/* Multicast group ID table operations */
const bfrt::BfRtTable *g_preMgidTable = nullptr;
std::unique_ptr<bfrt::BfRtTableKey> g_preMgidTableKey;
std::unique_ptr<bfrt::BfRtTableData> g_preMgidTableData;
bf_rt_id_t g_preMgidKeyGroupId = 0;
bf_rt_id_t g_preMgidActionId = 0;
bf_rt_id_t g_preMgidNodeIdValue = 0;
bf_rt_id_t g_preMgidL1Xid = 0;
bf_rt_id_t g_preMgidL1XidValid = 0;
bf_rt_id_t g_preMgidEcmpIds = 0;
bf_rt_id_t g_preMgidEcmpL1xidValid = 0;
bf_rt_id_t g_preMgidEcmpL1xid = 0;

// PIT register groups
const bfrt::BfRtTable *g_pitFinger1Reg = nullptr;
std::unique_ptr<bfrt::BfRtTableKey> g_pitFinger1RegKey;
std::unique_ptr<bfrt::BfRtTableData> g_pitFinger1RegData;
bf_rt_id_t g_pitFinger1Key;
bf_rt_id_t g_pitFinger1Value;

UINT32 g_regKeyMask = 0;

const bfrt::BfRtTable *g_pitFinger2Reg = nullptr;
std::unique_ptr<bfrt::BfRtTableKey> g_pitFinger2RegKey;
std::unique_ptr<bfrt::BfRtTableData> g_pitFinger2RegData;
bf_rt_id_t g_pitFinger2Key;
bf_rt_id_t g_pitFinger2Value;

const bfrt::BfRtTable *g_pitPort1Reg = nullptr;
std::unique_ptr<bfrt::BfRtTableKey> g_pitPort1RegKey;
std::unique_ptr<bfrt::BfRtTableData> g_pitPort1RegData;
bf_rt_id_t g_pitPort1Key;
bf_rt_id_t g_pitPort1Value;

const bfrt::BfRtTable *g_pitPort2Reg = nullptr;
std::unique_ptr<bfrt::BfRtTableKey> g_pitPort2RegKey;
std::unique_ptr<bfrt::BfRtTableData> g_pitPort2RegData;
bf_rt_id_t g_pitPort2Key;
bf_rt_id_t g_pitPort2Value;

/* Operation related to the outport table sent to backend servers based on MAC */
const bfrt::BfRtTable *g_toServerTable = nullptr;
std::unique_ptr<bfrt::BfRtTableKey> g_toServerTableKey;
std::unique_ptr<bfrt::BfRtTableData> g_toServerTableData;
bf_rt_id_t g_toServerKey;
bf_rt_id_t g_macTblKeySerIndex;
bf_rt_id_t g_toServerActionId = 0;
bf_rt_id_t g_toServerValue = 0;

/* register for server number */
const bfrt::BfRtTable *g_serverNumReg = nullptr;
std::unique_ptr<bfrt::BfRtTableKey> g_serverNumRegKey;
std::unique_ptr<bfrt::BfRtTableData> g_serverNumRegData;
bf_rt_id_t g_serverNumKey;
bf_rt_id_t g_serverNumValue;

/*********************************************************************
 * Function: Initialize hash calculation
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitFibHashAlgorithm()
{
    char *error_message = NULL;
    /* Initialize the hash algorithm */
    initialize_algorithm(&g_fingerHashAlgorithm, CRC_DYN, true, true, CRC_32);
    if (g_fingerHashAlgorithm.crc_matrix == NULL) {
        g_fingerHashAlgorithm.crc_matrix = g_hashMatrix;
        for (UINT32 index = 0; index < 256; index++) {
            g_fingerHashAlgorithm.crc_matrix[index] = (UINT8*)g_hashMatrixData[index];
            memset(g_fingerHashAlgorithm.crc_matrix[index], 0, (sizeof(UINT8) * 8));
        }
    } else {
        for (UINT32 index = 0; index < 256; index++) {
            memset(g_fingerHashAlgorithm.crc_matrix[index], 0, (sizeof(UINT8) * 8));
        }
    }
    initialize_crc_matrix(&g_fingerHashAlgorithm);
    if (verify_algorithm(&g_fingerHashAlgorithm, &error_message) != true) {
        printf("Error: hash parameter is error for %s\n", error_message);
        return;
    }
}

/*********************************************************************
 * Function: Hash computing resources release
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ReleaseFibHashAlgorithm()
{
#if 0
    if (g_fingerHashAlgorithm.crc_matrix == NULL) {
        return;
    }
    /* Release resources */
    for (UINT32 index = 0; index < 256; index++) {
        if (g_fingerHashAlgorithm.crc_matrix[index] != NULL) {
            free(g_fingerHashAlgorithm.crc_matrix[index]);
            g_fingerHashAlgorithm.crc_matrix[index] = NULL;
        }
    }
    free(g_fingerHashAlgorithm.crc_matrix);
    g_fingerHashAlgorithm.crc_matrix = NULL;
#endif
}

/*********************************************************************
 * Function: Device information related initialization
 * Input: appPath: Control plane app running path
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitDeviceManager(const char *appPath, UINT32 initType)
{
    g_dev_target.dev_id = 0;
    g_dev_target.pipe_id = ALL_PIPES;
    g_appWorkPath = appPath;
    g_pclndnMngInfo.initType = initType;
    memset(&g_fingerHashAlgorithm, 0, sizeof(bfn_hash_algorithm_t));
    g_mapPortMngInfo.clear();
    g_macMacTranInfo.clear();
}
/*********************************************************************
 * Function: Exit related processing
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_LibExitProc()
{
    PCLNDN_ReleaseFibHashAlgorithm();
}
/*********************************************************************
 * Function: Initialize and add all ports
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_AddAllPort()
{
    UINT32 portId = 1;
    /* Add all ports as 100G */
    bf_pm_port_add_all(g_dev_target.dev_id, BF_SPEED_100G, BF_FEC_TYP_NONE);
}
/*********************************************************************
 * Function:    Initialize and add the corresponding port 
 *              according to the configuration file
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_AddPortWithLine(char *lineInfo)
{
}

/*********************************************************************
 * Function:    Initialize and add the corresponding port 
 *              according to the configuration file
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_AddPortWithCfgFile()
{
    string cfgFile = g_appWorkPath + PCL_NDN_PATH_SEPRATOR + PCL_NDN_PORT_CFG_FILE;
    char buffer[PCL_NDN_LINE_BUF_LEN] = {0};
    FILE *fileHandle = fopen(cfgFile.c_str(), "r");
    if (fileHandle == NULL) {
        return;
    }

    while (fgets(buffer, (PCL_NDN_LINE_BUF_LEN - 1), fileHandle) != NULL) {
        PCLNDN_AddPortWithLine(buffer);
    }
    fclose(fileHandle);
}

/*********************************************************************
 * Function: Add a panel port to the management node
 * Input: frontHandle: Panel port information
 * Output: None
 * Return: None
 * *******************************************************************/
bf_status_t PCLNDN_AddPortMngInfo(bf_pal_front_port_handle_t *frontHandle)
{
    bf_status_t status = BF_SUCCESS;
    bf_dev_port_t portDevId = 0;
    bool isInternalPort = false;
    UINT32 mapKey = (frontHandle->conn_id << UINT16_BITS) + frontHandle->chnl_id;

    bf_pm_is_port_internal(g_dev_target.dev_id, frontHandle, &isInternalPort);
    if (!isInternalPort) {
#ifdef SDE_9XX_OLD
        status = bf_pm_port_front_panel_port_to_dev_port_get(g_dev_target.dev_id, frontHandle, &portDevId);
#else
        status = bf_pm_port_front_panel_port_to_dev_port_get(frontHandle, &g_dev_target.dev_id, &portDevId);
#endif
        if (status != BF_SUCCESS) {
            printf("Error: get port:%u/%u devid fail\n", frontHandle->conn_id, frontHandle->chnl_id);
            return PCL_ERROR;
        }
        PclPortMngInfo newPort = {0};
        newPort.used   = PCL_FALSE;
        newPort.pipeId = DEV_PORT_TO_PIPE(portDevId);
        newPort.areaId = (frontHandle->conn_id - 1) / PCL_MAX_PORT_AREA_NUM;
        newPort.connId = frontHandle->conn_id;
        newPort.chnlId = frontHandle->chnl_id;
        newPort.portDevId = (UINT32)portDevId;
        g_mapPortMngInfo[mapKey] = newPort;
        if (newPort.areaId > g_pclndnMngInfo.maxArea) {
            g_pclndnMngInfo.maxArea = newPort.areaId;
        }
    }
    return BF_SUCCESS;
}

/*********************************************************************
 * Function: Add devid of all created ports
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitPortDevId()
{
    bf_status_t status = BF_SUCCESS;
    bf_pal_front_port_handle_t frontHandle;
    bf_pal_front_port_handle_t* current = &frontHandle;
    bf_pal_front_port_handle_t newHandle;
    bf_pal_front_port_handle_t *nextHandle = &newHandle;

    status = bf_pm_port_front_panel_port_get_first(g_dev_target.dev_id, current);
    if (status != BF_SUCCESS) {
        printf("Error: get first front panel port fail, error code: %d\n", status);
        return;
    }
    PCLNDN_AddPortMngInfo(current);
    while (status == BF_SUCCESS) {
        status = bf_pm_port_front_panel_port_get_next(g_dev_target.dev_id, current, nextHandle);
        if (status == BF_OBJECT_NOT_FOUND) {
            break;
        }
        if (status != BF_SUCCESS) {
            printf("Error: get port:%u/%u next devid fail\n", current->conn_id, current->chnl_id);
            break;
        }
        PCLNDN_AddPortMngInfo(nextHandle);
        current = nextHandle;
    }
    printf("Info: all port num %u with %u area.\n", g_mapPortMngInfo.size(), g_pclndnMngInfo.maxArea);
}

/*********************************************************************
 * Function:    Automatically add the corresponding devId 
 *              according to the port ID
 * Input:   conn_id: port ID
 *          clishContext: command line context
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_CheckAndAddPortDev(UINT32 conn_id, VOID *clishContext)
{
    bf_status_t status = 0;
    bf_dev_port_t portDevId = 0;
    bf_pal_front_port_handle_t portHandle;
    bool is_enabled = false;

    portHandle.chnl_id = 0;
    portHandle.conn_id = conn_id;
    
    /* Legality check */
    if (conn_id > PCL_NDN_MAX_PORT_ID || conn_id == 0) {
        return PCL_ERROR;
    }

    /* Only enabled ports are automatically added */
    status = bf_pm_port_is_enabled(g_dev_target.dev_id, &portHandle, &is_enabled);
    if ((status != BF_SUCCESS) || (is_enabled == false)) {
        return PCL_ERROR;
    }
    
#ifdef SDE_9XX_OLD
        status = bf_pm_port_front_panel_port_to_dev_port_get(g_dev_target.dev_id, &portHandle, &portDevId);
#else
        status = bf_pm_port_front_panel_port_to_dev_port_get(&portHandle, &g_dev_target.dev_id, &portDevId);
#endif
    if (status != BF_SUCCESS) {
        return PCL_ERROR;
    }
    if (clishContext == NULL) {
        printf("Info: auto add port devid, port:%u devid:%u\n", portHandle.conn_id, portDevId);
    } else {
        bfshell_printf(clishContext, "Info: auto add port devid, port:%u devid:%u\n", portHandle.conn_id, portDevId);
    }
    return PCL_OK;
}

/*********************************************************************
 * Function: Initialize related ports
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitPort()
{
    PCLNDN_InitPortDevId();
#if 0
    if (g_pclndnMngInfo.initType == PCL_NDN_INIT_WITH_CFG_FILE) {
        PCLNDN_AddPortWithCfgFile();
    } else {
        PCLNDN_AddAllPort();
        PCLNDN_InitPortDevId();
    }
    bf_pm_port_autoneg_set_all(g_dev_target.dev_id, PM_AN_FORCE_DISABLE);
    bf_pm_port_enable_all(g_dev_target.dev_id);
    if (bf_pkt_is_inited(g_dev_target.dev_id)) {
        printf("Info: bf_pkt is initialized\n");
    }
#endif
}

/*********************************************************************
 * Function: Callback function for packet sending completion processing
 * Input: None
 * Output: None
 * Return: 0: Success, Others: Failure
 * *******************************************************************/
static bf_status_t PCLNDN_PktTxDoneNotifCallback(bf_dev_id_t dev_id, bf_pkt_tx_ring_t tx_ring, uint64_t tx_cookie, UINT32 status)
{
    bf_pkt *pkt = (bf_pkt *)(uintptr_t)tx_cookie;
    
    bf_pkt_free(dev_id, pkt);
    return 0;
}

/*********************************************************************
 * Function: Packet receiving processing function
 * Input: None
 * Output: None
 * Return: 0: Success, Others: Failure
 * *******************************************************************/
bf_status_t PCLNDN_RxPacketCallback(bf_dev_id_t dev_id, bf_pkt *pkt, VOID *cookie, bf_pkt_rx_ring_t rx_ring)
{
    (VOID)dev_id;
    (VOID)cookie;
    (VOID)rx_ring;
    PclNdnOutFromCpuInfo fromcpuInfo = {0};
    bf_pkt *txPacket = NULL;
    UINT32 txLength = sizeof(PclNdnOutFromCpuInfo) + pkt->pkt_size;
    UINT8 *dataBuffer = NULL;
    UINT8 *temp = NULL;
    
    printf("Info: Packet received\n");
    if (bf_pkt_alloc(g_dev_target.dev_id, &txPacket, txLength, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
        printf("Error: Failed bf_pkt_alloc\n");
        return 0;
    }
    dataBuffer = (UINT8 *)malloc(txLength);
    if (dataBuffer == NULL) {
        printf("Error: Failed to alloc new memory\n");
        return 0;
    }
    temp = dataBuffer;
    fromcpuInfo.tlv_type = 88;
    fromcpuInfo.tlv_length = 2;
    fromcpuInfo.outport = 132;
    memcpy(temp, pkt->pkt_data, sizeof(PclNdnMacLayerHeader));
    temp += sizeof(PclNdnMacLayerHeader);
    memcpy(temp, &fromcpuInfo, sizeof(PclNdnOutFromCpuInfo));
    temp += sizeof(PclNdnOutFromCpuInfo);
    memcpy(temp, (pkt->pkt_data + sizeof(PclNdnMacLayerHeader)), (pkt->pkt_size - sizeof(PclNdnMacLayerHeader)));
    if (bf_pkt_data_copy(txPacket, dataBuffer, txLength) != 0) {
        printf("Error: Failed data copy\n");
    }

    bf_status_t stat = bf_pkt_tx(g_dev_target.dev_id, txPacket, BF_PKT_TX_RING_0, (VOID*)txPacket);
    if (stat != BF_SUCCESS) {
        printf("Error: Failed to send packet status=%s\n", bf_err_str(stat));
        bf_pkt_free(0, txPacket);
    }
    printf("Info: success send the packet\n");
    free(dataBuffer);
    /* debug print */
#if 0
    for (UINT32 i = 0; i < pkt->pkt_size; i++) {
        printf("%02x ", pkt->pkt_data[i]);
        if ((i != 0) && (i % 32 == 0)) {
            printf("\n");
        }
    }
    printf("\n");
#endif
    bf_pkt_free(g_dev_target.dev_id, pkt);
    return 0;
}

/*********************************************************************
 * Function:    Packet receiving and sending callback function 
 *              registration initialization
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitPktDriverCallback()
{
    UINT32 tx_ring = 0;
    UINT32 rx_ring = 0;
    bf_status_t status = 0;
    int cookie = 0;

    /* register callback for TX complete */
    for (tx_ring = BF_PKT_TX_RING_0; tx_ring < BF_PKT_TX_RING_MAX; tx_ring++) {
        bf_pkt_tx_done_notif_register(g_dev_target.dev_id, PCLNDN_PktTxDoneNotifCallback, (bf_pkt_tx_ring_t)tx_ring);
    }
    /* register callback for RX */
    for (rx_ring = BF_PKT_RX_RING_0; rx_ring < BF_PKT_RX_RING_MAX; rx_ring++) {
        status |= bf_pkt_rx_register(g_dev_target.dev_id, PCLNDN_RxPacketCallback, (bf_pkt_rx_ring_t)rx_ring, (VOID*)&cookie);
    }
    printf("Info: pktdriver callback register done. stat=0x%x\n", status);
}

/*********************************************************************
 * Function: Barefoot runtime information initialization
 * Input: None
 * Output: None
 * Return: 0: Success, Others: Failure
 * *******************************************************************/
bf_status_t PCLNDN_SetUpBfrt(const char *progname)
{
    /* Get devMgr singleton instance */
    auto &devMgr = bfrt::BfRtDevMgr::getInstance();
    // Get bfrtInfo object from dev_id and p4 program name
    auto bf_status = devMgr.bfRtInfoGet(g_dev_target.dev_id, progname, &g_bfrtInfo);
    // Create a session object
    g_session = bfrt::BfRtSession::sessionCreate();
    printf("Info: bfrt Setup! Get bfrt info status:%u\n", bf_status);
    return bf_status;
}

/*********************************************************************
 * Function: Initialize the TCAM table information of the port bitmap
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitPortBitmapTable()
{
    bf_status_t status = 0;
    status = g_bfrtInfo->bfrtTableFromNameGet("SwitchIngress.NdnPortBitmap", &g_portBitmapTable);
    status |= g_portBitmapTable->keyFieldIdGet("ig_md.inPort", &g_keyInPort);
    status |= g_portBitmapTable->actionIdGet("SwitchIngress.SetPortBitmap", &g_portBitmapActionId);
    status |= g_portBitmapTable->dataFieldIdGet("bitmap", g_portBitmapActionId, &g_portBitmapValue);
    status |= g_portBitmapTable->keyAllocate(&g_portBitmapTableKey);
    status |= g_portBitmapTable->dataAllocate(&g_portBitmapTableData);
    printf("Info: port bitmap table init finish as:%u\n", status);
}

/*********************************************************************
 * Function: Initialize the reserved TCAM table info sent by multicast
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitMulticastTable()
{
    bf_status_t status = 0;
    size_t tableSize = 0;
    size_t keySize = 0;
    /* Multicast group Node table operations */
    status = g_bfrtInfo->bfrtTableFromNameGet("$pre.node", &g_preNodeTable);
    status |= g_preNodeTable->keyFieldIdGet("$MULTICAST_NODE_ID", &g_preNodeKeyNodeId);
    status |= g_preNodeTable->dataFieldIdGet("$MULTICAST_RID", &g_preNodeGroupIdValue);
    status |= g_preNodeTable->dataFieldIdGet("$DEV_PORT", &g_preNodePortListValue);
    status |= g_preNodeTable->keyAllocate(&g_preNodeTableKey);
    status |= g_preNodeTable->dataAllocate(&g_preNodeTableData);

#ifdef SDE_9XX_OLD
    g_preNodeTable->tableSizeGet(&tableSize);
#else
    g_preNodeTable->tableSizeGet(*g_session, g_dev_target, &tableSize);
#endif
    g_preNodeTable->keyFieldSizeGet(g_preNodeKeyNodeId, &keySize);
    printf("Info: pre.node table init finish as:%u,size :%u, keySize:%u\n", status, tableSize, keySize);

    /* Multicast group ID table operations */
    status = g_bfrtInfo->bfrtTableFromNameGet("$pre.mgid", &g_preMgidTable);
    status |= g_preMgidTable->keyFieldIdGet("$MGID", &g_preMgidKeyGroupId);
    status |= g_preMgidTable->dataFieldIdGet("$MULTICAST_NODE_ID", &g_preMgidNodeIdValue);
    status |= g_preMgidTable->dataFieldIdGet("$MULTICAST_NODE_L1_XID", &g_preMgidL1Xid);
    status |= g_preMgidTable->dataFieldIdGet("$MULTICAST_NODE_L1_XID_VALID", &g_preMgidL1XidValid);
    status |= g_preMgidTable->dataFieldIdGet("$MULTICAST_ECMP_ID", &g_preMgidEcmpIds);
    status |= g_preMgidTable->dataFieldIdGet("$MULTICAST_ECMP_L1_XID_VALID", &g_preMgidEcmpL1xidValid);
    status |= g_preMgidTable->dataFieldIdGet("$MULTICAST_ECMP_L1_XID", &g_preMgidEcmpL1xid);

    status |= g_preMgidTable->keyAllocate(&g_preMgidTableKey);
    status |= g_preMgidTable->dataAllocate(&g_preMgidTableData);

#ifdef SDE_9XX_OLD
    g_preMgidTable->tableSizeGet(&tableSize);
#else
    g_preMgidTable->tableSizeGet(*g_session, g_dev_target, &tableSize);
#endif
    printf("Info: pre.mgid table init finish as:%u,size :%u\n", status, tableSize);
}

/*********************************************************************
 * Function: MAC forwarding outport table info initialization
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitToServerTable()
{
    bf_status_t status = 0;

    status = g_bfrtInfo->bfrtTableFromNameGet("SwitchIngress.NdnToServerTbl", &g_toServerTable);
    status |= g_toServerTable->keyFieldIdGet("hdr.ethernet.dstAddr", &g_toServerKey);
    status |= g_toServerTable->keyFieldIdGet("ig_md.serverindex", &g_macTblKeySerIndex);
    status |= g_toServerTable->actionIdGet("SwitchIngress.SetToServerOutputPort", &g_toServerActionId);
    status |= g_toServerTable->dataFieldIdGet("outport", g_toServerActionId, &g_toServerValue);
    status |= g_toServerTable->keyAllocate(&g_toServerTableKey);
    status |= g_toServerTable->dataAllocate(&g_toServerTableData);
    printf("Info: NdnToServerTbl table init finish as:%u\n", status);
}

/*********************************************************************
 * Function: Initialization of PIT register groups
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitPitRegisters()
{
    bf_status_t status = 0;
    size_t tableSize = 0;

    status = g_bfrtInfo->bfrtTableFromNameGet("SwitchIngress.reg_table_finger1", &g_pitFinger1Reg);
    status |= g_pitFinger1Reg->keyFieldIdGet("$REGISTER_INDEX", &g_pitFinger1Key);
    status |= g_pitFinger1Reg->dataFieldIdGet("SwitchIngress.reg_table_finger1.f1", &g_pitFinger1Value);
    status |= g_pitFinger1Reg->keyAllocate(&g_pitFinger1RegKey);
    status |= g_pitFinger1Reg->dataAllocate(&g_pitFinger1RegData);
#ifdef SDE_9XX_OLD
    g_pitFinger1Reg->tableSizeGet((size_t*)(&showInfo.tableSize));
#else
    g_pitFinger1Reg->tableSizeGet(*g_session, g_dev_target, &tableSize);
#endif
    printf("Info: reg_table_finger1 table init finish as:%u, with size:%u\n", status, tableSize);
    g_regKeyMask = tableSize - 1;

    status = g_bfrtInfo->bfrtTableFromNameGet("SwitchIngress.reg_table_finger2", &g_pitFinger2Reg);
    status |= g_pitFinger2Reg->keyFieldIdGet("$REGISTER_INDEX", &g_pitFinger2Key);
    status |= g_pitFinger2Reg->dataFieldIdGet("SwitchIngress.reg_table_finger2.f1", &g_pitFinger2Value);
    status |= g_pitFinger2Reg->keyAllocate(&g_pitFinger2RegKey);
    status |= g_pitFinger2Reg->dataAllocate(&g_pitFinger2RegData);
    printf("Info: reg_table_finger2 table init finish as:%u\n", status);

    status = g_bfrtInfo->bfrtTableFromNameGet("SwitchIngress.reg_table_portmap1", &g_pitPort1Reg);
    status |= g_pitPort1Reg->keyFieldIdGet("$REGISTER_INDEX", &g_pitPort1Key);
    status |= g_pitPort1Reg->dataFieldIdGet("SwitchIngress.reg_table_portmap1.f1", &g_pitPort1Value);
    status |= g_pitPort1Reg->keyAllocate(&g_pitPort1RegKey);
    status |= g_pitPort1Reg->dataAllocate(&g_pitPort1RegData);
    printf("Info: reg_table_portmap1 table init finish as:%u\n", status);

    status = g_bfrtInfo->bfrtTableFromNameGet("SwitchIngress.reg_table_portmap2", &g_pitPort2Reg);
    status |= g_pitPort2Reg->keyFieldIdGet("$REGISTER_INDEX", &g_pitPort2Key);
    status |= g_pitPort2Reg->dataFieldIdGet("SwitchIngress.reg_table_portmap2.f1", &g_pitPort2Value);
    status |= g_pitPort2Reg->keyAllocate(&g_pitPort2RegKey);
    status |= g_pitPort2Reg->dataAllocate(&g_pitPort2RegData);
    printf("Info: reg_table_portmap2 table init finish as:%u\n", status);
}

/*********************************************************************
 * Function: Supported server number register initialization
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitServerNumRegister()
{
    bf_status_t status = 0;

    status = g_bfrtInfo->bfrtTableFromNameGet("SwitchIngress.reg_server_number", &g_serverNumReg);
    status |= g_serverNumReg->keyFieldIdGet("$REGISTER_INDEX", &g_serverNumKey);
    status |= g_serverNumReg->dataFieldIdGet("SwitchIngress.reg_server_number.f1", &g_serverNumValue);
    status |= g_serverNumReg->keyAllocate(&g_serverNumRegKey);
    status |= g_serverNumReg->dataAllocate(&g_serverNumRegData);
    printf("Info: reg_server_number table init finish as:%u\n", status);
}

/*********************************************************************
 * Function: Related tables initialization
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitTables()
{
    PCLNDN_InitPortBitmapTable();
    PCLNDN_InitMulticastTable();
    PCLNDN_InitToServerTable();
    PCLNDN_InitPitRegisters();
    PCLNDN_InitServerNumRegister();
}
/*********************************************************************
 * Function: Command line operation result prompt
 * Input:   status: result status
 *          clishContext: context pointer
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_CommonShowCmdRunResult(UINT32 status, VOID *clishContext)
{
    string infomsg = "Command run success.";
    if (status != PCL_OK) {
        infomsg = "Command run fail.";
    }
    if (clishContext == NULL) {
        printf("%s\n", infomsg.c_str());
    } else {
        bfshell_printf(clishContext, "%s\n", infomsg.c_str());
    }
}
/*********************************************************************
 * Function: Update operation entry of a table entry
 * Input:   opType: operation type
 *          tcamTable: table pointer
 *          tableKey: table key
 *          tableData: table data
 *          newTableData: new table data
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_UpdateTableOneEntry(PclNdnEntryOpType opType, const bfrt::BfRtTable* tcamTable, const bfrt::BfRtTableKey &tableKey, const bfrt::BfRtTableData &tableData)
{
    UINT32 status = PCL_ERROR;
    switch (opType) {
        case PCL_NDN_ENTRY_ADD_ONLY:
            status = (UINT32)tcamTable->tableEntryAdd(*g_session, g_dev_target, tableKey, tableData);
            break;
        case PCL_NDN_ENTRY_ADD_MOD:
            status = (UINT32)tcamTable->tableEntryMod(*g_session, g_dev_target, tableKey, tableData);
            break;
        case PCL_NDN_ENTRY_DEL:
            status = (UINT32)tcamTable->tableEntryDel(*g_session, g_dev_target, tableKey);
            break;
        default:
            printf("not support type:%u\n", opType);
    }
    return status;
}

/*********************************************************************
 * Function: Set the default entry for the table
 * Input:   tcamTable: table pointer
 *          tableData: table data
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_UpdateTableDefaultEntry(const bfrt::BfRtTable* tcamTable, const bfrt::BfRtTableData &tableData)
{
    UINT32 status = PCL_ERROR;
    status = (UINT32)tcamTable->tableDefaultEntrySet(*g_session, g_dev_target, tableData);
    return status;
}
const string g_tableTypeName[PCL_NDN_MAX_TABLE_TYPE] = {
    "MATCH_DIRECT",                /* 0: bfrt::BfRtTable::MATCH_DIRECT Match action table */
    "MATCH_INDIRECT",              /* 1: bfrt::BfRtTable::MATCH_INDIRECT Match action table with actions of the table implemented using an "ActionProfile"*/
    "MATCH_INDIRECT_SELECTOR",     /* 2: bfrt::BfRtTable::MATCH_INDIRECT_SELECTOR Match action table with actions of the table implemented using an "ActionSelector" */
    "ACTION_PROFILE",              /* 3: bfrt::BfRtTable::ACTION_PROFILE Action Profile table */
    "SELECTOR",                    /* 4: bfrt::BfRtTable::SELECTOR Action Selector table */
    "COUNTER",                     /* 5: bfrt::BfRtTable::COUNTER Counter table */
    "METER",                       /* 6: bfrt::BfRtTable::METER Meter table */
    "REGISTER",                    /* 7: bfrt::BfRtTable::REGISTER Register table */
    "LPF",                         /* 8: bfrt::BfRtTable::LPF LPF table */
    "WRED",                        /* 9: bfrt::BfRtTable::WRED WRED table */
    "PVS",                         /* 10: bfrt::BfRtTable::PVS Parser Value Set table. This table contains only Keys and no Data */
    "PORT_METADATA",               /* 11: bfrt::BfRtTable::PORT_METADATA Port Metadata table */
    "DYN_HASH_CFG",                /* 12: bfrt::BfRtTable::DYN_HASH_CFG Dynamic Hashing configuration table */
    "SNAPSHOT",                    /* 13: bfrt::BfRtTable::SNAPSHOT Snapshot */
    "SNAPSHOT_LIVENESS",           /* 14: bfrt::BfRtTable::SNAPSHOT_LIVENESS Snapshot field Liveness */
    "PORT_CFG",                    /* 15: bfrt::BfRtTable::PORT_CFG Port Configuration */
    "PORT_STAT",                   /* 16: bfrt::BfRtTable::PORT_STAT Port Stats */
    "PORT_HDL_INFO",               /* 17: bfrt::BfRtTable::PORT_HDL_INFO Port Hdl to Dev_port Conversion table*/
    "PORT_FRONT_PANEL_IDX_INFO",   /* 18: bfrt::BfRtTable::PORT_FRONT_PANEL_IDX_INFO Front panel Idx to Dev_port Conversion table */
    "PORT_STR_INFO",               /* 19: bfrt::BfRtTable::PORT_STR_INFO Port Str to Dev_port Conversion table */
    "PKTGEN_PORT_CFG",             /* 20: bfrt::BfRtTable::PKTGEN_PORT_CFG Pktgen Port Configuration table */
    "PKTGEN_APP_CFG",              /* 21: bfrt::BfRtTable::PKTGEN_APP_CFG Pktgen Application Configuration table */
    "PKTGEN_PKT_BUFF_CFG",         /* 22: bfrt::BfRtTable::PKTGEN_PKT_BUFF_CFG Pktgen Packet Buffer Configuration table */
    "PKTGEN_PORT_MASK_CFG",        /* 23: bfrt::BfRtTable::PKTGEN_PORT_MASK_CFG Pktgen Port Mask Configuration table */
    "PKTGEN_PORT_DOWN_REPLAY_CFG", /* 24: bfrt::BfRtTable::PKTGEN_PORT_DOWN_REPLAY_CFG Pktgen Port Down Replay Configuration table */
    "PRE_MGID",                    /* 25: bfrt::BfRtTable::PRE_MGID PRE MGID table */
    "PRE_NODE",                    /* 26: bfrt::BfRtTable::PRE_NODE PRE Node table */
    "PRE_ECMP",                    /* 27: bfrt::BfRtTable::PRE_ECMP PRE ECMP table */
    "PRE_LAG",                     /* 28: bfrt::BfRtTable::PRE_LAG PRE LAG table */
    "PRE_PRUNE",                   /* 29: bfrt::BfRtTable::PRE_PRUNE PRE Prune (L2 XID) table */
    "MIRROR_CFG",                  /* 30: bfrt::BfRtTable::MIRROR_CFG Mirror configuration table */
    "TM_PPG",                      /* 31: bfrt::BfRtTable::TM_PPG Traffic Mgr PPG Table */
    "PRE_PORT",                    /* 32: bfrt::BfRtTable::PRE_PORT PRE Port table */
};

string PCLNDN_GetTableTypeName(UINT32 tableType)
{
    if (tableType < PCL_NDN_MAX_TABLE_TYPE) {
        return g_tableTypeName[tableType];
    }
    return "UNKNOWN";
}

/*********************************************************************
 * Function: Show public information of a table
 * Input: showInfo: control information to show
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_GetTableCommonInfo(PclNdnTableFiledShowInfo &showInfo)
{
    string tableName = "";
    string tableTypeName = "";
    UINT32 ifUseage = PCL_TRUE;
    bfrt::BfRtTable::TableType tableType = bfrt::BfRtTable::TableType::MATCH_DIRECT;

    showInfo.tcamTable->tableNameGet(&tableName);
    showInfo.tcamTable->tableIdGet(&showInfo.tableId);

#ifdef SDE_9XX_OLD
    showInfo.tcamTable->tableSizeGet((size_t*)(&showInfo.tableSize));
#else
    showInfo.tcamTable->tableSizeGet(*g_session, g_dev_target, (size_t*)(&showInfo.tableSize));
#endif

    showInfo.tcamTable->tableTypeGet((&tableType));
    showInfo.tableType = (UINT32)tableType;
    ifUseage = PCLNDN_IF_SUPPORT_USAGE(tableType);
    tableTypeName = PCLNDN_GetTableTypeName(showInfo.tableType);
    
    if (ifUseage != PCL_TRUE) {
        if (showInfo.clishContext != NULL) {
            bfshell_printf(showInfo.clishContext, "Table %s Info:\n \tTableId:%u\n \tSize:%u\n \tType:%s\n",
                    tableName.c_str(), showInfo.tableId, showInfo.tableSize, tableTypeName.c_str());
        }
    } else {
        showInfo.tcamTable->tableUsageGet(*g_session, g_dev_target, PCL_NDN_GET_FROM_HW, &showInfo.usedCount);
        if (showInfo.clishContext != NULL) {
            bfshell_printf(showInfo.clishContext, "Table %s Info:\n \tTableId:%u\n \tSize:%u\n \tType:%s\n \tUsed count:%u\n",
                    tableName.c_str(), showInfo.tableId, showInfo.tableSize, tableTypeName.c_str(), showInfo.usedCount);
        }
    }
}
const string g_tableDataTypeName[PCLNDN_DATA_BUT] = {
    "INT_ARR",
    "BOOL_ARR",
    "UINT64",
    "BYTE_STREAM",
    "FLOAT",
    "CONTAINER",
    "STRING",
    "BOOL",
};
const string g_tableKeyTypeName[PCLNDN_KEY_BUT] = {
    "INVALID",
    "EXACT",
    "TERNARY",
    "RANGE",
    "LPM",
};

string PCLNDN_GetTableKeyTypeName(UINT32 keyType)
{
    if (keyType < PCLNDN_KEY_BUT) {
        return g_tableKeyTypeName[keyType];
    }
    return "UNKNOWN";
}

string PCLNDN_GetTableDataTypeName(UINT32 dataType)
{
    if (dataType < PCLNDN_DATA_BUT) {
        return g_tableDataTypeName[dataType];
    }
    return "UNKNOWN";
}

/*********************************************************************
 * Function: Show the value of the None symbol integer field
 * Input: showInfo: info to show
 *       filedName: field name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableUint64DataInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    uint64_t value = 0;

    if (showInfo.showType == PCL_NDN_TABLE_FIELD_KEY) {
        showInfo.tableKey->getValue(showInfo.fieldId, &value);
    } else {
        showInfo.tableData->getValue(showInfo.fieldId, &value);
    }
    bfshell_printf(showInfo.clishContext, "\t %s: 0x%x\n", filedName.c_str(), value);
}
/*********************************************************************
 * Function: Show the value of the None symbol integer string field
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableUint64ArrayDataInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    std::vector<uint64_t> valueList;
    vector<uint64_t>::iterator it;

    if (showInfo.showType == PCL_NDN_TABLE_FIELD_KEY) {
        bfshell_printf(showInfo.clishContext, "\t %s: Not support data type:%u", filedName.c_str(), showInfo.dataType);
        return;
    }
    showInfo.tableData->getValue(showInfo.fieldId, &valueList);
    bfshell_printf(showInfo.clishContext, "\t %s: ", filedName.c_str());
    for (it = valueList.begin(); it < valueList.end(); it++) {
        bfshell_printf(showInfo.clishContext, "0x%x ", *it);
    }
    bfshell_printf(showInfo.clishContext, "\n");
}

/*********************************************************************
 * Function: Show integer string field value processing
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableIntArrayDataInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    std::vector<bf_rt_id_t> valueList;
    vector<bf_rt_id_t>::iterator it;

    if (showInfo.showType == PCL_NDN_TABLE_FIELD_KEY) {
        bfshell_printf(showInfo.clishContext, "\t %s: Not support data type:%u", filedName.c_str(), showInfo.dataType);
        return;
    }

    showInfo.tableData->getValue(showInfo.fieldId, &valueList);
    bfshell_printf(showInfo.clishContext, "\t %s: ", filedName.c_str());
    for (it = valueList.begin(); it < valueList.end(); it++) {
        bfshell_printf(showInfo.clishContext, "%d ", *it);
    }
    bfshell_printf(showInfo.clishContext, "\n");
}
/*********************************************************************
 * Function: Show the value of a Boolean field
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableBoolDataInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    bool value = 0;
    string isValid = "";
    if (showInfo.showType == PCL_NDN_TABLE_FIELD_KEY) {
        bfshell_printf(showInfo.clishContext, "\t %s: Not support data type:%u", filedName.c_str(), showInfo.dataType);
        return;
    }
    showInfo.tableData->getValue(showInfo.fieldId, &value);
    isValid = PCL_NDN_BOOL_STRIG(value);
    bfshell_printf(showInfo.clishContext, "\t %s: %s\n", filedName.c_str(), isValid.c_str());
}
/*********************************************************************
 * Function: Show Boolean string field value processing
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableBoolArrayDataInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    std::vector<bool> valueList;
    vector<bool>::iterator it;
    string isValid = "";

    if (showInfo.showType == PCL_NDN_TABLE_FIELD_KEY) {
        bfshell_printf(showInfo.clishContext, "\t %s: Not support data type:%u", filedName.c_str(), showInfo.dataType);
        return;
    }

    showInfo.tableData->getValue(showInfo.fieldId, &valueList);
    bfshell_printf(showInfo.clishContext, "\t %s: ", filedName.c_str());
    for (it = valueList.begin(); it < valueList.end(); it++) {
        isValid = PCL_NDN_BOOL_STRIG(*it);
        bfshell_printf(showInfo.clishContext, "%s ", isValid.c_str());
    }
    bfshell_printf(showInfo.clishContext, "\n");
}
/*********************************************************************
 * Function: Show floating point field values
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableStringDataInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    std::string value = 0;
    if (showInfo.showType == PCL_NDN_TABLE_FIELD_KEY) {
        showInfo.tableKey->getValue(showInfo.fieldId, &value);
    } else {
        showInfo.tableData->getValue(showInfo.fieldId, &value);
    }
    bfshell_printf(showInfo.clishContext, "\t %s: %s\n", filedName.c_str(), value.c_str());
}
/*********************************************************************
 * Function: Show string field value processing
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableFloatDataInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    float value = 0;
    if (showInfo.showType == PCL_NDN_TABLE_FIELD_KEY) {
        bfshell_printf(showInfo.clishContext, "\t %s: Not support data type:%u", filedName.c_str(), showInfo.dataType);
        return;
    }
    showInfo.tableData->getValue(showInfo.fieldId, &value);
    bfshell_printf(showInfo.clishContext, "\t %s: %f\n", filedName.c_str(), value);
}
/*********************************************************************
 * Function: Show byte stream field value processing
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableByteStreamDataInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    UINT8 value[PCL_NDN_MAX_DATA_BYTE] = {0};
    size_t byteSize = (showInfo.fieldSize + 7) / 8;
    
    /* If the cache is too large, the maximum supported cache is used */
    if (byteSize > PCL_NDN_MAX_DATA_BYTE) {
        byteSize = PCL_NDN_MAX_DATA_BYTE;
        bfshell_printf(showInfo.clishContext, "Info: fieldId:%s length(%u) is bigger than our max buf, %u bytes will be show. \n",
            filedName.c_str(), showInfo.fieldSize, PCL_NDN_MAX_DATA_BYTE);
    }

    if (showInfo.showType == PCL_NDN_TABLE_FIELD_KEY) {
        showInfo.tableKey->getValue(showInfo.fieldId, byteSize, value);
    } else {
        showInfo.tableData->getValue(showInfo.fieldId, byteSize, value);
    }
    bfshell_printf(showInfo.clishContext, "\t %s: 0x", filedName.c_str());
    for (UINT32 index = 0; index < byteSize; index++) {
        bfshell_printf(showInfo.clishContext, "%02x", value[index]);
    }
    bfshell_printf(showInfo.clishContext, "\n");
}

/*********************************************************************
 * Function: BYTE_STREAM type processing dispatch entry
 * Input: showInfo: control info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_TableByteSteamPreProc(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    if ((showInfo.tableType == (UINT32)bfrt::BfRtTable::TableType::REGISTER) && (showInfo.showType != PCL_NDN_TABLE_FIELD_KEY)) {
        PCLNDN_ShowTableUint64ArrayDataInfo(showInfo, filedName);
        return;
    }
    /* If the byte stream is less than 64 bits, it will be shown according to the 64-bit operation manner */
    if (showInfo.fieldSize <= UINT32_BITS) {
        PCLNDN_ShowTableUint64DataInfo(showInfo, filedName);
        return;
    }
    PCLNDN_ShowTableByteStreamDataInfo(showInfo, filedName);
}

/*********************************************************************
 * Function: Public processing entry for showing the value of field
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableFieldDataInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    switch (showInfo.dataType) {
        case PCLNDN_DATA_INT_ARR:
            PCLNDN_ShowTableIntArrayDataInfo(showInfo, filedName);
            break;
        case PCLNDN_DATA_BOOL_ARR:
            PCLNDN_ShowTableBoolArrayDataInfo(showInfo, filedName);
            break;
        case PCLNDN_DATA_UINT64:
            PCLNDN_ShowTableUint64DataInfo(showInfo, filedName);
            break;
        case PCLNDN_DATA_BYTE_STREAM:
            PCLNDN_TableByteSteamPreProc(showInfo, filedName);
            break;
        case PCLNDN_DATA_FLOAT:
            PCLNDN_ShowTableFloatDataInfo(showInfo, filedName);
            break;
        case PCLNDN_DATA_STRING:
            PCLNDN_ShowTableStringDataInfo(showInfo, filedName);
            break;
        case PCLNDN_DATA_BOOL:
            PCLNDN_ShowTableBoolDataInfo(showInfo, filedName);
            break;
        default:
            bfshell_printf(showInfo.clishContext, "\t Field:%s type=%d is not support for display now.\n", filedName.c_str(), showInfo.dataType);
            break;
    }
}
/*********************************************************************
 * Function: Show the value of the None symbol integer field
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyTernaryUint64Info(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    uint64_t value = 0;
    uint64_t mask = 0;

    showInfo.tableKey->getValueandMask(showInfo.fieldId, &value, &mask);
    bfshell_printf(showInfo.clishContext, "\t %s: Value: 0x%x, Mask:0x%x\n", filedName.c_str(), value, mask);
}

/*********************************************************************
 * Function: show byte stream field value processing
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyTernaryByteStreamInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    UINT8 value[PCL_NDN_MAX_DATA_BYTE] = {0};
    UINT8 mask[PCL_NDN_MAX_DATA_BYTE] = {0};
    size_t byteSize = (showInfo.fieldSize + 7) / 8;
    
    /* If the cache is too large, the maximum supported cache is used */
    if (byteSize > PCL_NDN_MAX_DATA_BYTE) {
        byteSize = PCL_NDN_MAX_DATA_BYTE;
        bfshell_printf(showInfo.clishContext, "Info: fieldId:%s length(%u) is bigger than our max buf, %u bytes will be show. \n",
            filedName.c_str(), showInfo.fieldSize, PCL_NDN_MAX_DATA_BYTE);
    }

    showInfo.tableKey->getValueandMask(showInfo.fieldId, byteSize, value, mask);
    bfshell_printf(showInfo.clishContext, "\t %s:\n Value: 0x", filedName.c_str());
    for (UINT32 index = 0; index < byteSize; index++) {
        bfshell_printf(showInfo.clishContext, "%02x", value[index]);
    }
    bfshell_printf(showInfo.clishContext, ",\n Mask:0x");
    for (UINT32 index = 0; index < byteSize; index++) {
        bfshell_printf(showInfo.clishContext, "%02x", mask[index]);
    }
    bfshell_printf(showInfo.clishContext, "\n");
}

/*********************************************************************
 * Function: Byte stream field preprocessing
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_TableKeyByteSteamPreProc(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    /* If the byte stream is less than 64 bits, it will be shown according to the 64-bit operation manner */
    if (showInfo.fieldSize <= PCL_NDN_TABLE_DATA_SIZE_UINT64) {
        PCLNDN_ShowTableKeyTernaryUint64Info(showInfo, filedName);
        return;
    }
    PCLNDN_ShowTableKeyTernaryByteStreamInfo(showInfo, filedName);
}

/*********************************************************************
 * Function: Show field values ​​of ternary type matching rules 
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyTernaryInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    switch (showInfo.dataType) {
        case PCLNDN_DATA_UINT64:
            PCLNDN_ShowTableKeyTernaryUint64Info(showInfo, filedName);
            break;
        case PCLNDN_DATA_BYTE_STREAM:
            PCLNDN_TableKeyByteSteamPreProc(showInfo, filedName);
            break;
        default:
            bfshell_printf(showInfo.clishContext, "\t Field:%s type=%d is not support for display now.\n", filedName.c_str(), showInfo.dataType);
            break;
    }
}

/*********************************************************************
 * Function: Show the value of the None symbol integer field
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyRangeUint64Info(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    uint64_t start = 0;
    uint64_t end = 0;

    showInfo.tableKey->getValueRange(showInfo.fieldId, &start, &end);
    bfshell_printf(showInfo.clishContext, "\t %s: [%llu, %llu]\n", filedName.c_str(), start, end);
}

/*********************************************************************
 * Function: Show byte stream field values
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyRangeByteStreamInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    UINT8 start[PCL_NDN_MAX_DATA_BYTE] = {0};
    UINT8 end[PCL_NDN_MAX_DATA_BYTE] = {0};
    size_t byteSize = (showInfo.fieldSize + 7) / 8;
    
    /* If the cache is too large, the maximum supported cache is used */
    if (byteSize > PCL_NDN_MAX_DATA_BYTE) {
        byteSize = PCL_NDN_MAX_DATA_BYTE;
        bfshell_printf(showInfo.clishContext, "Info: fieldId:%s length(%u) is bigger than our max buf, %u bytes will be show. \n",
            filedName.c_str(), showInfo.fieldSize, PCL_NDN_MAX_DATA_BYTE);
    }

    showInfo.tableKey->getValueRange(showInfo.fieldId, byteSize, start, end);
    bfshell_printf(showInfo.clishContext, "\t %s: [0x", filedName.c_str());
    for (UINT32 index = 0; index < byteSize; index++) {
        bfshell_printf(showInfo.clishContext, "%02x", start[index]);
    }
    bfshell_printf(showInfo.clishContext, ", 0x");
    for (UINT32 index = 0; index < byteSize; index++) {
        bfshell_printf(showInfo.clishContext, "%02x", end[index]);
    }
    bfshell_printf(showInfo.clishContext, "]\n");
}

/*********************************************************************
 * Function: Byte stream field preprocessing
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_TableKeyRangePreProc(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    /* If the byte stream is less than 64 bits, it will be shown according to the 64-bit operation manner */
    if (showInfo.fieldSize <= PCL_NDN_TABLE_DATA_SIZE_UINT64) {
        PCLNDN_ShowTableKeyRangeUint64Info(showInfo, filedName);
        return;
    }
    PCLNDN_ShowTableKeyRangeByteStreamInfo(showInfo, filedName);
}

/*********************************************************************
 * Function: Show the field value of the matching rule of the range type
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyRangeInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    switch (showInfo.dataType) {
        case PCLNDN_DATA_UINT64:
            PCLNDN_ShowTableKeyRangeUint64Info(showInfo, filedName);
            break;
        case PCLNDN_DATA_BYTE_STREAM:
            PCLNDN_TableKeyRangePreProc(showInfo, filedName);
            break;
        default:
            bfshell_printf(showInfo.clishContext, "\t Field:%s type=%d is not support for display now.\n", filedName.c_str(), showInfo.dataType);
            break;
    }
}

/*********************************************************************
 * Function: Show the value of the None symbol integer field
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyLpmUint64Info(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    uint64_t value = 0;
    uint16_t preLength = 0;

    showInfo.tableKey->getValueLpm(showInfo.fieldId, &value, &preLength);
    bfshell_printf(showInfo.clishContext, "\t %s: Value:0x%x, Mask:%u\n", filedName.c_str(), value, preLength);
}

/*********************************************************************
 * Function: Show byte stream field values
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyLpmByteStreamInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    UINT8 value[PCL_NDN_MAX_DATA_BYTE] = {0};
    uint16_t preLength = 0;
    size_t byteSize = (showInfo.fieldSize + 7) / 8;
    
    /* If the cache is too large, the maximum supported cache is used */
    if (byteSize > PCL_NDN_MAX_DATA_BYTE) {
        byteSize = PCL_NDN_MAX_DATA_BYTE;
        bfshell_printf(showInfo.clishContext, "Info: fieldId:%s length(%u) is bigger than our max buf, %u bytes will be show. \n",
            filedName.c_str(), showInfo.fieldSize, PCL_NDN_MAX_DATA_BYTE);
    }

    showInfo.tableKey->getValueLpm(showInfo.fieldId, byteSize, value, &preLength);
    bfshell_printf(showInfo.clishContext, "\t %s: Value: 0x", filedName.c_str());
    for (UINT32 index = 0; index < byteSize; index++) {
        bfshell_printf(showInfo.clishContext, "%02x", value[index]);
    }
    bfshell_printf(showInfo.clishContext, ", Mask:%u\n", preLength);
}

/*********************************************************************
 * Function: Byte stream field preprocessing
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_TableKeyLpmPreProc(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    /* If the byte stream is less than 64 bits, it will be shown according to the 64-bit operation manner */
    if (showInfo.fieldSize <= PCL_NDN_TABLE_DATA_SIZE_UINT64) {
        PCLNDN_ShowTableKeyLpmUint64Info(showInfo, filedName);
        return;
    }
    PCLNDN_ShowTableKeyLpmByteStreamInfo(showInfo, filedName);
}

/*********************************************************************
 * Function: Show the field value of the matching rule of the range type
 * Input: showInfo: info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyLpmInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    switch (showInfo.dataType) {
        case PCLNDN_DATA_UINT64:
            PCLNDN_ShowTableKeyLpmUint64Info(showInfo, filedName);
            break;
        case PCLNDN_DATA_BYTE_STREAM:
            PCLNDN_TableKeyLpmPreProc(showInfo, filedName);
            break;
        default:
            bfshell_printf(showInfo.clishContext, "\t Field:%s type=%d is not support for display now.\n", filedName.c_str(), showInfo.dataType);
            break;
    }
}

/*********************************************************************
 * Function: processing entry for showing table KEY info
 * Input: showInfo: control info to show
 *       filedName: filed name
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyFieldDetailInfo(PclNdnTableFiledShowInfo &showInfo, string &filedName)
{
    switch(showInfo.keyType) {
        case PCLNDN_KEY_EXACT:
            PCLNDN_ShowTableFieldDataInfo(showInfo, filedName);
            break;
        case PCLNDN_KEY_TERNARY:
            PCLNDN_ShowTableKeyTernaryInfo(showInfo, filedName);
            break;
        case PCLNDN_KEY_RANGE:
            PCLNDN_ShowTableKeyRangeInfo(showInfo, filedName);
            break;
        case PCLNDN_KEY_LPM:
            PCLNDN_ShowTableKeyLpmInfo(showInfo, filedName);
            break;
        default:
            bfshell_printf(showInfo.clishContext, "\t Field:%s key type=%d is not support for display now.\n", filedName.c_str(), showInfo.keyType);
            break;
    }
}

/*********************************************************************
 * Function: Get the KEY attribute info of the table
 * Input:   tcamTable: table pointer
 * Output:  keyList: key list
 *          keyMapInfo: attribute info corresponding to the key
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_GetTableKeyFieldAttrInfo(const bfrt::BfRtTable* tcamTable, std::vector<bf_rt_id_t> &keyList,
    std::map<bf_rt_id_t, PclNdnTableKeyInfo> &keyMapInfo)
{
    bf_rt_id_t keyId = 0;
    bf_status_t status = BF_SUCCESS;
    bfrt::DataType dataType = bfrt::DataType::UINT64;
    bfrt::KeyFieldType keyType = bfrt::KeyFieldType::INVALID;
    size_t fieldSize = 0;
    PclNdnTableKeyInfo keyInfo;
    string tempName = "";
    bool ifPtr = false;
    UINT32 keyNums = 0;
    
    /* get key info */
    status = tcamTable->keyFieldIdListGet(&keyList);
    if (status != BF_SUCCESS) {
        // bfshell_printf(clishContext, "\t Get key list failed for 0x%x.\n", status);
        return status;
    }
    keyNums = keyList.size();
    for (UINT32 i = 0; i < keyNums; ++i) {
        keyId = keyList[i];

        keyType = bfrt::KeyFieldType::INVALID;
        tcamTable->keyFieldTypeGet(keyId, &keyType);
        keyInfo.keyType = (UINT32)keyType;

        dataType = bfrt::DataType::UINT64;
        tcamTable->keyFieldDataTypeGet(keyId, &dataType);
        keyInfo.dataType = (UINT32)dataType;

        fieldSize = 0;
        tcamTable->keyFieldSizeGet(keyId, &fieldSize);
        keyInfo.fieldSize = fieldSize;

        ifPtr = false;
        tcamTable->keyFieldIsPtrGet(keyId, &ifPtr);
        keyInfo.ifPtr = (UINT32)ifPtr;

        tempName = "";
        tcamTable->keyFieldNameGet(keyId, &tempName);
        keyInfo.fieldName = tempName;
        
        keyMapInfo[keyId] = keyInfo;
    }
    return PCL_OK;
}

/*********************************************************************
 * Function: Show the key attribute info of the table
 * Input: clishContext: command line context
 *       keyList: key list
 *       keyMapInfo: Attribute info corresponding to the key
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableKeyFieldAttrInfo(const void *clishContext, std::vector<bf_rt_id_t> &keyList,
    std::map<bf_rt_id_t, PclNdnTableKeyInfo> &keyMapInfo)
{
    bf_rt_id_t keyId = 0;
    UINT32 keyNums = 0;
    string keyTypeName = "";
    string dataTypeName = "";
    string isPtr = "";
    
    keyNums = keyList.size();
    bfshell_printf(clishContext, "Entries attribute info:\n  %u key field(s) in this table. Key field info:\n", keyNums);
    bfshell_printf(clishContext, "|---------------------------------------------------------------------------|\n");
    bfshell_printf(clishContext, "|   ID   |        Name        |    DataType    | MatchType |  Size  |  Ptr  |\n");

    for (UINT32 i = 0; i < keyNums; ++i) {
        keyId = keyList[i];
        PclNdnTableKeyInfo &keyInfo = keyMapInfo[keyId];
        keyTypeName = PCLNDN_GetTableKeyTypeName(keyInfo.keyType);
        dataTypeName = PCLNDN_GetTableDataTypeName(keyInfo.dataType);
        isPtr = PCL_NDN_BOOL_STRIG(keyInfo.ifPtr);
        bfshell_printf(clishContext, "|%8u|%20s|%16s|%11s|%8u|%7s|\n",
            keyId, keyInfo.fieldName.c_str(), dataTypeName.c_str(), keyTypeName.c_str(), keyInfo.fieldSize, isPtr.c_str());
    }
    bfshell_printf(clishContext, "|---------------------------------------------------------------------------|\n");
}

/*********************************************************************
 * Function: Get the value attribute info of the table with action
 * Input: tcamTable: table pointer
 *       actionId: action ID
 * Output: dataList: value list
 *       dataMapInfo: attribute info corresponding to the value
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_GetTableValueFieldAttrWithAction(const bfrt::BfRtTable* tcamTable, UINT32 actionId,
    std::vector<bf_rt_id_t> &dataList, std::map<bf_rt_id_t, PclNdnTableDataInfo> &dataMapInfo)
{
    bf_rt_id_t fieldId = 0;
    bf_status_t status = BF_SUCCESS;
    PclNdnTableDataInfo dataFieldInfo;
    bfrt::DataType dataType = bfrt::DataType::UINT64;
    size_t fieldSize = 0;
    string tempName = "";
    bool ifValid = false;
    UINT32 dataNums = 0;

    /* get the data field list */
    status = tcamTable->dataFieldIdListGet(actionId, &dataList);
    if (status != BF_SUCCESS) {
        return status;
    }
    dataNums = dataList.size();
    for (UINT32 i = 0; i < dataNums; ++i) {
        fieldId = dataList[i];

        dataType = bfrt::DataType::UINT64;
        tcamTable->dataFieldDataTypeGet(fieldId, actionId, &dataType);
        dataFieldInfo.dataType = (UINT32)dataType;

        fieldSize = 0;
        tcamTable->dataFieldSizeGet(fieldId, actionId, &fieldSize);
        dataFieldInfo.fieldSize = fieldSize;

        ifValid = false;
        tcamTable->dataFieldIsPtrGet(fieldId, actionId, &ifValid);
        dataFieldInfo.ifPtr = (UINT32)ifValid;

        ifValid = false;
        tcamTable->dataFieldMandatoryGet(fieldId, actionId, &ifValid);
        dataFieldInfo.ifMandatory = (UINT32)ifValid;

        ifValid = false;
        tcamTable->dataFieldReadOnlyGet(fieldId, actionId, &ifValid);
        dataFieldInfo.ifReadOnly = (UINT32)ifValid;

        tempName = "";
        tcamTable->dataFieldNameGet(fieldId, actionId, &tempName);
        dataFieldInfo.fieldName = tempName;

        dataMapInfo[fieldId] = dataFieldInfo;
    }
    return PCL_OK;
}
/*********************************************************************
 * Function: Get the value attribute info of the table without action
 * Input: tcamTable: table pointer
 * Output: dataList: value list
 *       dataMapInfo: attribute info corresponding to the value
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_GetTableValueFieldAttrWithoutAction(const bfrt::BfRtTable* tcamTable,
    std::vector<bf_rt_id_t> &dataList, std::map<bf_rt_id_t, PclNdnTableDataInfo> &dataMapInfo)
{
    bf_rt_id_t fieldId = 0;
    bf_status_t status = BF_SUCCESS;
    PclNdnTableDataInfo dataFieldInfo;
    bfrt::DataType dataType = bfrt::DataType::UINT64;
    size_t fieldSize = 0;
    string tempName = "";
    bool ifValid = false;
    UINT32 dataNums = 0;

    /* get the data field list */
    status = tcamTable->dataFieldIdListGet(&dataList);
    if (status != BF_SUCCESS) {
        return status;
    }
    dataNums = dataList.size();
    for (UINT32 i = 0; i < dataNums; ++i) {
        fieldId = dataList[i];

        dataType = bfrt::DataType::UINT64;
        tcamTable->dataFieldDataTypeGet(fieldId, &dataType);
        dataFieldInfo.dataType = (UINT32)dataType;

        fieldSize = 0;
        tcamTable->dataFieldSizeGet(fieldId, &fieldSize);
        dataFieldInfo.fieldSize = fieldSize;

        ifValid = false;
        tcamTable->dataFieldIsPtrGet(fieldId, &ifValid);
        dataFieldInfo.ifPtr = (UINT32)ifValid;

        ifValid = false;
        tcamTable->dataFieldMandatoryGet(fieldId, &ifValid);
        dataFieldInfo.ifMandatory = (UINT32)ifValid;

        ifValid = false;
        tcamTable->dataFieldReadOnlyGet(fieldId, &ifValid);
        dataFieldInfo.ifReadOnly = (UINT32)ifValid;

        tempName = "";
        tcamTable->dataFieldNameGet(fieldId, &tempName);
        dataFieldInfo.fieldName = tempName;

        dataMapInfo[fieldId] = dataFieldInfo;
    }
    return PCL_OK;
}
/*********************************************************************
 * Function: Get the value attribute info of the table
 * Input: tcamTable: table pointer
 *       useAction: if there is action
 *       actionId: action ID
 * Output: dataList: value list
 *       dataMapInfo: attribute info corresponding to the value
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_GetTableDataFieldAttrInfo(const bfrt::BfRtTable* tcamTable, UINT32 useAction, UINT32 actionId,
    std::vector<bf_rt_id_t> &dataList, std::map<bf_rt_id_t, PclNdnTableDataInfo> &dataMapInfo)
{
    UINT32 ret = PCL_OK;
    if (useAction == PCL_TRUE) {
        ret = PCLNDN_GetTableValueFieldAttrWithAction(tcamTable, actionId, dataList, dataMapInfo);
    } else {
        ret = PCLNDN_GetTableValueFieldAttrWithoutAction(tcamTable, dataList, dataMapInfo);
    }
    return ret;
}

/*********************************************************************
 * Function: Show the value attribute info of the table
 * Input: clishContext: command line context
 *       dataList: value list
 *       dataMapInfo: attribute info corresponding to the value
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableDataFieldAttrInfo(const void *clishContext, std::vector<bf_rt_id_t> &dataList,
    std::map<bf_rt_id_t, PclNdnTableDataInfo> &dataMapInfo)
{
    bf_rt_id_t fieldId = 0;
    UINT32 dataNums = 0;
    string dataTypeName = "";
    string isPtr = "";
    string isMandatory = "";
    string isReadOnly = "";
    
    dataNums = dataList.size();
    bfshell_printf(clishContext, "  %u value field(s) in this table. Value field info:\n", dataNums);
    bfshell_printf(clishContext, "|----------------------------------------------------------------------------------|\n");
    bfshell_printf(clishContext, "|   ID   |        Name        |    DataType    |  Size  |  Ptr  |Mandatory|ReadOnly|\n");

    for (UINT32 i = 0; i < dataNums; ++i) {
        fieldId = dataList[i];
        PclNdnTableDataInfo &dataInfo = dataMapInfo[fieldId];
        dataTypeName = PCLNDN_GetTableDataTypeName(dataInfo.dataType);
        isPtr = PCL_NDN_BOOL_STRIG(dataInfo.ifPtr);
        isMandatory = PCL_NDN_BOOL_STRIG(dataInfo.ifMandatory);
        isReadOnly = PCL_NDN_BOOL_STRIG(dataInfo.ifReadOnly);
        bfshell_printf(clishContext, "|%8u|%20s|%16s|%8u|%7s|%9s|%8s|\n",
            fieldId, dataInfo.fieldName.c_str(), dataTypeName.c_str(), dataInfo.fieldSize, isPtr.c_str(), isMandatory.c_str(), isReadOnly.c_str());
    }
    bfshell_printf(clishContext, "|----------------------------------------------------------------------------------|\n");
}

/*********************************************************************
 * Function: Show information of an entry in the table
 * Input: showInfo: control info to show
 *       keyList: key list
 *       keyMapInfo: Attribute info corresponding to the key
 *       dataList: value list
 *       dataMapInfo: attribute info corresponding to the value
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableOneEntryField(PclNdnTableFiledShowInfo &showInfo, std::vector<bf_rt_id_t> &keyList,
    std::map<bf_rt_id_t, PclNdnTableKeyInfo> &keyMapInfo, std::vector<bf_rt_id_t> &dataList,
    std::map<bf_rt_id_t, PclNdnTableDataInfo> &dataMapInfo)
{
    UINT32 keyNums = 0;
    UINT32 dataNums = 0;

    if (showInfo.entryType == PCL_NDN_ENTRY_NORMAL) {
        showInfo.showType = PCL_NDN_TABLE_FIELD_KEY;
        keyNums = keyList.size();
        /* show the 1st KEY */
        bfshell_printf(showInfo.clishContext, "Index:%u \n Key:\n", showInfo.index);
        for (UINT32 i = 0; i < keyNums; ++i) {
            showInfo.fieldId =  keyList[i];
            showInfo.dataType = keyMapInfo[keyList[i]].dataType;
            showInfo.keyType = keyMapInfo[keyList[i]].keyType;
            showInfo.fieldSize = keyMapInfo[keyList[i]].fieldSize;
            PCLNDN_ShowTableKeyFieldDetailInfo(showInfo, keyMapInfo[keyList[i]].fieldName);
        }
    }
    showInfo.showType = PCL_NDN_TABLE_FIELD_DATA;
    /* show the 1st data */
    if (showInfo.entryType == PCL_NDN_ENTRY_NORMAL) {
        bfshell_printf(showInfo.clishContext," Value:\n");
    } else {
        bfshell_printf(showInfo.clishContext," Default Value:\n");
    }
    dataNums = dataList.size();
    for (UINT32 i = 0; i < dataNums; ++i) {
        showInfo.fieldId =  dataList[i];
        showInfo.dataType = dataMapInfo[dataList[i]].dataType;
        showInfo.fieldSize = dataMapInfo[dataList[i]].fieldSize;
        PCLNDN_ShowTableFieldDataInfo(showInfo, dataMapInfo[dataList[i]].fieldName);
    }
}

/*********************************************************************
 * Function: Show common info of an entry in the table searched by index
 * Input: showInfo: control info to show
 *       useAction: indicates whether actionid is needed
 *       actionId: actionId
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableOneEntry(PclNdnTableFiledShowInfo &showInfo, UINT32 useAction, UINT32 actionId)
{
    UINT32 ret = PCL_OK;
    std::vector<bf_rt_id_t> keyList;
    std::map<bf_rt_id_t, PclNdnTableKeyInfo> keyMapInfo;
    std::vector<bf_rt_id_t> dataList;
    std::map<bf_rt_id_t, PclNdnTableDataInfo> dataMapInfo;

    /* retrieve and show public info */
    if (showInfo.hideAttr != PCL_TRUE) {
        bfshell_printf(showInfo.clishContext, "=====================================================================================\n");
        PCLNDN_GetTableCommonInfo(showInfo);
    }

    /* get key info */
    ret = PCLNDN_GetTableKeyFieldAttrInfo(showInfo.tcamTable, keyList, keyMapInfo);
    if (ret != PCL_OK) {
        bfshell_printf(showInfo.clishContext, "Error: Get key list failed for 0x%x.\n", ret);
        return;
    }
    /* get value field */
    ret = PCLNDN_GetTableDataFieldAttrInfo(showInfo.tcamTable, useAction, actionId, dataList, dataMapInfo);
    if (ret != PCL_OK) {
        bfshell_printf(showInfo.clishContext, "Error: Get data list failed for 0x%x.\n", ret);
        return;
    }
    if (showInfo.hideAttr != PCL_TRUE) {
        bfshell_printf(showInfo.clishContext, "=====================================================================================\n");
        /* show key-value attribute info */
        PCLNDN_ShowTableKeyFieldAttrInfo(showInfo.clishContext, keyList, keyMapInfo);
        PCLNDN_ShowTableDataFieldAttrInfo(showInfo.clishContext, dataList, dataMapInfo);
        bfshell_printf(showInfo.clishContext, "=====================================================================================\n");
    }

    if (showInfo.entryType == PCL_NDN_ENTRY_NORMAL) {
        /* get table data */
        ret = showInfo.tcamTable->tableEntryGet(*g_session, g_dev_target, *showInfo.tableKey, PCL_NDN_GET_FROM_HW, showInfo.tableData);
        if (ret != BF_SUCCESS) {
            bfshell_printf(showInfo.clishContext, "Info: Entry not exsit with the key.\n");
            return;
        }
    } else {
        ret = showInfo.tcamTable->tableDefaultEntryGet(*g_session, g_dev_target, PCL_NDN_GET_FROM_HW, showInfo.tableData);
        if (ret != BF_SUCCESS) {
            bfshell_printf(showInfo.clishContext, "Info: Default entry has not been set, please set first.\n");
            return;
        }
    }
    PCLNDN_ShowTableOneEntryField(showInfo, keyList, keyMapInfo, dataList, dataMapInfo);
    bfshell_printf(showInfo.clishContext, "=====================================================================================\n");
}

/*********************************************************************
 * Function: Show all entries except the first one
 * Input: showInfo: control info to show
 *       keyList: key list
 *       keyMapInfo: Attribute info corresponding to the key
 *       dataList: value list
 *       dataMapInfo: attribute info corresponding to the value
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowTableLeftEntries(PclNdnTableFiledShowInfo &showInfo,
    std::vector<bf_rt_id_t> &keyList, std::map<bf_rt_id_t, PclNdnTableKeyInfo> &keyMapInfo,
    std::vector<bf_rt_id_t> &dataList, std::map<bf_rt_id_t, PclNdnTableDataInfo> &dataMapInfo)
{
    bf_status_t status = BF_SUCCESS;
    UINT32 returned = 0;
    bfrt::BfRtTable::keyDataPairs key_data_pairs;
    std::vector<std::unique_ptr<bfrt::BfRtTableKey>> keys(showInfo.leftEntry);
    std::vector<std::unique_ptr<bfrt::BfRtTableData>> data(showInfo.leftEntry);

    for (unsigned i = 0; i < showInfo.leftEntry; ++i) {
        showInfo.tcamTable->keyAllocate(&keys[i]);
        showInfo.tcamTable->dataAllocate(&data[i]);
        key_data_pairs.push_back(std::make_pair(keys[i].get(), data[i].get()));
    }
    status = showInfo.tcamTable->tableEntryGetNext_n(*g_session,
                                                g_dev_target,
                                                *showInfo.tableKey,
                                                showInfo.leftEntry,
                                                PCL_NDN_GET_FROM_HW,
                                                &key_data_pairs,
                                                &returned);
    if ((status != BF_SUCCESS) || (returned != showInfo.leftEntry)) {
        bfshell_printf(showInfo.clishContext, "Error: Get next entry fail for status:%u, returned:%u, expct:%u\n",
            status, returned, showInfo.leftEntry);
        return;
    }
    /* show the remaining entries */
    for (UINT32 i = 0; i < returned; ++i) {
        showInfo.tableKey = keys[i].get();
        showInfo.tableData = data[i].get();
        PCLNDN_ShowTableOneEntryField(showInfo, keyList, keyMapInfo, dataList, dataMapInfo);
        showInfo.index++;
        bfshell_printf(showInfo.clishContext, "=====================================================================================\n");
    }
}

/*********************************************************************
 * Function: Show public info of the table
 * Input: tcamTable: table pointer
 *       useAction: indicates whether actionid is needed
 *       actionId: actionId
 *       clishContext: command line context
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_CommonShowTcamTableInfo(const bfrt::BfRtTable* tcamTable, UINT32 useAction, UINT32 actionId, const VOID *clishContext)
{
    UINT32 ret = 0;
    std::vector<bf_rt_id_t> keyList;
    std::map<bf_rt_id_t, PclNdnTableKeyInfo> keyMapInfo;
    std::vector<bf_rt_id_t> dataList;
    std::map<bf_rt_id_t, PclNdnTableDataInfo> dataMapInfo;
    std::unique_ptr<bfrt::BfRtTableKey> firstKey;
    std::unique_ptr<bfrt::BfRtTableData> firstData;
    PclNdnTableFiledShowInfo showInfo = {0};

    bfshell_printf(clishContext, "=====================================================================================\n");
    /* retrieve and show public info */
    showInfo.index = 1;
    showInfo.clishContext = (VOID*)clishContext;
    showInfo.tcamTable = (bfrt::BfRtTable*)tcamTable;
    PCLNDN_GetTableCommonInfo(showInfo);
    /* get key info */
    ret = PCLNDN_GetTableKeyFieldAttrInfo(tcamTable, keyList, keyMapInfo);
    if (ret != PCL_OK) {
        bfshell_printf(clishContext, "Error: Get key list failed for 0x%x.\n", ret);
        return;
    }
    /* get value field */
    ret = PCLNDN_GetTableDataFieldAttrInfo(tcamTable, useAction, actionId, dataList, dataMapInfo);
    if (ret != PCL_OK) {
        bfshell_printf(clishContext, "Error: Get data list failed for 0x%x.\n", ret);
        return;
    }
    bfshell_printf(clishContext, "=====================================================================================\n");
    /* show key-value attribute info */
    PCLNDN_ShowTableKeyFieldAttrInfo(clishContext, keyList, keyMapInfo);
    PCLNDN_ShowTableDataFieldAttrInfo(clishContext, dataList, dataMapInfo);

    /* get the 1st info */
    tcamTable->keyAllocate(&firstKey);
    tcamTable->dataAllocate(&firstData);
    ret = tcamTable->tableEntryGetFirst(*g_session, g_dev_target, PCL_NDN_GET_FROM_HW, firstKey.get(), firstData.get());
    if (ret != BF_SUCCESS) {
        bfshell_printf(clishContext, "\t No Entries.\n");
        return;
    }
    showInfo.tableKey = firstKey.get();
    showInfo.tableData = firstData.get();

    bfshell_printf(clishContext, "=====================================================================================\n");
    /* show the 1st info */
    PCLNDN_ShowTableOneEntryField(showInfo, keyList, keyMapInfo, dataList, dataMapInfo);
    bfshell_printf(clishContext, "=====================================================================================\n");
    /* If there is only one info, then return to the end directly */
    if (showInfo.usedCount == 1) {
        return;
    }
    showInfo.index++;
    /* Get and show the remaining table entries */
    showInfo.leftEntry = showInfo.usedCount - 1;
    PCLNDN_ShowTableLeftEntries(showInfo, keyList, keyMapInfo, dataList, dataMapInfo);
    //bfshell_printf(clishContext, "=====================================================================================\n");
}
/*********************************************************************
 * Function: Show port-bitmap table entry
 * Input: portBitInfo: port-bitmap info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPortBitmapEntry(UINT32 portDevId, UINT32 index, UINT8 hideAttr, VOID *clishContext)
{
    PclNdnTableFiledShowInfo showInfo = {0};

    /* Initialize arguments */
    showInfo.index = index;
    showInfo.hideAttr = hideAttr;
    showInfo.clishContext = clishContext;
    g_portBitmapTable->keyReset(g_portBitmapTableKey.get());
    g_portBitmapTable->dataReset(g_portBitmapActionId, g_portBitmapTableData.get());
    showInfo.tcamTable = (bfrt::BfRtTable*)g_portBitmapTable;

    /* configure Key */
    g_portBitmapTableKey->setValue(g_keyInPort, (uint64_t)portDevId);

    /* configure key-value arguments */
    showInfo.tableKey = g_portBitmapTableKey.get();
    showInfo.tableData = g_portBitmapTableData.get();
    PCLNDN_ShowTableOneEntry(showInfo, PCL_TRUE, g_portBitmapActionId);
}

/*********************************************************************
 * Function: Show all port-bitmap table entries
 * Input: portBitInfo: port-bitmap info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowAllPortBitmapEntry(PclBitmapCmdInfo &portBitInfo)
{
    PCLNDN_CommonShowTcamTableInfo(g_portBitmapTable, PCL_TRUE, g_portBitmapActionId, portBitInfo.clishContext);
}

/*********************************************************************
 * Function: Add a port-bimap table entry
 * Input:  portBitInfo: port-bitmap info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_UpdatePortBitmapEntry(UINT32 portDevId, UINT32 bitmapId, UINT8 subType, VOID *clishContext)
{
    g_portBitmapTable->keyReset(g_portBitmapTableKey.get());
    g_portBitmapTable->dataReset(g_portBitmapActionId, g_portBitmapTableData.get());
    g_portBitmapTableKey->setValue(g_keyInPort, (uint64_t)portDevId);
    g_portBitmapTableData->setValue(g_portBitmapValue, (uint64_t)bitmapId);

    if (clishContext == NULL) {
        printf("Info: will add/mod/del(0:add,1:mod or add,2:del, current:%u) bitmap entry for devid:%u, bitmap:%u\n", subType, portDevId, bitmapId);
    } else {
        bfshell_printf(clishContext, "Info: will add/mod/del(0:add,1:mod or add,2:del, current:%u) bitmap entry for devid:%u, bitmap:%u\n",
            subType, portDevId, bitmapId);
    }
    UINT32 status = PCLNDN_UpdateTableOneEntry((PclNdnEntryOpType)subType, g_portBitmapTable, *g_portBitmapTableKey, *g_portBitmapTableData);
    //PCLNDN_CommonShowCmdRunResult(status, clishContext);
}

/*********************************************************************
 * Function: Calculate corresponding ports based on (multicast) group ID
 * Input: groupId: group ID
 * Output: portList: port list
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_GetPortListByGroup(PclMultiGroupCmdInfo &nodeInfo, std::vector<bf_rt_id_t> &portList)
{
    map<UINT32, PclPortMngInfo>::iterator it;
    UINT32 bitmask = nodeInfo.bitmap;
    UINT32 bitreverse = 0;
    UINT8 bitmapIndex = 0;
    UINT8 baseIndex = nodeInfo.areaId * PCL_MAX_PORT_AREA_NUM + 1;

    it = g_mapPortMngInfo.begin();
    while (it != g_mapPortMngInfo.end()) {
        PclPortMngInfo &portInfo = it->second;
        if (portInfo.used == PCL_TRUE) {
            /* Only the same groups can form a group */
            if (portInfo.areaId == nodeInfo.areaId) {
                bitmapIndex = portInfo.connId - baseIndex;
                bitreverse = SHIFT_LEFT_BITS(bitmapIndex);
                /* add to the list */
                if ((bitreverse & bitmask) != 0) {
                    portList.push_back(portInfo.portDevId);
                    /* add one and delete one */
                    bitreverse = ~bitreverse;
                    bitmask = bitmask & bitreverse;
                }
            }
        }
        it++;
    }
    if (bitmask == 0) {
        return PCL_OK;
    }
    bfshell_printf(nodeInfo.clishContext, "Error: the bitmask with the following bit(s) has not been set to port:\n");
    for (UINT32 index = 0; index < PCL_MAX_PORT_BITMAP_BITS; index++) {
        bitreverse = SHIFT_LEFT_BITS(index);
        if ((bitreverse & bitmask) != 0) {
            bfshell_printf(nodeInfo.clishContext, "%u ", (index + baseIndex));
        }
    }
    bfshell_printf(nodeInfo.clishContext, "\n");

    return PCL_ERROR;
}
/*********************************************************************
 * Function: Show info about table entry updates
 * Input:  opType: operation type
 *      nodeInfo: node info
 *      portList: port list
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPreNodeTableUpdateInfo(PclMultiGroupCmdInfo &nodeInfo, std::vector<bf_rt_id_t> &portList)
{
    vector<bf_rt_id_t>::iterator it;

    /* show by serial port */
    if (nodeInfo.clishContext == NULL) {
        printf("Info: will add/mod/del(0:add,1:mod or add,2:del, current:%u) $pre.node nodeid:%u, the port list is:\n",
               nodeInfo.subCmd, nodeInfo.bitmask);
        for (it = portList.begin(); it < portList.end(); it++) {
            printf("%u ", *it);
        }
        printf("\n");
        return;
    }
    /* show by command line */
    bfshell_printf(nodeInfo.clishContext, "Info: will add/mod/del(0:add,1:mod or add,2:del, current:%u) $pre.node nodeid:%u, the port list is:\n",
                   nodeInfo.subCmd, nodeInfo.bitmask);
    for (it = portList.begin(); it < portList.end(); it++) {
        bfshell_printf(nodeInfo.clishContext, "%u ", *it);
    }
    bfshell_printf(nodeInfo.clishContext, "\n");
    return;
}
/*********************************************************************
 * Function: Multicast send entry update injection
 * Input: opType: operation type
 *      nodeInfo: node info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_UpdatePreNodeTableEntry(PclMultiGroupCmdInfo &nodeInfo)
{
    std::vector<bf_rt_id_t> portList;
    UINT32 ret = 0;

    /*  There is a bug in SDE 9.2.0, which processes bytes as bits to check the size. 
        Therefore, tables larger than 15 cannot be added. 
        After confirming whether to upgrade the SDE version, we will decide whether to keep this part. */
    g_preNodeTable->keyReset(g_preNodeTableKey.get());
    g_preNodeTableKey->setValue(g_preNodeKeyNodeId, (uint64_t)nodeInfo.bitmask);

    /* updates without deletion */
    if (nodeInfo.subCmd != PCL_NDN_ENTRY_DEL) {
        ret = PCLNDN_GetPortListByGroup(nodeInfo, portList);
        if (ret != PCL_OK) {
            return PCL_ERROR;
        }
        g_preNodeTable->dataReset(g_preNodeTableData.get());
        g_preNodeTableData->setValue(g_preNodeGroupIdValue, (uint64_t)nodeInfo.bitmask);
        g_preNodeTableData->setValue(g_preNodePortListValue, portList);
    }

    /* echo info */
    PCLNDN_ShowPreNodeTableUpdateInfo(nodeInfo, portList);
    ret = PCLNDN_UpdateTableOneEntry((PclNdnEntryOpType)nodeInfo.subCmd, g_preNodeTable, *g_preNodeTableKey, *g_preNodeTableData);
    return ret;
}

/*********************************************************************
 * Function: Show info about table entry updates
 * Input:  opType: operation type
 *      groupInfo: group info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPreMgidTableUpdateInfo(PclMultiGroupCmdInfo &groupInfo)
{
    /* show by serial port */
    if (groupInfo.clishContext == NULL) {
        printf("Info: will add/mod/del(0:add,1:mod or add,2:del, current:%u) $pre.mgid for groupId:%u\n", groupInfo.subCmd, groupInfo.bitmask);
        return;
    }
    /* show by command line */
    bfshell_printf(groupInfo.clishContext, "Info: will add/mod/del(0:add,1:mod or add,2:del, current:%u) $pre.mgid for groupId:%u\n", groupInfo.subCmd, groupInfo.bitmask);
    return;
}
/*********************************************************************
 * Function: Multicast send entry update injection
 * Input:  opType: operation type
 *      groupInfo: group info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_UpdatePreMgIdTableEntry(PclMultiGroupCmdInfo &groupInfo)
{
    std::vector<bf_rt_id_t> l1Id;
    std::vector<bf_rt_id_t> l1XId;
    std::vector<bool> xidValid;
    std::vector<bf_rt_id_t> ecmpids;
    std::vector<bf_rt_id_t> ecmpidx;
    std::vector<bool> ecmpidxValid;

    /* configure Key */
    g_preMgidTable->keyReset(g_preMgidTableKey.get());
    g_preMgidTableKey->setValue(g_preMgidKeyGroupId, (uint64_t)groupInfo.bitmask);

    /* updates without deletion */
    if (groupInfo.subCmd != PCL_NDN_ENTRY_DEL) {
        l1Id.push_back(groupInfo.bitmask);
        l1XId.push_back(0);
        xidValid.push_back(false);
        ecmpids.clear();
        ecmpidx.clear();
        ecmpidxValid.clear();
        g_preMgidTable->dataReset(g_preMgidTableData.get());
        g_preMgidTableData->setValue(g_preMgidNodeIdValue, l1Id);
        g_preMgidTableData->setValue(g_preMgidL1Xid, l1XId);
        g_preMgidTableData->setValue(g_preMgidL1XidValid, xidValid);
        g_preMgidTableData->setValue(g_preMgidEcmpIds, ecmpids);
        g_preMgidTableData->setValue(g_preMgidEcmpL1xidValid, ecmpidxValid);
        g_preMgidTableData->setValue(g_preMgidEcmpL1xid, ecmpidx);
    }
    PCLNDN_ShowPreMgidTableUpdateInfo(groupInfo);
    UINT32 status = PCLNDN_UpdateTableOneEntry((PclNdnEntryOpType)groupInfo.subCmd, g_preMgidTable, *g_preMgidTableKey, *g_preMgidTableData);
    return status;
}

/*********************************************************************
 * Function: Multicast send entry injection
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitMulticastTableEntry()
{
}

/*********************************************************************
 * Function: Change the number of supported servers
 * Input:  serverNumber: number of servers
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_UpdateServerNumEntry(UINT32 serverNumber)
{
    g_serverNumReg->keyReset(g_serverNumRegKey.get());
    g_serverNumReg->dataReset(g_serverNumRegData.get());
    g_serverNumRegKey->setValue(g_serverNumKey, 0);
    g_serverNumRegData->setValue(g_serverNumValue, (uint64_t)serverNumber);

    UINT32 status = PCLNDN_UpdateTableOneEntry(PCL_NDN_ENTRY_ADD_MOD, g_serverNumReg, *g_serverNumRegKey, *g_serverNumRegData);
    return status;
}

/*********************************************************************
 * Function: Table entry initialization
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_InitTableEntry()
{
    g_pclndnMngInfo.serverNumber = PCL_MAX_DEFAULT_SERVER;
    PCLNDN_UpdateServerNumEntry(PCL_MAX_DEFAULT_SERVER);

    g_session->verifyTransaction();
    g_session->sessionCompleteOperations();
    g_session->commitTransaction(true);
}

/*********************************************************************
 * Function: Get name and port info from the fib-xxx command line
 * Input: argName: command line name
 *       argValue: command line value
 *       ndnName: name info
 *       fibInfo: FIB temporary info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_GetPortFormPortBitmapOpArgs(string argName, string argValue, PclNdnPortBitmapInfo &portBitInfo)
{
    if (argName == "port") {
        UINT32 portId = strtoul(argValue.c_str(), 0, 0);
        portBitInfo.portId = portId;
        portBitInfo.showType = PCL_NDN_PORT_BITMAP_SHOW_PORT;
        return PCL_OK;
    }
    bfshell_printf(portBitInfo.clishContext, "Error: not support argument: %s now\n", argName.c_str());
    return PCL_ERROR;
}

/*********************************************************************
 * Function: Get name and port info from the fib-xxx command line
 * Input: cmdInfo: command line info
 *       portBitInfo: port-bitmap info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_GetPortFormPortBitmapOpCmd(const PclNdnCmdInfo *cmdInfo, PclNdnPortBitmapInfo &portBitInfo)
{
    UINT32 ret = PCL_OK;
    for (UINT32 i = 0; i < cmdInfo->argNum; i++) {
        ret = PCLNDN_GetPortFormPortBitmapOpArgs(cmdInfo->argNames[i], cmdInfo->argValues[i], portBitInfo);
        if (ret != PCL_OK) {
            return PCL_ERROR;
        }
    }
    return PCL_OK;
}

/*********************************************************************
 * Function: Show all $pre-node entries
 * Input: nodeInfo: node info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPreNodeEntry(PclMultiGroupCmdInfo &nodeInfo, UINT32 index, UINT8 hideAttr)
{
    PclNdnTableFiledShowInfo showInfo = {0};

    /* Initialize arguments */
    showInfo.index = index;
    showInfo.hideAttr = hideAttr;
    showInfo.clishContext = nodeInfo.clishContext;
    g_preNodeTable->keyReset(g_preNodeTableKey.get());
    g_preNodeTable->dataReset(g_preNodeTableData.get());
    showInfo.tcamTable = (bfrt::BfRtTable*)g_preNodeTable;

    /* configure Key */
    g_preNodeTableKey->setValue(g_preNodeKeyNodeId, (uint64_t)nodeInfo.bitmask);

    /* configure key-value arguments */
    showInfo.tableKey = g_preNodeTableKey.get();
    showInfo.tableData = g_preNodeTableData.get();

    /* call public show */
    PCLNDN_ShowTableOneEntry(showInfo, PCL_FALSE, 0);
}
/*********************************************************************
 * Function: Show all $pre-mgid entries
 * Input: groupInfo: group info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPreMgidEntry(PclMultiGroupCmdInfo &groupInfo, UINT32 index, UINT8 hideAttr)
{
    PclNdnTableFiledShowInfo showInfo = {0};

    /* Initialize arguments */
    showInfo.index = index;
    showInfo.hideAttr = hideAttr;
    showInfo.clishContext = groupInfo.clishContext;
    g_preMgidTable->keyReset(g_preMgidTableKey.get());
    g_preMgidTable->dataReset(g_preMgidTableData.get());
    showInfo.tcamTable = (bfrt::BfRtTable*)g_preMgidTable;

    /* configure key */
    g_preMgidTableKey->setValue(g_preNodeKeyNodeId, (uint64_t)groupInfo.bitmask);

    /* configure key-value arguments */
    showInfo.tableKey = g_preMgidTableKey.get();
    showInfo.tableData = g_preMgidTableData.get();

    /* call public show */
    PCLNDN_ShowTableOneEntry(showInfo, PCL_FALSE, 0);
}

/*********************************************************************
 * Function: Show the fingerprint register 1 of PIT
 * Input: pitInfo: PIT control info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPitFingerReg1Entry(PclNdnPitInfo &pitInfo)
{
    PclNdnTableFiledShowInfo showInfo = {0};

    /* Initialize arguments */
    showInfo.clishContext = pitInfo.clishContext;
    showInfo.tcamTable = (bfrt::BfRtTable*)g_pitFinger1Reg;
    g_pitFinger1Reg->keyReset(g_pitFinger1RegKey.get());
    g_pitFinger1Reg->dataReset(g_pitFinger1RegData.get());
    /* configure key */
    g_pitFinger1RegKey->setValue(g_pitFinger1Key, (uint64_t)pitInfo.index);
    /* configure key-value arguments */
    showInfo.tableKey = g_pitFinger1RegKey.get();
    showInfo.tableData = g_pitFinger1RegData.get();

    PCLNDN_ShowTableOneEntry(showInfo, PCL_FALSE, 0);
}
/*********************************************************************
 * Function: Show the fingerprint register 2 of PIT
 * Input: pitInfo: PIT control info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPitFingerReg2Entry(PclNdnPitInfo &pitInfo)
{
    PclNdnTableFiledShowInfo showInfo = {0};

    /* Initialize arguments */
    showInfo.clishContext = pitInfo.clishContext;
    showInfo.tcamTable = (bfrt::BfRtTable*)g_pitFinger2Reg;
    g_pitFinger2Reg->keyReset(g_pitFinger2RegKey.get());
    g_pitFinger2Reg->dataReset(g_pitFinger2RegData.get());
    /* configure key */
    g_pitFinger2RegKey->setValue(g_pitFinger2Key, (uint64_t)pitInfo.index);
    /* configure key-value arguments */
    showInfo.tableKey = g_pitFinger2RegKey.get();
    showInfo.tableData = g_pitFinger2RegData.get();

    PCLNDN_ShowTableOneEntry(showInfo, PCL_FALSE, 0);
}
/*********************************************************************
 * Function: Show the port-bitmap register 1 of PIT
 * Input: pitInfo: PIT control info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPitPortReg1Entry(PclNdnPitInfo &pitInfo)
{
    PclNdnTableFiledShowInfo showInfo = {0};

    /* Initialize arguments */
    showInfo.clishContext = pitInfo.clishContext;
    showInfo.tcamTable = (bfrt::BfRtTable*)g_pitPort1Reg;
    g_pitPort1Reg->keyReset(g_pitPort1RegKey.get());
    g_pitPort1Reg->dataReset(g_pitPort1RegData.get());
    /* configure key */
    g_pitPort1RegKey->setValue(g_pitPort1Key, (uint64_t)pitInfo.index);
    /* configure key-value arguments */
    showInfo.tableKey = g_pitPort1RegKey.get();
    showInfo.tableData = g_pitPort1RegData.get();

    PCLNDN_ShowTableOneEntry(showInfo, PCL_FALSE, 0);
}
/*********************************************************************
 * Function: Show the port-bitmap register 2 of PIT
 * Input: pitInfo: PIT control info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPitPortReg2Entry(PclNdnPitInfo &pitInfo)
{
    PclNdnTableFiledShowInfo showInfo = {0};

    /* Initialize arguments */
    showInfo.clishContext = pitInfo.clishContext;
    showInfo.tcamTable = (bfrt::BfRtTable*)g_pitPort2Reg;
    g_pitPort2Reg->keyReset(g_pitPort2RegKey.get());
    g_pitPort2Reg->dataReset(g_pitPort2RegData.get());
    /* configure key */
    g_pitPort2RegKey->setValue(g_pitPort2Key, (uint64_t)pitInfo.index);
    /* configure key-value arguments */
    showInfo.tableKey = g_pitPort2RegKey.get();
    showInfo.tableData = g_pitPort2RegData.get();

    PCLNDN_ShowTableOneEntry(showInfo, PCL_FALSE, 0);
}

/*********************************************************************
 * Function: Show the fingerprint info of PIT
 * Input: pitInfo: PIT control info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPitFingerRegEntry(PclNdnPitInfo &pitInfo)
{
    switch (pitInfo.regType) {
        case PCL_NDN_PIT_SHOW_ALL:
            PCLNDN_ShowPitFingerReg1Entry(pitInfo);
            PCLNDN_ShowPitFingerReg2Entry(pitInfo);
            break;
        case PCL_NDN_PIT_SHOW_REG1:
            PCLNDN_ShowPitFingerReg1Entry(pitInfo);
            break;
        case PCL_NDN_PIT_SHOW_REG2:
            PCLNDN_ShowPitFingerReg2Entry(pitInfo);
            break;
        default:
            bfshell_printf(pitInfo.clishContext, "Error: not support this command now\n");
            break;
    }
}

/*********************************************************************
 * Function: Show the port-bitmap info of PIT
 * Input: pitInfo: PIT control info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPitPortRegEntry(PclNdnPitInfo &pitInfo)
{
    switch (pitInfo.regType) {
        case PCL_NDN_PIT_SHOW_ALL:
            PCLNDN_ShowPitPortReg1Entry(pitInfo);
            PCLNDN_ShowPitPortReg2Entry(pitInfo);
            break;
        case PCL_NDN_PIT_SHOW_REG1:
            PCLNDN_ShowPitPortReg1Entry(pitInfo);
            break;
        case PCL_NDN_PIT_SHOW_REG2:
            PCLNDN_ShowPitPortReg2Entry(pitInfo);
            break;
        default:
            bfshell_printf(pitInfo.clishContext, "Error: not support this command now\n");
            break;
    }
}

/*********************************************************************
 * Function: Get relevant info from the pcct xxx command line
 * Input: type: type
 *       argValue: argument value
 * Output: pitInfo: PIT control info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdatePcctCmdInfo(UINT32 type, const char* argValue, PclNdnPitInfo &pitInfo)
{
    switch(type) {
        case PCCT_CMD_ARG_NAME:
            pitInfo.ndnName = argValue;
            break;
        case PCCT_CMD_ARG_INDEX:
            pitInfo.index = strtoul(argValue, 0, 0);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: Get info from the pcct xxx command line
 * Input: argName: command line name
 *       pitInfo: PIT control info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCL_GetPcctCmdArgType(string argName, PclNdnPitInfo &pitInfo)
{
    if (argName == "show") {
        pitInfo.subCmd = PCL_NDN_ENTRY_SHOW;
        return PCCT_CMD_ARG_SKIP;
    }
    if (argName == "ndn_name") {
        return PCCT_CMD_ARG_NAME;
    }
    if (argName == "index") {
        return PCCT_CMD_ARG_INDEX;
    }
    
    if ((argName == "finger") || (argName == "finger-regs")) {
        pitInfo.tableType = PCL_NDN_PIT_TABLE_FINGER;
        return PCCT_CMD_ARG_SKIP;
    }
    if ((argName == "port-bitmap") || (argName == "port-regs")) {
        pitInfo.tableType = PCL_NDN_PIT_TABLE_PORT;
        return PCCT_CMD_ARG_SKIP;
    }
    if ((argName == "finger1") || (argName == "bitmap1")) {
        pitInfo.regType = PCL_NDN_PIT_SHOW_REG1;
        return PCCT_CMD_ARG_SKIP;
    }
    if ((argName == "finger2") || (argName == "bitmap2")) {
        pitInfo.regType = PCL_NDN_PIT_SHOW_REG2;
        return PCCT_CMD_ARG_SKIP;
    }

    if (argName == "type") {
        return PCCT_CMD_ARG_SKIP;
    }
    if (argName == "ndn") {
        return PCCT_CMD_ARG_SKIP;
    }
    if (argName =="index-choice") {
        return PCCT_CMD_ARG_SKIP;
    }
    if (argName == "pit-tables") {
        return PCCT_CMD_ARG_SKIP;
    }
    bfshell_printf(pitInfo.clishContext, "Error: can not process arg:%s\n", argName.c_str());
    return PCCT_CMD_ARG_BUT;
}

/*********************************************************************
 * Function: Get info from the pcct xxx command line
 * Input: cmdInfo: command line info
 *       pitInfo: PIT control info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_GetPcctInfoFromCmd(const PclNdnCmdInfo *cmdInfo, PclNdnPitInfo &pitInfo)
{
    UINT32 type = 0;
    pitInfo.clishContext = cmdInfo->clishContext;
    for (UINT32 index = 0; index < cmdInfo->argNum; index++) {
        type = PCL_GetPcctCmdArgType(cmdInfo->argNames[index], pitInfo);
        PCL_UpdatePcctCmdInfo(type, cmdInfo->argValues[index], pitInfo);
    }
}

/*********************************************************************
 * Function: Get info about the name field
 * Input: ndnName: original name info
 * Output: nameInfo: name info
 * Return: OK: success, others: failure
 * *******************************************************************/
UINT32 PCLNDN_GetNameLableInfo(string &ndnName, PclNdnNameInfo &nameInfo)
{
    UINT32 nums = 0;
    UINT32 lens = 0;
    char* sepStart = strtok((char*)ndnName.c_str(), PCL_NDN_PATH_SEPRATOR);
    while (sepStart != NULL) {
        lens = strlen(sepStart);
        if (lens > PCL_NDN_NAME_LEN_PER_LABLE) {
            printf("Error: name lable:%s, length:%u is not support now.\n", sepStart, lens);
            return PCL_ERROR;
        }
        nameInfo.lableLength[nums] = lens;
        memcpy(nameInfo.lableNames[nums], sepStart, lens);
        nums++;
        if (nums >= PCL_NDN_MAX_NAME_LABLE) {
            break;
        }
        sepStart = strtok(NULL, PCL_NDN_PATH_SEPRATOR);
    }
    nameInfo.labelNum = nums;
    return PCL_OK;
}

/*********************************************************************
 * Function:    Synthesize the data info 
 *              involved in the calculation based on the name length
 * Input: name: name
 *      length: length 
 * Output: lable: name component involved in the calculation
 * Return: OK: success, others: failure
 * *******************************************************************/
VOID PCL_SetNameLableInfo(char* lable, const char* name, UINT32 length)
{
    UINT32 mask = 0;
    UINT32 start = 0;
    const char* temp = name;

    for (UINT32 index = 0; index < PCL_NDN_MAX_NAME_LABLE; index++) {
        mask = SHIFT_LEFT_BITS(index);
        if (mask & length) {
            start = mask - 1;
            memcpy(&lable[start], temp, mask);
            temp += mask;
        }
    }
}
/*********************************************************************
 * Function: calculate fingerprint hash
 * Input: nameInfo: name info
 * Output: None
 * Return: OK: success, others: failure
 * *******************************************************************/
UINT32 PCLNDN_CalcNameFingerprint(PclNdnNameInfo &nameInfo)
{
    UINT8 nameBuf[PCL_NDN_NAME_BUF_LEN] = {0};
    UINT32 length = 0;
    UINT32 hashCrc = 0;
    UINT8 *crcResult = (UINT8*)&hashCrc;
    char* lable = (char*)nameBuf;

    nameInfo.hashResult = 0;
    for (UINT32 index = 0; index < nameInfo.labelNum; index++) {
        PCL_SetNameLableInfo(lable, nameInfo.lableNames[index], nameInfo.lableLength[index]);
        lable += PCL_NDN_NAME_LEN_PER_LABLE;
        length += PCL_NDN_NAME_LEN_PER_LABLE;
    }

    nameInfo.hashLength = length;
    calculate_crc(&g_fingerHashAlgorithm, 32, nameBuf, length, crcResult);
    /* Convert byte order and save */
    nameInfo.hashResult = htonl(hashCrc);
    return PCL_OK;
}
/*********************************************************************
 * Function: Calculate fingerprint related info
 * Input: pitInfo: pcct info
 * Output: None
 * Return: OK: success, others: failure
 * *******************************************************************/
UINT32 PCLNDN_GetUpdatePitIndexWithName(PclNdnPitInfo &pitInfo)
{
    if (pitInfo.ndnName == "") {
        return PCL_OK;
    }
    PclNdnNameInfo nameInfo = {0};
    string tempName = pitInfo.ndnName;

    PCLNDN_InitFibHashAlgorithm();
    /* parse name filed */
    if (PCLNDN_GetNameLableInfo(tempName, nameInfo) != PCL_OK) {
        bfshell_printf(pitInfo.clishContext, "Error: get name lable failed for: %s\n", pitInfo.ndnName.c_str());
        return PCL_ERROR;
    }
    /* calculate fingerprint */
    if (PCLNDN_CalcNameFingerprint(nameInfo) != PCL_OK) {
        bfshell_printf(pitInfo.clishContext, "Error: calc name hash failed for: %s\n", pitInfo.ndnName.c_str());
        return PCL_ERROR;
    }
    pitInfo.index = nameInfo.hashResult & g_regKeyMask;
    bfshell_printf(pitInfo.clishContext, "Info: ndn name: %s will use register index:0x%x.\n", pitInfo.ndnName.c_str(), pitInfo.index);

    return PCL_OK;
}
/*********************************************************************
 * Function: pcct show command line processing
 * Input: cmdInfo: command line info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCL_ProcPcctShowCmd(PclNdnPitInfo &pitInfo)
{
    UINT32 ret = PCL_OK;

    /* calculate index */
    ret = PCLNDN_GetUpdatePitIndexWithName(pitInfo);
    if (ret != PCL_OK) {
        return PCL_ERROR;
    }
    /* show by type */
    switch (pitInfo.tableType) {
        case PCL_NDN_PIT_TABLE_ALL:
            PCLNDN_ShowPitFingerRegEntry(pitInfo);
            PCLNDN_ShowPitPortRegEntry(pitInfo);
            break;
        case PCL_NDN_PIT_TABLE_FINGER:
            PCLNDN_ShowPitFingerRegEntry(pitInfo);
            break;
        case PCL_NDN_PIT_TABLE_PORT:
            PCLNDN_ShowPitPortRegEntry(pitInfo);
            break;
        default:
            bfshell_printf(pitInfo.clishContext, "Error: not support this command now\n");
            break;
    }
    return PCL_OK;
}

/*********************************************************************
 * Function: pcct xxx command line processing
 * Input: cmdInfo: command line info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_ProcPcctCmd(const PclNdnCmdInfo *cmdInfo)
{
    PclNdnPitInfo pitInfo = {0};

    pitInfo.ndnName = "";
    pitInfo.clishContext = cmdInfo->clishContext;
    /* Assign info from the command to temporary info */
    PCL_GetPcctInfoFromCmd(cmdInfo, pitInfo);

    switch (pitInfo.subCmd) {
        case PCL_NDN_ENTRY_SHOW:
            PCL_ProcPcctShowCmd(pitInfo);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: Get mac address from command line
 * Input: argValue: argument value
 * Output: macAddr: mac address
 * Return: None
 * *******************************************************************/
UINT32 PCL_UpdateCmdMacAddr(const char* argValue, UINT8 *macAddr)
{
    UINT32 value = 0;
    UINT8 buffer[4] = { 0 };
    UINT32 index = 0;
    UINT32 count = 0;
    const char* temp = argValue;

    while (*temp != 0) {
        if (*temp == ':') {
            value = strtoul((const char*)buffer, 0, 16);
            if ((count != 2) || (value > 255)) {
                return PCL_ERROR;
            }
            macAddr[index] = (UINT8)value;
            index++;
            count = 0;
        } else {
            buffer[count] = *temp;
            count++;
            if (count > 2) {
                return PCL_ERROR;
            }
        }
        temp++;
    }
    if (count == 2) {
        value = strtoul((const char*)buffer, 0, 16);
        macAddr[index] = (UINT8)value;
        index++;
        count = 0;
    }
    if (index != PCL_MAC_ADDR_LEN) {
        return PCL_ERROR;
    }
    return PCL_OK;
}

/*********************************************************************
 * Function: Get the server number from the mac xxx command line
 * Input: argValue: argument value
 * Output: serverCmdInfo: server related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateMacServerNumberInfo(const char* argValue, PclMacTransCmdInfo &macCmdInfo)
{
    UINT32 number = strtoul(argValue, 0, 0);

    if (number >= PCL_MAX_SERVER_NUM) {
        bfshell_printf(macCmdInfo.clishContext, "Error: server number %u is bigger than max: %u\n", number, PCL_MAX_SERVER_NUM);
        macCmdInfo.parseResult = SHIFT_LEFT_BITS(MAC_CMD_ARG_SERVER);
        return;
    }
    if (number > g_pclndnMngInfo.serverNumber) {
        bfshell_printf(macCmdInfo.clishContext, "Warning: server index %u is over current config %u, will not be used.\n", number, g_pclndnMngInfo.serverNumber);
    }
    macCmdInfo.serverIndex = (UINT8)number;
}
/*********************************************************************
 * Function: Get the dest MAC address info from the mac xxx command line
 * Input: argValue: argument value
 * Output: macCmdInfo: mac related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateMacAddrInfo(const char* argValue, PclMacTransCmdInfo &macCmdInfo)
{
    UINT32 ret = PCL_OK;
    UINT8 dstMac[PCL_MAC_ADDR_LEN] = {0};
    UINT64 macAddress = 0;

    ret = PCL_UpdateCmdMacAddr(argValue, dstMac);
    if (ret != PCL_OK) {
        bfshell_printf(macCmdInfo.clishContext, "Error: invalid mac address: %s\n", argValue);
        macCmdInfo.parseResult = SHIFT_LEFT_BITS(MAC_CMD_ARG_MAC_ADDR);
        return;
    }
    for (UINT32 index = 0; index < PCL_MAC_ADDR_LEN; index++) {
        macAddress = (macAddress << BYTE_BITS) + dstMac[index];
    }
    macCmdInfo.dmacAddr = macAddress;
    macCmdInfo.dstMacStr = argValue;
    //bfshell_printf(macCmdInfo->clishContext, "Info: mac address trans to %llu\n", macCmdInfo->dmacAddr);
}

/*********************************************************************
 * Function: Get the outport from the mac xxx command line
 * Input: argValue: argument value
 * Output: macCmdInfo: mac related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateMacOutPortInfo(const char* argValue, PclMacTransCmdInfo &macCmdInfo)
{
    bf_status_t status;
    bf_pal_front_port_handle_t portHandle;
    bf_dev_port_t portDevId = 0;
    bool isInternalPort = false;
    UINT32 mapKey = 0;

    status = bf_pm_port_str_to_hdl_get(g_dev_target.dev_id, argValue, &portHandle);
    if (status != BF_SUCCESS) {
        bfshell_printf(macCmdInfo.clishContext, "Error: port %s is not exist\n", argValue);
        macCmdInfo.parseResult = SHIFT_LEFT_BITS(MAC_CMD_ARG_PORTID);
        return;
    }

    bf_pm_is_port_internal(g_dev_target.dev_id, &portHandle, &isInternalPort);
    if (isInternalPort) {
        bfshell_printf(macCmdInfo.clishContext, "Error: port %s is internal port\n", argValue);
        macCmdInfo.parseResult = SHIFT_LEFT_BITS(MAC_CMD_ARG_PORTID);
        return;
    }
    
    mapKey = (portHandle.conn_id << UINT16_BITS) + portHandle.chnl_id;
    if (g_mapPortMngInfo.find(mapKey) == g_mapPortMngInfo.end()) {
        bfshell_printf(macCmdInfo.clishContext, "Error: port %s has not exsit\n", argValue);
        macCmdInfo.parseResult = SHIFT_LEFT_BITS(MAC_CMD_ARG_PORTID);
        return;
    }
    PclPortMngInfo &portInfo = g_mapPortMngInfo[mapKey];
    if (portInfo.used != PCL_TRUE) {
        bfshell_printf(macCmdInfo.clishContext, "Error: port %s has not exsit\n", argValue);
        macCmdInfo.parseResult = SHIFT_LEFT_BITS(MAC_CMD_ARG_PORTID);
        return;
    }
    macCmdInfo.outport = portInfo.portDevId;
}
/*********************************************************************
 * Function: Get related info from the mac xxx command line
 * Input: type: type
 *       argValue: argument value
 * Output: macCmdInfo: mac related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateMacCmdInfo(UINT32 type, const char* argValue, PclMacTransCmdInfo &macCmdInfo)
{
    switch(type) {
        case MAC_CMD_ARG_SERVER:
            PCL_UpdateMacServerNumberInfo(argValue, macCmdInfo);
            break;
        case MAC_CMD_ARG_MAC_ADDR:
            PCL_UpdateMacAddrInfo(argValue, macCmdInfo);
            break;
        case MAC_CMD_ARG_PORTID:
            PCL_UpdateMacOutPortInfo(argValue, macCmdInfo);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: Get the argument type from the mac xxx command line
 * Input: argName: argument name
 *       macCmdInfo: mac related info
 * Output: None
 * Return: argument type
 * *******************************************************************/
UINT32 PCL_GetMacCmdArgType(const char *argName, PclMacTransCmdInfo &macCmdInfo)
{
    if (strcmp(argName, "add") == 0) {
        macCmdInfo.subCmd = PCL_NDN_ENTRY_ADD_ONLY;
        return MAC_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "mod") == 0) {
        macCmdInfo.subCmd = PCL_NDN_ENTRY_ADD_MOD;
        return MAC_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "del") == 0) {
        macCmdInfo.subCmd = PCL_NDN_ENTRY_DEL;
        return MAC_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "show") == 0) {
        macCmdInfo.subCmd = PCL_NDN_ENTRY_SHOW;
        return MAC_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "server") == 0) {
        return MAC_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "serverindex") == 0) {
        macCmdInfo.subkey = MAC_SUBKEY_SERVER;
        return MAC_CMD_ARG_SERVER;
    }
    if (strcmp(argName, "dmac") == 0) {
        return MAC_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "macaddr") == 0) {
        macCmdInfo.subkey = MAC_SUBKEY_DMAC;
        return MAC_CMD_ARG_MAC_ADDR;
    }
    if (strcmp(argName, "port") == 0) {
        return MAC_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "portid") == 0) {
        return MAC_CMD_ARG_PORTID;
    }
    if (strcmp(argName, "type") == 0) {
        return MAC_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "key") == 0) {
        return MAC_CMD_ARG_SKIP;
    }
    bfshell_printf(macCmdInfo.clishContext, "Error: can not process arg:%s\n", argName);
    return MAC_CMD_ARG_BUT;
}
/*********************************************************************
 * Function: Get the related info from the mac xxx command line
 * Input: cmdInfo: command related info pointer
 * Output: macCmdInfo: mac related info
 * Return: None
 * *******************************************************************/
VOID PCL_GetMacInfoFromCmd(const PclNdnCmdInfo *cmdInfo, PclMacTransCmdInfo &macCmdInfo)
{
    UINT32 type = 0;
    macCmdInfo.clishContext = cmdInfo->clishContext;
    for (UINT32 index = 0; index < cmdInfo->argNum; index++) {
        type = PCL_GetMacCmdArgType(cmdInfo->argNames[index], macCmdInfo);
        PCL_UpdateMacCmdInfo(type, cmdInfo->argValues[index], macCmdInfo);
    }
}
/*********************************************************************
 * Function: Update processing from mac table entry
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCL_UpdateMacTranEntry(PclMacTransCmdInfo &macCmdInfo)
{
    /* Initialize arguments */
    g_toServerTable->keyReset(g_toServerTableKey.get());

    /* configure key */
    g_toServerTableKey->setValue(g_toServerKey, macCmdInfo.dmacAddr);
    g_toServerTableKey->setValue(g_macTblKeySerIndex, (uint64_t)macCmdInfo.serverIndex);

    /* configure value */
    if (macCmdInfo.subCmd != PCL_NDN_ENTRY_DEL) {
        g_toServerTable->dataReset(g_toServerActionId, g_toServerTableData.get());
        g_toServerTableData->setValue(g_toServerValue, (uint64_t)macCmdInfo.outport);
    }
    if (macCmdInfo.clishContext == NULL) {
        printf("Info: will add/mod/del(0:add,1:mod or add,2:del, current:%u) mac transform entry for key:%u-%s(%#llx), port:%u\n",
            macCmdInfo.subCmd, macCmdInfo.serverIndex, macCmdInfo.dstMacStr.c_str(), macCmdInfo.dmacAddr, macCmdInfo.outport);
    } else {
        bfshell_printf(macCmdInfo.clishContext, "Info: will add/mod/del(0:add,1:mod or add,2:del, current:%u) mac transform entry for key:%u-%s(%#llx), port:%u\n",
            macCmdInfo.subCmd, macCmdInfo.serverIndex, macCmdInfo.dstMacStr.c_str(), macCmdInfo.dmacAddr, macCmdInfo.outport);
    }

    /* update operation */
    UINT32 status = PCLNDN_UpdateTableOneEntry((PclNdnEntryOpType)macCmdInfo.subCmd, g_toServerTable, *g_toServerTableKey, *g_toServerTableData);
    PCLNDN_CommonShowCmdRunResult(status, macCmdInfo.clishContext);
    return status;
}

/*********************************************************************
 * Function: Configuring processing from the mac add command line
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_AddMacTranConfig(PclMacTransCmdInfo &macCmdInfo)
{
    if (g_macMacTranInfo.find(macCmdInfo.serverIndex) != g_macMacTranInfo.end()) {
        if (g_macMacTranInfo[macCmdInfo.serverIndex].find(macCmdInfo.dmacAddr) != g_macMacTranInfo[macCmdInfo.serverIndex].end()) {
            bfshell_printf(macCmdInfo.clishContext, "Info: key:%u-%s(%#llx) has already been added, please use mod or del to change.\n",
                macCmdInfo.serverIndex, macCmdInfo.dstMacStr.c_str(), macCmdInfo.dmacAddr);
            return;
        }
    }
    UINT32 status = PCL_UpdateMacTranEntry(macCmdInfo);
    if (status != PCL_OK) {
        return;
    }
    PclMacTransInfo newMac = {0};
    newMac.dmacAddr = macCmdInfo.dmacAddr;
    newMac.serverIndex = macCmdInfo.serverIndex;
    newMac.outport = macCmdInfo.outport;

    if (g_macMacTranInfo.find(macCmdInfo.serverIndex) != g_macMacTranInfo.end()) {
        g_macMacTranInfo[macCmdInfo.serverIndex][macCmdInfo.dmacAddr] = newMac;
    } else {
        map<UINT64, PclMacTransInfo> newMap;
        newMap[macCmdInfo.dmacAddr] = newMac;
        g_macMacTranInfo[macCmdInfo.serverIndex] = newMap;
    }
}

/*********************************************************************
 * Function: Configuring processing from the mac mod command line
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ModMacTranConfig(PclMacTransCmdInfo &macCmdInfo)
{
    if (g_macMacTranInfo.find(macCmdInfo.serverIndex) == g_macMacTranInfo.end()) {
        bfshell_printf(macCmdInfo.clishContext, "Info: server:%u  has not been added, please add first.\n", macCmdInfo.serverIndex);
        return;
    }
    if (g_macMacTranInfo[macCmdInfo.serverIndex].find(macCmdInfo.dmacAddr) == g_macMacTranInfo[macCmdInfo.serverIndex].end()) {
        bfshell_printf(macCmdInfo.clishContext, "Info: server:%u, mac%s(%#llx) has not been added, please add first.\n",
            macCmdInfo.serverIndex, macCmdInfo.dstMacStr.c_str(), macCmdInfo.dmacAddr);
        return;
    }
    PclMacTransInfo &macInfo = g_macMacTranInfo[macCmdInfo.serverIndex][macCmdInfo.dmacAddr];
    if (macInfo.outport == macCmdInfo.outport) {
        bfshell_printf(macCmdInfo.clishContext, "Info: server:%u, mac%s(%#llx) with not %u is the same with current, no need to change.\n",
            macCmdInfo.serverIndex, macCmdInfo.dstMacStr.c_str(), macCmdInfo.dmacAddr, macCmdInfo.outport);
        return;
    }
    UINT32 status = PCL_UpdateMacTranEntry(macCmdInfo);
    if (status != PCL_OK) {
        return;
    }
    macInfo.outport = macCmdInfo.outport;
}

/*********************************************************************
 * Function: Configuring processing from the mac del command line
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_DelMacTranConfig(PclMacTransCmdInfo &macCmdInfo)
{
    if (g_macMacTranInfo.find(macCmdInfo.serverIndex) == g_macMacTranInfo.end()) {
        bfshell_printf(macCmdInfo.clishContext, "Info: server:%u  has not been added, nothing to change.\n", macCmdInfo.serverIndex);
        return;
    }
    if (g_macMacTranInfo[macCmdInfo.serverIndex].find(macCmdInfo.dmacAddr) == g_macMacTranInfo[macCmdInfo.serverIndex].end()) {
        bfshell_printf(macCmdInfo.clishContext, "Info: server:%u, mac%s(%#llx) has not been added, nothing to change.\n",
            macCmdInfo.serverIndex, macCmdInfo.dstMacStr.c_str(), macCmdInfo.dmacAddr);
        return;
    }
    UINT32 status = PCL_UpdateMacTranEntry(macCmdInfo);
    if (status != PCL_OK) {
        return;
    }
    g_macMacTranInfo[macCmdInfo.serverIndex].erase(macCmdInfo.dmacAddr);
    if (g_macMacTranInfo[macCmdInfo.serverIndex].size() == 0) {
        g_macMacTranInfo.erase(macCmdInfo.serverIndex);
    }
}
/*********************************************************************
 * Function: Configuring processing from the mac xxx command line
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ProcMacTranConfigCmd(PclMacTransCmdInfo &macCmdInfo)
{
    switch (macCmdInfo.subCmd) {
        case PCL_NDN_ENTRY_ADD_ONLY:
            PCL_AddMacTranConfig(macCmdInfo);
            break;
        case PCL_NDN_ENTRY_ADD_MOD:
            PCL_ModMacTranConfig(macCmdInfo);
            break;
        case PCL_NDN_ENTRY_DEL:
            PCL_DelMacTranConfig(macCmdInfo);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: Show all entries sent to the server based on MAC
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowAllMacToServerEntry(PclMacTransCmdInfo &macCmdInfo)
{
    bfshell_printf(macCmdInfo.clishContext, "Mac entry info:\n");
    PCLNDN_CommonShowTcamTableInfo(g_toServerTable, PCL_TRUE, g_toServerActionId, macCmdInfo.clishContext);
}

/*********************************************************************
 * Function: Show the entries sent to the server based on MAC
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowMacToServerEntry(PclMacTransCmdInfo &macCmdInfo, UINT32 index, UINT8 hideAttr)
{
    PclNdnTableFiledShowInfo showInfo = {0};

    /* Initialize arguments */
    showInfo.index = index;
    showInfo.hideAttr = hideAttr;
    showInfo.clishContext = macCmdInfo.clishContext;
    g_toServerTable->keyReset(g_toServerTableKey.get());
    g_toServerTable->dataReset(g_toServerActionId, g_toServerTableData.get());
    showInfo.tcamTable = (bfrt::BfRtTable*)g_toServerTable;

    /* configure key */
    g_toServerTableKey->setValue(g_toServerKey, macCmdInfo.dmacAddr);
    g_toServerTableKey->setValue(g_macTblKeySerIndex, (uint64_t)macCmdInfo.serverIndex);

    /* configure key-value arguments */
    showInfo.tableKey = g_toServerTableKey.get();
    showInfo.tableData = g_toServerTableData.get();
    PCLNDN_ShowTableOneEntry(showInfo, PCL_TRUE, g_toServerActionId);
}


/*********************************************************************
 * Function: Show the entries sent to the server based on MAC
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowMacEntryWithServer(PclMacTransCmdInfo &macCmdInfo)
{
    UINT32 index = 1;
    UINT8 hideAttr = PCL_FALSE;
    UINT8 showAttr = PCL_FALSE;
    map<UINT64, PclMacTransInfo>::iterator it;

    if (g_macMacTranInfo.find(macCmdInfo.serverIndex) == g_macMacTranInfo.end()) {
        return;
    }
    if (g_macMacTranInfo[macCmdInfo.serverIndex].size() == 0) {
        return;
    }
    bfshell_printf(macCmdInfo.clishContext, "Mac table info:\n");
    map<UINT64, PclMacTransInfo> &macTranInfo = g_macMacTranInfo[macCmdInfo.serverIndex];
    it = macTranInfo.begin();
    while (it != macTranInfo.end()) {
        PclMacTransInfo &macInfo = it->second;
        macCmdInfo.serverIndex = macInfo.serverIndex;
        macCmdInfo.dmacAddr = macInfo.dmacAddr;
        if (showAttr == PCL_FALSE) {
            showAttr = PCL_TRUE;
            hideAttr = PCL_FALSE;
        } else {
            hideAttr = PCL_TRUE;
        }
        PCLNDN_ShowMacToServerEntry(macCmdInfo, index, hideAttr);
        it++;
        index++;
    }
}

/*********************************************************************
 * Function: Show info about a server from the mac show command line
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ShowOneServerMacTranConfig(PclMacTransCmdInfo &macCmdInfo, map<UINT64, PclMacTransInfo> &mapMacInfo)
{
    map<UINT64, PclMacTransInfo>::iterator it;

    it = mapMacInfo.begin();
    while (it != mapMacInfo.end()) {
        PclMacTransInfo &macInfo = it->second;
        bfshell_printf(macCmdInfo.clishContext, "| %6u | %#014llx | %4u |\n", macInfo.serverIndex, macInfo.dmacAddr, macInfo.outport);
        it++;
    }
}

/*********************************************************************
 * Function: Show info about a server from the mac show command line
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ShowServerMacTranConfig(PclMacTransCmdInfo &macCmdInfo)
{
    if (g_macMacTranInfo.find(macCmdInfo.serverIndex) == g_macMacTranInfo.end()) {
        bfshell_printf(macCmdInfo.clishContext, "Info: server:%u  has not been added.\n", macCmdInfo.serverIndex);
        return;
    }
    if (g_macMacTranInfo[macCmdInfo.serverIndex].size() == 0) {
        bfshell_printf(macCmdInfo.clishContext, "Info: server:%u  has not been added.\n", macCmdInfo.serverIndex);
        return;
    }
    bfshell_printf(macCmdInfo.clishContext, "Mac config info:\n");
    bfshell_printf(macCmdInfo.clishContext, "=====================================================================================\n");
    bfshell_printf(macCmdInfo.clishContext, "| Server |      Mac       | Port |\n");
    PCL_ShowOneServerMacTranConfig(macCmdInfo, g_macMacTranInfo[macCmdInfo.serverIndex]);
    bfshell_printf(macCmdInfo.clishContext, "=====================================================================================\n");
}

/*********************************************************************
 * Function: Show all info from the mac show command line
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ShowAllServerMacTranConfig(PclMacTransCmdInfo &macCmdInfo)
{
    map<UINT8, map<UINT64, PclMacTransInfo> >::iterator it;

    if (g_macMacTranInfo.size() == 0) {
        bfshell_printf(macCmdInfo.clishContext, "Info: no mac transfrom info has not been added.\n");
        return;
    }

    bfshell_printf(macCmdInfo.clishContext, "Mac config info:\n");
    bfshell_printf(macCmdInfo.clishContext, "=====================================================================================\n");
    bfshell_printf(macCmdInfo.clishContext, "| Server |      Mac       | Port |\n");
    it = g_macMacTranInfo.begin();
    while (it != g_macMacTranInfo.end()) {
        PCL_ShowOneServerMacTranConfig(macCmdInfo, it->second);
        it++;
    }
    bfshell_printf(macCmdInfo.clishContext, "=====================================================================================\n");
}

/*********************************************************************
 * Function: Configure processing from the mac xxx command line
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ShowMacTranConfig(PclMacTransCmdInfo &macCmdInfo)
{
    if (g_macMacTranInfo.find(macCmdInfo.serverIndex) == g_macMacTranInfo.end()) {
        bfshell_printf(macCmdInfo.clishContext, "Info: server:%u  has not been added.\n", macCmdInfo.serverIndex);
        return;
    }
    if (g_macMacTranInfo[macCmdInfo.serverIndex].find(macCmdInfo.dmacAddr) == g_macMacTranInfo[macCmdInfo.serverIndex].end()) {
        bfshell_printf(macCmdInfo.clishContext, "Info: server:%u, mac%s(%#llx) has not been added.\n",
            macCmdInfo.serverIndex, macCmdInfo.dstMacStr.c_str(), macCmdInfo.dmacAddr);
        return;
    }
    PclMacTransInfo &macInfo = g_macMacTranInfo[macCmdInfo.serverIndex][macCmdInfo.dmacAddr];
    bfshell_printf(macCmdInfo.clishContext, "Mac config info:\n");
    bfshell_printf(macCmdInfo.clishContext, "=====================================================================================\n");
    bfshell_printf(macCmdInfo.clishContext, "| Server |      Mac       | Port |\n");
    bfshell_printf(macCmdInfo.clishContext, "| %6u | %#014llx | %4u |\n",
        macInfo.serverIndex, macInfo.dmacAddr, macInfo.outport);
    bfshell_printf(macCmdInfo.clishContext, "=====================================================================================\n");
}

/*********************************************************************
 * Function: Show processing from mac xxx command line
 * Input: macCmdInfo: mac related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ProcMacTranShowCmd(PclMacTransCmdInfo &macCmdInfo)
{
    switch(macCmdInfo.subkey) {
        case MAC_SUBKEY_NONE:
            PCL_ShowAllServerMacTranConfig(macCmdInfo);
            PCLNDN_ShowAllMacToServerEntry(macCmdInfo);
            break;
        case MAC_SUBKEY_SERVER:
            PCL_ShowServerMacTranConfig(macCmdInfo);
            PCLNDN_ShowMacEntryWithServer(macCmdInfo);
            break;
        case MAC_SUBKEY_DMAC:
            PCL_ShowMacTranConfig(macCmdInfo);
            PCLNDN_ShowMacToServerEntry(macCmdInfo, 1, PCL_FALSE);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: mac xxx command line processing
 * Input: cmdInfo: command line info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_ProcMacCmd(const PclNdnCmdInfo *cmdInfo)
{
    PclMacTransCmdInfo macCmdInfo = {0};

    PCL_GetMacInfoFromCmd(cmdInfo, macCmdInfo);
    if (macCmdInfo.parseResult != PCL_OK) {
        return PCL_OK;
    }
    switch (macCmdInfo.subCmd) {
        case PCL_NDN_ENTRY_ADD_ONLY:
        case PCL_NDN_ENTRY_ADD_MOD:
        case PCL_NDN_ENTRY_DEL:
            PCL_ProcMacTranConfigCmd(macCmdInfo);
            break;
        case PCL_NDN_ENTRY_SHOW:
            PCL_ProcMacTranShowCmd(macCmdInfo);
            break;
        default:
            bfshell_printf(macCmdInfo.clishContext, "Error: not support now\n");
            break;
    }
    return PCL_OK;
}

/*********************************************************************
 * Function: Check from the bitmap add/mod command
 * Input: bitmapCmdInfo: bitmap related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
UINT32 PCL_CheckBitmapAddOrMod(PclBitmapCmdInfo &bitmapCmdInfo, UINT32 isAdd)
{
    map<UINT32, PclPortMngInfo>::iterator it;
    UINT32 mapKey = 0;

    if (bitmapCmdInfo.subkey != BITMAP_SUBKEY_PORT) {
        return PCL_OK;
    }
    mapKey = (bitmapCmdInfo.connId << UINT16_BITS) + bitmapCmdInfo.chnlId;
    if (g_mapPortMngInfo.find(mapKey) == g_mapPortMngInfo.end()) {
        bfshell_printf(bitmapCmdInfo.clishContext, "Error: port %u/%u has not exsit\n", bitmapCmdInfo.connId, bitmapCmdInfo.chnlId);
        return PCL_ERROR;
    }
    PclPortMngInfo &portInfo = g_mapPortMngInfo[mapKey];
    if (isAdd == PCL_TRUE) {
        if (portInfo.bitmapId != 0) {
            bfshell_printf(bitmapCmdInfo.clishContext, "Info: port %u/%u has already set the bitmap %u\n", bitmapCmdInfo.connId, bitmapCmdInfo.chnlId, portInfo.bitmapId);
            return PCL_ERROR;
        }
        if (portInfo.used != PCL_TRUE) {
            bfshell_printf(bitmapCmdInfo.clishContext, "Error: port %u/%u has not been added\n", bitmapCmdInfo.connId, bitmapCmdInfo.chnlId);
            return PCL_ERROR;
        }
    }
    UINT8 areaBase = portInfo.areaId * PCL_MAX_PORT_AREA_NUM;
    UINT8 shiftBits = portInfo.connId - areaBase - 1;
    bitmapCmdInfo.bitmapId = (portInfo.areaId << PCL_MAX_PORT_BITMAP_BITS) + SHIFT_LEFT_BITS(shiftBits);

    it = g_mapPortMngInfo.begin();
    while (it != g_mapPortMngInfo.end()) {
        PclPortMngInfo &current = it->second;
        if (current.bitmapId == bitmapCmdInfo.bitmapId) {
            bfshell_printf(bitmapCmdInfo.clishContext, "Error: port %u/%u has already set the bitmap %u\n", current.connId, current.chnlId, bitmapCmdInfo.bitmapId);
            return PCL_ERROR;
        }
        it++;
    }
    portInfo.bitmapId = bitmapCmdInfo.bitmapId;
    bfshell_printf(bitmapCmdInfo.clishContext, "Info: port %u/%u will set bitmap to value %u\n", bitmapCmdInfo.connId, bitmapCmdInfo.chnlId, portInfo.bitmapId);
    return PCL_OK;
}

/*********************************************************************
 * Function: Check from the bitmap del command
 * Input: bitmapCmdInfo: bitmap related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
UINT32 PCL_CheckBitmapDel(PclBitmapCmdInfo &bitmapCmdInfo)
{
    UINT32 mapKey = 0;

    if (bitmapCmdInfo.subkey != BITMAP_SUBKEY_PORT) {
        return PCL_OK;
    }
    mapKey = (bitmapCmdInfo.connId << UINT16_BITS) + bitmapCmdInfo.chnlId;
    if (g_mapPortMngInfo.find(mapKey) == g_mapPortMngInfo.end()) {
        bfshell_printf(bitmapCmdInfo.clishContext, "Error: port %u/%u has not exsit\n", bitmapCmdInfo.connId, bitmapCmdInfo.chnlId);
        return PCL_ERROR;
    }
    PclPortMngInfo &portInfo = g_mapPortMngInfo[mapKey];
    if (portInfo.used != PCL_TRUE) {
        bfshell_printf(bitmapCmdInfo.clishContext, "Info: port %u/%u has not been added\n", bitmapCmdInfo.connId, bitmapCmdInfo.chnlId);
        return PCL_ERROR;
    }
    if (portInfo.bitmapId == 0) {
        bfshell_printf(bitmapCmdInfo.clishContext, "Info: port %u/%u bitmap has not been set\n", bitmapCmdInfo.connId, bitmapCmdInfo.chnlId);
        return PCL_ERROR;
    }
    bfshell_printf(bitmapCmdInfo.clishContext, "Info: port %u/%u bitmap will be deleted\n", bitmapCmdInfo.connId, bitmapCmdInfo.chnlId);
    portInfo.bitmapId = 0;
    return PCL_OK;
}
/*********************************************************************
 * Function: Check from the bitmap add/mod/del command
 * Input: bitmapCmdInfo: bitmap related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
UINT32 PCL_CheckIfBitmapContinue(PclBitmapCmdInfo &bitmapCmdInfo)
{
    UINT32 status = PCL_ERROR;
    switch (bitmapCmdInfo.subCmd) {
        case PCL_NDN_ENTRY_ADD_ONLY:
            status = PCL_CheckBitmapAddOrMod(bitmapCmdInfo, PCL_TRUE);
            break;
        case PCL_NDN_ENTRY_ADD_MOD:
            status = PCL_CheckBitmapAddOrMod(bitmapCmdInfo, PCL_FALSE);
            break;
        case PCL_NDN_ENTRY_DEL:
            status = PCL_CheckBitmapDel(bitmapCmdInfo);
            break;
        default:
            bfshell_printf(bitmapCmdInfo.clishContext, "not support sub command:%u\n", bitmapCmdInfo.subCmd);
    }
    return status;
}

/*********************************************************************
 * Function: bitmap add/mod/del command line processing
 * Input: bitmapCmdInfo: bitmap related info
 *      areaId: group ID
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_BitmapConfigWithArea(PclBitmapCmdInfo &bitmapCmdInfo, UINT8 areaId)
{
    UINT32 status = PCL_ERROR;
    bf_pal_front_port_handle_t portHandle;
    UINT32 start = areaId * PCL_MAX_PORT_AREA_NUM;
    UINT32 end = start + PCL_MAX_PORT_AREA_NUM;
    UINT32 mapKey = 0;
    UINT8 shiftBits = 0;
    UINT8 groupBase = 0;

    portHandle.chnl_id = 0;
    for (UINT32 index = start; index < end; index++) {
        portHandle.conn_id = index + 1;
        mapKey = (portHandle.conn_id << UINT16_BITS) + portHandle.chnl_id;
        if (g_mapPortMngInfo.find(mapKey) != g_mapPortMngInfo.end()) {
            PclPortMngInfo &portInfo = g_mapPortMngInfo[mapKey];
            groupBase = portInfo.areaId * PCL_MAX_PORT_AREA_NUM;
            shiftBits = portInfo.connId - groupBase - 1;
            if (bitmapCmdInfo.subCmd != PCL_NDN_ENTRY_DEL) {
                portInfo.bitmapId = (portInfo.areaId << PCL_MAX_PORT_BITMAP_BITS) + SHIFT_LEFT_BITS(shiftBits);
            } else {
                portInfo.bitmapId = 0;
            }
            PCLNDN_UpdatePortBitmapEntry(portInfo.portDevId, portInfo.bitmapId, bitmapCmdInfo.subCmd, bitmapCmdInfo.clishContext);
        }
    }
}

/*********************************************************************
 * Function: Add bitmaps of all ports from the bitmap add/mod/del command
 * Input: bitmapCmdInfo: bitmap related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_BitmapConfigWithAll(PclBitmapCmdInfo &bitmapCmdInfo)
{
    for (UINT8 areaId = 0; areaId < g_pclndnMngInfo.maxArea; areaId++) {
        PCL_BitmapConfigWithArea(bitmapCmdInfo, areaId);
    }
}
/*********************************************************************
 * Function: bitmap add/mod/del command line processing
 * Input: argValue: argument value
 * Output: bitmapCmdInfo: bitmap related info
 * Return: None
 * *******************************************************************/
VOID PCL_ProcBitmapConfigCmd(PclBitmapCmdInfo &bitmapCmdInfo)
{
    UINT32 ret = PCL_CheckIfBitmapContinue(bitmapCmdInfo);
    if (ret != PCL_OK) {
        return;
    }
    switch (bitmapCmdInfo.subkey) {
        case BITMAP_SUBKEY_PORT:
            PCLNDN_UpdatePortBitmapEntry(bitmapCmdInfo.portDevId, bitmapCmdInfo.bitmapId, bitmapCmdInfo.subCmd, bitmapCmdInfo.clishContext);
            break;
        case BITMAP_SUBKEY_AREA:
            PCL_BitmapConfigWithArea(bitmapCmdInfo, bitmapCmdInfo.areaId);
            break;
        case BITMAP_SUBKEY_NONE:
            PCL_BitmapConfigWithAll(bitmapCmdInfo);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: Show the bitmap of ports by group
 * Input: bitmapCmdInfo: bitmap related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowPortBitmapWithArea(PclBitmapCmdInfo &bitmapCmdInfo, UINT8 areaId)
{
    UINT32 status = PCL_ERROR;
    bf_pal_front_port_handle_t portHandle;
    UINT32 start = areaId * PCL_MAX_PORT_AREA_NUM + 1;
    UINT32 end = start + PCL_MAX_PORT_AREA_NUM;
    UINT32 mapKey = 0;
    UINT32 index = 1;
    UINT8 hasShowAttr = PCL_FALSE;
    UINT8  hideAttr = PCL_FALSE;

    portHandle.chnl_id = 0;
    for (UINT32 conn_id = start; conn_id < end; conn_id++) {
        portHandle.conn_id = conn_id;
        mapKey = (portHandle.conn_id << UINT16_BITS) + portHandle.chnl_id;
        if (g_mapPortMngInfo.find(mapKey) != g_mapPortMngInfo.end()) {
            PclPortMngInfo &portInfo = g_mapPortMngInfo[mapKey];
            if (portInfo.used == PCL_TRUE) {
                if (hasShowAttr == PCL_FALSE) {
                    hasShowAttr = PCL_TRUE;
                    hideAttr = PCL_FALSE;
                } else {
                    hideAttr = PCL_TRUE;
                }
                PCLNDN_ShowPortBitmapEntry(portInfo.portDevId, index, hideAttr, bitmapCmdInfo.clishContext);
                index++;
            }
        }
    }
}

/*********************************************************************
 * Function: bitmap show command line processing
 * Input: argValue: argument value
 * Output: bitmapCmdInfo: bitmap related info
 * Return: None
 * *******************************************************************/
VOID PCL_ProcBitmapShowCmd(PclBitmapCmdInfo &bitmapCmdInfo)
{   
    switch (bitmapCmdInfo.subkey) {
        case BITMAP_SUBKEY_PORT:
            PCLNDN_ShowPortBitmapEntry(bitmapCmdInfo.portDevId, 1, PCL_FALSE, bitmapCmdInfo.clishContext);
            break;
        case BITMAP_SUBKEY_AREA:
            PCLNDN_ShowPortBitmapWithArea(bitmapCmdInfo, bitmapCmdInfo.areaId);
            break;
        case BITMAP_SUBKEY_NONE:
            PCLNDN_ShowAllPortBitmapEntry(bitmapCmdInfo);
            break;
        default:
            break;
    }
}

/*********************************************************************
 * Function: Get bitmap index info from the bitmap xxx command line
 * Input: argValue: argument value
 * Output: bitmapCmdInfo: bitmap related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateBitmapAreaIdInfo(const char* argValue, PclBitmapCmdInfo &bitmapCmdInfo)
{
    UINT32 index = strtoul(argValue, 0, 0);

    if (index >= PCL_MAX_PORT_AREA_NUM) {
        bfshell_printf(bitmapCmdInfo.clishContext, "Error: bitmap group %u is bigger than max: %u\n", index, PCL_MAX_PORT_AREA_NUM);
        bitmapCmdInfo.parseResult = SHIFT_LEFT_BITS(BITMAP_CMD_ARG_AREAID);
        return;
    }
    bitmapCmdInfo.areaId = (UINT8)index;
}
/*********************************************************************
 * Function: Get the outport from the bitmap xxx command line
 * Input: argValue: argument value
 * Output: bitmapCmdInfo: bitmap related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateBitmapPortInfo(const char* argValue, PclBitmapCmdInfo &bitmapCmdInfo)
{
    bf_status_t status;
    bf_pal_front_port_handle_t portHandle;
    bf_dev_port_t portDevId = 0;
    bool isInternalPort = false;

    status = bf_pm_port_str_to_hdl_get(g_dev_target.dev_id, argValue, &portHandle);
    if (status != BF_SUCCESS) {
        bfshell_printf(bitmapCmdInfo.clishContext, "Error: port %s is invalid\n", argValue);
        bitmapCmdInfo.parseResult = SHIFT_LEFT_BITS(BITMAP_CMD_ARG_PORT_INDEX);
        return;
    }

    bf_pm_is_port_internal(g_dev_target.dev_id, &portHandle, &isInternalPort);
    if (isInternalPort) {
        bfshell_printf(bitmapCmdInfo.clishContext, "Error: port %s is internal port\n", argValue);
        bitmapCmdInfo.parseResult = SHIFT_LEFT_BITS(BITMAP_CMD_ARG_PORT_INDEX);
        return;
    }

#ifdef SDE_9XX_OLD
    status = bf_pm_port_front_panel_port_to_dev_port_get(g_dev_target.dev_id, &portHandle, &portDevId);
#else
    status = bf_pm_port_front_panel_port_to_dev_port_get(&portHandle, &g_dev_target.dev_id, &portDevId);
#endif
    if (status != BF_SUCCESS) {
        bfshell_printf(bitmapCmdInfo.clishContext, "Error: get port:%s devid fail\n", argValue);
        bitmapCmdInfo.parseResult = SHIFT_LEFT_BITS(BITMAP_CMD_ARG_PORT_INDEX);
        return;
    }
    bitmapCmdInfo.portDevId = (UINT32)portDevId;
    bitmapCmdInfo.connId = portHandle.conn_id;
    bitmapCmdInfo.chnlId = portHandle.chnl_id;
    bitmapCmdInfo.areaId = (UINT8)((portHandle.conn_id - 1) / PCL_MAX_PORT_AREA_NUM);
}
/*********************************************************************
 * Function: Get related info from the bitmap xxx command
 * Input: type: type
 *       argValue: argument value
 * Output: bitmapCmdInfo: bitmap related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateBitmapCmdInfo(UINT32 type, const char* argValue, PclBitmapCmdInfo &bitmapCmdInfo)
{
    switch(type) {
        case BITMAP_CMD_ARG_PORT_INDEX:
            PCL_UpdateBitmapPortInfo(argValue, bitmapCmdInfo);
            break;
        case BITMAP_CMD_ARG_AREAID:
            PCL_UpdateBitmapAreaIdInfo(argValue, bitmapCmdInfo);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: Get the argument type from the bitmap xxx command
 * Input: argName: argument name
 *       bitmapCmdInfo: bitmap related info
 * Output: None
 * Return: argument type
 * *******************************************************************/
UINT32 PCL_GetBitmapCmdArgType(const char *argName, PclBitmapCmdInfo &bitmapCmdInfo)
{
    if (strcmp(argName, "add") == 0) {
        bitmapCmdInfo.subCmd = PCL_NDN_ENTRY_ADD_ONLY;
        return BITMAP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "mod") == 0) {
        bitmapCmdInfo.subCmd = PCL_NDN_ENTRY_ADD_MOD;
        return BITMAP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "del") == 0) {
        bitmapCmdInfo.subCmd = PCL_NDN_ENTRY_DEL;
        return BITMAP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "show") == 0) {
        bitmapCmdInfo.subCmd = PCL_NDN_ENTRY_SHOW;
        return BITMAP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "port") == 0) {
        return BITMAP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "portid") == 0) {
        bitmapCmdInfo.subkey = BITMAP_SUBKEY_PORT;
        return BITMAP_CMD_ARG_PORT_INDEX;
    }
    if (strcmp(argName, "area") == 0) {
        return BITMAP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "areaId") == 0) {
        bitmapCmdInfo.subkey = BITMAP_SUBKEY_AREA;
        return BITMAP_CMD_ARG_AREAID;
    }
    if (strcmp(argName, "type") == 0) {
        return BITMAP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "subtype") == 0) {
        return BITMAP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "key") == 0) {
        return BITMAP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "keytype") == 0) {
        return BITMAP_CMD_ARG_SKIP;
    }
    bfshell_printf(bitmapCmdInfo.clishContext, "Error: can not process arg:%s\n", argName);
    return BITMAP_CMD_ARG_BUT;
}
/*********************************************************************
 * Function: Get related info from the bitmap xxx command
 * Input: cmdInfo: command related info pointer
 * Output: bitmapCmdInfo: bitmap related info
 * Return: None
 * *******************************************************************/
VOID PCL_GetBitmapInfoFromCmd(const PclNdnCmdInfo *cmdInfo, PclBitmapCmdInfo &bitmapCmdInfo)
{
    UINT32 type = 0;
    bitmapCmdInfo.clishContext = cmdInfo->clishContext;
    for (UINT32 index = 0; index < cmdInfo->argNum; index++) {
        type = PCL_GetBitmapCmdArgType(cmdInfo->argNames[index], bitmapCmdInfo);
        PCL_UpdateBitmapCmdInfo(type, cmdInfo->argValues[index], bitmapCmdInfo);
    }
}
/*********************************************************************
 * Function: bitmap xxx command line processing
 * Input: cmdInfo: command line info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_ProcBitmapCmd(const PclNdnCmdInfo *cmdInfo)
{
    PclBitmapCmdInfo bitmapCmdInfo = {0};

    PCL_GetBitmapInfoFromCmd(cmdInfo, bitmapCmdInfo);
    if (bitmapCmdInfo.parseResult != PCL_OK) {
        return PCL_OK;
    }
    switch (bitmapCmdInfo.subCmd) {
        case PCL_NDN_ENTRY_ADD_ONLY:
        case PCL_NDN_ENTRY_ADD_MOD:
        case PCL_NDN_ENTRY_DEL:
            PCL_ProcBitmapConfigCmd(bitmapCmdInfo);
            break;
        case PCL_NDN_ENTRY_SHOW:
            PCL_ProcBitmapShowCmd(bitmapCmdInfo);
            break;
        default:
            bfshell_printf(bitmapCmdInfo.clishContext, "Error: not support now\n");
            break;
    }

    return PCL_OK;
}

/*********************************************************************
 * Function: Show the configuration of a port
 * Input: portCmdInfo: port related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowOnePortInfo(PclPortCmdInfo &portCmdInfo)
{
    if (g_mapPortMngInfo.find(portCmdInfo.mapKey) == g_mapPortMngInfo.end()) {
        bfshell_printf(portCmdInfo.clishContext, "Info: port %u/%u has not exsit\n", portCmdInfo.connId, portCmdInfo.chnlId);
        return;
    }
    PclPortMngInfo &portInfo = g_mapPortMngInfo[portCmdInfo.mapKey];
    if (portInfo.used != PCL_TRUE) {
        return;
    }
    bfshell_printf(portCmdInfo.clishContext, "=====================================================================================\n");
    bfshell_printf(portCmdInfo.clishContext, "| ConnId | ChnlId | DevId | PipeId | Area | BitmapValue |\n");
    bfshell_printf(portCmdInfo.clishContext, "| %6u | %6u | %5u | %6u | %4u | %11u |\n",
        portInfo.connId, portInfo.chnlId, portInfo.portDevId, portInfo.pipeId, portInfo.areaId, portInfo.bitmapId);
    bfshell_printf(portCmdInfo.clishContext, "=====================================================================================\n");
}

/*********************************************************************
 * Function: Show the configuration of all ports
 * Input: portCmdInfo: port related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowAllPortInfo(PclPortCmdInfo &portCmdInfo, UINT32 filterArea)
{
    map<UINT32, PclPortMngInfo>::iterator it;

    if (g_mapPortMngInfo.size() == 0) {
        bfshell_printf(portCmdInfo.clishContext, "Info: no port has been added\n");
        return;
    }

    bfshell_printf(portCmdInfo.clishContext, "=====================================================================================\n");
    bfshell_printf(portCmdInfo.clishContext, "| ConnId | ChnlId | DevId | PipeId | Area | BitmapValue |\n");
    it = g_mapPortMngInfo.begin();
    while (it != g_mapPortMngInfo.end()) {
        PclPortMngInfo &portInfo = it->second;
        if (portInfo.used == PCL_TRUE) {
            if (filterArea == PCL_TRUE) {
                if (portInfo.areaId == portCmdInfo.areaId) {
                    bfshell_printf(portCmdInfo.clishContext, "| %6u | %6u | %5u | %6u | %4u | %11u |\n",
                        portInfo.connId, portInfo.chnlId, portInfo.portDevId, portInfo.pipeId, portInfo.areaId, portInfo.bitmapId);
                }
            } else {
                bfshell_printf(portCmdInfo.clishContext, "| %6u | %6u | %5u | %6u | %4u | %11u |\n",
                    portInfo.connId, portInfo.chnlId, portInfo.portDevId, portInfo.pipeId, portInfo.areaId, portInfo.bitmapId);
            }
        }
        it++;
    }
    bfshell_printf(portCmdInfo.clishContext, "=====================================================================================\n");
    return;
}

/*********************************************************************
 * Function: bitmap show command line processing
 * Input: portCmdInfo: port related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ProcPortShowCmd(PclPortCmdInfo &portCmdInfo)
{
    switch (portCmdInfo.subkey) {
        case PORT_SUBKEY_PORT:
            PCLNDN_ShowOnePortInfo(portCmdInfo);
            break;
        case PORT_SUBKEY_AREA:
            PCLNDN_ShowAllPortInfo(portCmdInfo, PCL_TRUE);
            break;
        case PORT_SUBKEY_NONE:
            PCLNDN_ShowAllPortInfo(portCmdInfo, PCL_FALSE);
            break;
        default:
            break;
    }
}

/*********************************************************************
 * Function: Add a port
 * Input: portCmdInfo: port related info
 *      areaId: group ID
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_AddOnePort(PclPortCmdInfo &portCmdInfo)
{
    bf_status_t status;

    if (g_mapPortMngInfo.find(portCmdInfo.mapKey) == g_mapPortMngInfo.end()) {
        bfshell_printf(portCmdInfo.clishContext, "Error: invalid front panel with port %u/%u\n", portCmdInfo.connId, portCmdInfo.chnlId);
        return;
    }
    PclPortMngInfo &addPort = g_mapPortMngInfo[portCmdInfo.mapKey];

    if (addPort.used == PCL_TRUE) {
        bfshell_printf(portCmdInfo.clishContext, "Info: port %u/%u has already been added\n", portCmdInfo.connId, portCmdInfo.chnlId);
        return;
    }

    bf_pal_front_port_handle_t portHandle;
    portHandle.conn_id = portCmdInfo.connId;
    portHandle.chnl_id = portCmdInfo.chnlId;
    status = bf_pm_port_add(g_dev_target.dev_id, &portHandle, BF_SPEED_100G, BF_FEC_TYP_NONE);
    status |= bf_pm_port_autoneg_set(g_dev_target.dev_id, &portHandle, PM_AN_FORCE_DISABLE);
    status |= bf_pm_port_enable(g_dev_target.dev_id, &portHandle);
    if (status != BF_SUCCESS) {
        bfshell_printf(portCmdInfo.clishContext, "Warn: port %u/%u enable with code 0x%x\n", portCmdInfo.connId, portCmdInfo.chnlId, status);
    }
    addPort.used = PCL_TRUE;
    bfshell_printf(portCmdInfo.clishContext, "Info: success add port %u/%u\n", portCmdInfo.connId, portCmdInfo.chnlId);
}

/*********************************************************************
 * Function: port add command line processing
 * Input: portCmdInfo: port related info
 *      areaId: group ID
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_AddPortWithArea(PclPortCmdInfo &portCmdInfo, UINT8 areaId)
{
    UINT32 status = PCL_ERROR;
    UINT32 start = areaId * PCL_MAX_PORT_AREA_NUM;
    UINT32 end = start + PCL_MAX_PORT_AREA_NUM;

    portCmdInfo.chnlId = 0;
    for (UINT32 index = start; index < end; index++) {
        portCmdInfo.connId = index + 1;
        portCmdInfo.mapKey = (portCmdInfo.connId << UINT16_BITS) + portCmdInfo.chnlId;
        PCL_AddOnePort(portCmdInfo);
    }
}

/*********************************************************************
 * Function: Add the bitmap of all ports from the port add/mod/del command
 * Input: portCmdInfo: port related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_AddPortWithAllArea(PclPortCmdInfo &portCmdInfo)
{
    for (UINT8 area = 0; area < g_pclndnMngInfo.maxArea; area++) {
        PCL_AddPortWithArea(portCmdInfo, area);
    }
}

/*********************************************************************
 * Function: Check port add command line
 * Input: portCmdInfo: port related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
VOID PCL_ProcPortAddCmd(PclPortCmdInfo &portCmdInfo)
{
    switch (portCmdInfo.subkey) {
        case PORT_SUBKEY_PORT:
            PCL_AddOnePort(portCmdInfo);
            break;
        case PORT_SUBKEY_AREA:
            PCL_AddPortWithArea(portCmdInfo, portCmdInfo.areaId);
            break;
        case PORT_SUBKEY_NONE:
            PCL_AddPortWithAllArea(portCmdInfo);
            break;
        default:
            break;
    }
    return;
}

/*********************************************************************
 * Function: port del command line processing
 * Input: portCmdInfo: port related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_DelOnePort(PclPortCmdInfo &portCmdInfo)
{
    bf_pal_front_port_handle_t portHandle;
    if (g_mapPortMngInfo.find(portCmdInfo.mapKey) == g_mapPortMngInfo.end()) {
        bfshell_printf(portCmdInfo.clishContext, "Info: port %u/%u has not been added\n", portCmdInfo.connId, portCmdInfo.chnlId);
        return;
    }
    PclPortMngInfo &portInfo = g_mapPortMngInfo[portCmdInfo.mapKey];
    if (portInfo.bitmapId != 0) {
        bfshell_printf(portCmdInfo.clishContext, "Info: port %u/%u has set the bitmap, please unset bitmap first\n", portCmdInfo.connId, portCmdInfo.chnlId);
        return;
    }
    portHandle.conn_id = portCmdInfo.connId;
    portHandle.chnl_id = portCmdInfo.chnlId;
    bf_pm_port_disable(g_dev_target.dev_id, &portHandle);
    bf_pm_port_delete(g_dev_target.dev_id, &portHandle);
    portInfo.used = PCL_FALSE;
    bfshell_printf(portCmdInfo.clishContext, "Info: port %u/%u was deleted\n", portCmdInfo.connId, portCmdInfo.chnlId);
    return;
}

/*********************************************************************
 * Function: port add command line processing
 * Input: portCmdInfo: port related info
 *      areaId: group ID
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_DelPortWithArea(PclPortCmdInfo &portCmdInfo, UINT8 areaId)
{
    UINT32 status = PCL_ERROR;
    UINT32 start = areaId * PCL_MAX_PORT_AREA_NUM;
    UINT32 end = start + PCL_MAX_PORT_AREA_NUM;

    portCmdInfo.chnlId = 0;
    for (UINT32 index = start; index < end; index++) {
        portCmdInfo.connId = index + 1;
        portCmdInfo.mapKey = (portCmdInfo.connId << UINT16_BITS) + portCmdInfo.chnlId;
        PCL_DelOnePort(portCmdInfo);
    }
}

/*********************************************************************
 * Function: Add the bitmap of all ports from the port add/mod/del command
 * Input: portCmdInfo: port related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_DelPortWithAllArea(PclPortCmdInfo &portCmdInfo)
{
    for (UINT8 area = 0; area < g_pclndnMngInfo.maxArea; area++) {
        PCL_DelPortWithArea(portCmdInfo, area);
    }
}
/*********************************************************************
 * Function: port del command line processing
 * Input: portCmdInfo: port related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
VOID PCL_ProcPortDelCmd(PclPortCmdInfo &portCmdInfo)
{
    switch (portCmdInfo.subkey) {
        case PORT_SUBKEY_PORT:
            PCL_DelOnePort(portCmdInfo);
            break;
        case PORT_SUBKEY_AREA:
            PCL_AddPortWithArea(portCmdInfo, portCmdInfo.areaId);
            break;
        case PORT_SUBKEY_NONE:
            PCL_AddPortWithAllArea(portCmdInfo);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: bitmap add/mod/del command line processing
 * Input: portCmdInfo: port related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ProcPortConfigCmd(PclPortCmdInfo &portCmdInfo)
{
    switch (portCmdInfo.subCmd) {
        case PCL_NDN_ENTRY_ADD_ONLY:
            PCL_ProcPortAddCmd(portCmdInfo);
            break;
        case PCL_NDN_ENTRY_DEL:
            PCL_ProcPortDelCmd(portCmdInfo);
            break;
        default:
            bfshell_printf(portCmdInfo.clishContext, "not support sub command:%u\n", portCmdInfo.subCmd);
    }
}
/*********************************************************************
 * Function: Get the outport from the bitmap xxx command
 * Input: argValue: argument value
 * Output: portCmdInfo: port related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdatePortCmdDevInfo(const char* argValue, PclPortCmdInfo &portCmdInfo)
{
    bf_status_t status;
    bf_pal_front_port_handle_t portHandle;
    bf_dev_port_t portDevId = 0;
    bool isInternalPort = false;

    status = bf_pm_port_str_to_hdl_get(g_dev_target.dev_id, argValue, &portHandle);
    if (status != BF_SUCCESS) {
        bfshell_printf(portCmdInfo.clishContext, "Error: port %s is invalid\n", argValue);
        portCmdInfo.parseResult = SHIFT_LEFT_BITS(PORT_CMD_ARG_PORTID);
        return;
    }

    bf_pm_is_port_internal(g_dev_target.dev_id, &portHandle, &isInternalPort);
    if (isInternalPort) {
        bfshell_printf(portCmdInfo.clishContext, "Error: port %s is internal port\n", argValue);
        portCmdInfo.parseResult = SHIFT_LEFT_BITS(PORT_CMD_ARG_PORTID);
        return;
    }

#ifdef SDE_9XX_OLD
    status = bf_pm_port_front_panel_port_to_dev_port_get(g_dev_target.dev_id, &portHandle, &portDevId);
#else
    status = bf_pm_port_front_panel_port_to_dev_port_get(&portHandle, &g_dev_target.dev_id, &portDevId);
#endif
    if (status != BF_SUCCESS) {
        bfshell_printf(portCmdInfo.clishContext, "Error: get port:%s devid fail\n", argValue);
        portCmdInfo.parseResult = SHIFT_LEFT_BITS(PORT_CMD_ARG_PORTID);
        return;
    }
    portCmdInfo.portDevId = (UINT32)portDevId;
    portCmdInfo.connId = portHandle.conn_id;
    portCmdInfo.chnlId = portHandle.chnl_id;
    portCmdInfo.mapKey = (portCmdInfo.connId << UINT16_BITS) + portCmdInfo.chnlId;
}

/*********************************************************************
 * Function: Get the area info of outports from the bitmap xxx command
 * Input: argValue: argument value
 * Output: portCmdInfo: port related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdatePortAreaInfo(const char* argValue, PclPortCmdInfo &portCmdInfo)
{

    UINT32 index = strtoul(argValue, 0, 0);

    if (index >= PCL_MAX_PORT_AREA_NUM) {
        bfshell_printf(portCmdInfo.clishContext, "Error: port %u is bigger than max: %u\n", index, PCL_MAX_PORT_AREA_NUM);
        portCmdInfo.parseResult = SHIFT_LEFT_BITS(PORT_CMD_ARG_AREAID);
        return;
    }
    portCmdInfo.areaId = (UINT8)index;
}
/*********************************************************************
 * Function: Get related info from the bitmap xxx command
 * Input: type: type
 *       argValue: argument value
 * Output: portCmdInfo: port related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdatePortCmdInfo(UINT32 type, const char* argValue, PclPortCmdInfo &portCmdInfo)
{
    switch(type) {
        case PORT_CMD_ARG_PORTID:
            PCL_UpdatePortCmdDevInfo(argValue, portCmdInfo);
            break;
        case PORT_CMD_ARG_AREAID:
            PCL_UpdatePortAreaInfo(argValue, portCmdInfo);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: Get the argument type from the port xxx command
 * Input: argName: argument name
 * Output: portCmdInfo: port related info
 * Return: argument type
 * *******************************************************************/
UINT32 PCL_GetPortCmdArgType(const char *argName, PclPortCmdInfo &portCmdInfo)
{
    if (strcmp(argName, "add") == 0) {
        portCmdInfo.subCmd = PCL_NDN_ENTRY_ADD_ONLY;
        return PORT_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "mod") == 0) {
        portCmdInfo.subCmd = PCL_NDN_ENTRY_ADD_MOD;
        return PORT_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "del") == 0) {
        portCmdInfo.subCmd = PCL_NDN_ENTRY_DEL;
        return PORT_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "show") == 0) {
        portCmdInfo.subCmd = PCL_NDN_ENTRY_SHOW;
        return PORT_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "port") == 0) {
        return PORT_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "portid") == 0) {
        portCmdInfo.subkey = PORT_SUBKEY_PORT;
        return PORT_CMD_ARG_PORTID;
    }
    if (strcmp(argName, "area") == 0) {
        return PORT_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "areaid") == 0) {
        portCmdInfo.subkey = PORT_SUBKEY_AREA;
        return PORT_CMD_ARG_AREAID;
    }
    if (strcmp(argName, "type") == 0) {
        return PORT_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "key") == 0) {
        return PORT_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "keytype") == 0) {
        return PORT_CMD_ARG_SKIP;
    }
    bfshell_printf(portCmdInfo.clishContext, "Error: can not process arg:%s\n", argName);
    return PORT_CMD_ARG_BUT;
}
/*********************************************************************
 * Function: Get related info from the port xxx command
 * Input: cmdInfo: command related info pointer
 * Output: portCmdInfo: port related info
 * Return: None
 * *******************************************************************/
VOID PCL_GetPortInfoFromCmd(const PclNdnCmdInfo *cmdInfo, PclPortCmdInfo &portCmdInfo)
{
    UINT32 type = 0;
    portCmdInfo.clishContext = cmdInfo->clishContext;
    for (UINT32 index = 0; index < cmdInfo->argNum; index++) {
        type = PCL_GetPortCmdArgType(cmdInfo->argNames[index], portCmdInfo);
        PCL_UpdatePortCmdInfo(type, cmdInfo->argValues[index], portCmdInfo);
    }
}
/*********************************************************************
 * Function: port xxx command line processing
 * Input: cmdInfo: command line info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_ProcPortCmd(const PclNdnCmdInfo *cmdInfo)
{
    PclPortCmdInfo portCmdInfo = {0};

    PCL_GetPortInfoFromCmd(cmdInfo, portCmdInfo);
    if (portCmdInfo.parseResult != PCL_OK) {
        return PCL_OK;
    }
    switch (portCmdInfo.subCmd) {
        case PCL_NDN_ENTRY_ADD_ONLY:
        case PCL_NDN_ENTRY_ADD_MOD:
        case PCL_NDN_ENTRY_DEL:
            PCL_ProcPortConfigCmd(portCmdInfo);
            break;
        case PCL_NDN_ENTRY_SHOW:
            PCL_ProcPortShowCmd(portCmdInfo);
            break;
        default:
            bfshell_printf(portCmdInfo.clishContext, "Error: not support now\n");
            break;
    }

    return PCL_OK;
}

/*********************************************************************
 * Function: Get pipe from group xxx command
 * Input: argValue: argument value
 * Output: groupCmdInfo: multicast group related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateGroupAreaInfo(const char* argValue, PclMultiGroupCmdInfo &groupCmdInfo)
{
    UINT32 areaId = strtoul(argValue, 0, 0);

    if (areaId >= g_pclndnMngInfo.maxArea) {
        bfshell_printf(groupCmdInfo.clishContext, "Error: area %u is bigger than max: %u\n", areaId, g_pclndnMngInfo.maxArea);
        groupCmdInfo.parseResult = SHIFT_LEFT_BITS(GROUP_CMD_ARG_AREA_ID);
        return;
    }
    groupCmdInfo.areaId = (UINT8)areaId;
}
/*********************************************************************
 * Function: Get bitmask from group xxx command
 * Input: argValue: argument value
 * Output: groupCmdInfo: multicast group related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateGroupBitMaskInfo(const char* argValue, PclMultiGroupCmdInfo &groupCmdInfo)
{
    UINT32 maskid = strtoul(argValue, 0, 0);
    UINT8 areaId = (UINT8)((maskid >> 8) & 0xFF);
    UINT8 bitmap = (UINT8)(maskid & 0xFF);

    if (areaId >= g_pclndnMngInfo.maxArea) {
        bfshell_printf(groupCmdInfo.clishContext, "Error: mask id %u made area index %u out of max area: %u\n", maskid, areaId, g_pclndnMngInfo.maxArea);
        groupCmdInfo.parseResult = SHIFT_LEFT_BITS(GROUP_CMD_ARG_MASK_ID);
        return;
    }
    if (bitmap == 0) {
        bfshell_printf(groupCmdInfo.clishContext, "Error: mask id %u made bitmap zero\n", maskid);
        groupCmdInfo.parseResult = SHIFT_LEFT_BITS(GROUP_CMD_ARG_MASK_ID);
        return;
    }
    groupCmdInfo.areaId = areaId;
    groupCmdInfo.bitmap = bitmap;
    groupCmdInfo.bitmask = maskid;
}
/*********************************************************************
 * Function: Get related info from group xxx command
 * Input: type: type
 *       argValue: argument value
 * Output: groupCmdInfo: multicast group related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateGroupCmdInfo(UINT32 type, const char* argValue, PclMultiGroupCmdInfo &groupCmdInfo)
{
    switch(type) {
        case GROUP_CMD_ARG_AREA_ID:
            PCL_UpdateGroupAreaInfo(argValue, groupCmdInfo);
            break;
        case GROUP_CMD_ARG_MASK_ID:
            PCL_UpdateGroupBitMaskInfo(argValue, groupCmdInfo);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: Get argument type from group xxx command
 * Input: argName: argument name
 * Output: groupCmdInfo: multicast group related info
 * Return: argument type
 * *******************************************************************/
UINT32 PCL_GetGroupCmdArgType(const char *argName, PclMultiGroupCmdInfo &groupCmdInfo)
{
    if (strcmp(argName, "add") == 0) {
        groupCmdInfo.subCmd = PCL_NDN_ENTRY_ADD_ONLY;
        return GROUP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "mod") == 0) {
        groupCmdInfo.subCmd = PCL_NDN_ENTRY_ADD_MOD;
        return GROUP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "del") == 0) {
        groupCmdInfo.subCmd = PCL_NDN_ENTRY_DEL;
        return GROUP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "show") == 0) {
        groupCmdInfo.subCmd = PCL_NDN_ENTRY_SHOW;
        return GROUP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "type") == 0) {
        return GROUP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "key") == 0) {
        return GROUP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "keytype") == 0) {
        return GROUP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "area") == 0) {
        return GROUP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "areaid") == 0) {
        groupCmdInfo.subkey = GROUP_SUBKEY_AREA_ID;
        return GROUP_CMD_ARG_AREA_ID;
    }
    if (strcmp(argName, "bitmask") == 0) {
        return GROUP_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "maskid") == 0) {
        groupCmdInfo.subkey = GROUP_SUBKEY_MASK_ID;
        return GROUP_CMD_ARG_MASK_ID;
    }
    bfshell_printf(groupCmdInfo.clishContext, "Error: can not process arg:%s\n", argName);
    return GROUP_CMD_ARG_BUT;
}
/*********************************************************************
 * Function: Get related info from group xxx command
 * Input: cmdInfo: command related info pointer
 * Output: groupCmdInfo: multicast group related info
 * Return: None
 * *******************************************************************/
VOID PCL_GetGroupInfoFromCmd(const PclNdnCmdInfo *cmdInfo, PclMultiGroupCmdInfo &groupCmdInfo)
{
    UINT32 type = 0;
    groupCmdInfo.clishContext = cmdInfo->clishContext;
    for (UINT32 index = 0; index < cmdInfo->argNum; index++) {
        type = PCL_GetGroupCmdArgType(cmdInfo->argNames[index], groupCmdInfo);
        PCL_UpdateGroupCmdInfo(type, cmdInfo->argValues[index], groupCmdInfo);
    }
}

/*********************************************************************
 * Function: group add one entry
 * Input: groupCmdInfo: multicast related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
VOID PCL_AddOneMultiGroup(PclMultiGroupCmdInfo &groupCmdInfo)
{
    UINT32 ret = PCL_OK;
    if (g_mapGroupInfo.find(groupCmdInfo.bitmask) != g_mapGroupInfo.end()) {
        bfshell_printf(groupCmdInfo.clishContext, "Error: bitmask %u has already added\n", groupCmdInfo.bitmask);
        return;
    }

    /* add pre-node */
    ret = PCLNDN_UpdatePreNodeTableEntry(groupCmdInfo);
    if (ret != PCL_OK) {
        return;
    }

    /* add pre-grp */
    PCLNDN_UpdatePreMgIdTableEntry(groupCmdInfo);

    /* add into list */
    PclMultiGroupInfo groupInfo;
    groupInfo.areaId = groupCmdInfo.areaId;
    groupInfo.bitmap = groupCmdInfo.bitmap;
    groupInfo.bitmask = groupCmdInfo.bitmask;
    g_mapGroupInfo[groupCmdInfo.bitmask] = groupInfo;
    return;
}

/*********************************************************************
 * Function: group add one entry
 * Input: groupCmdInfo: multicast related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
VOID PCL_AddMultiGroupWithArea(PclMultiGroupCmdInfo &groupCmdInfo, UINT8 areaId)
{
    UINT32 maskBase = areaId << 8;

    groupCmdInfo.areaId = areaId;
    for (UINT32 bitmap = 1; bitmap <= MAX_UINT8; bitmap++) {
        groupCmdInfo.bitmap = (UINT8)bitmap;
        groupCmdInfo.bitmask = maskBase + bitmap;
        PCL_AddOneMultiGroup(groupCmdInfo);
        usleep(10);
    }
}

/*********************************************************************
 * Function: group add all entries
 * Input: groupCmdInfo: multicast related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
VOID PCL_AddMultiGroupAll(PclMultiGroupCmdInfo &groupCmdInfo)
{
    for (UINT8 areaId = 0; areaId < g_pclndnMngInfo.maxArea; areaId++) {
        PCL_AddMultiGroupWithArea(groupCmdInfo, areaId);
    }
}

/*********************************************************************
 * Function: Check group add command
 * Input: groupCmdInfo: multicast related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
VOID PCL_ProcGroupAddCmd(PclMultiGroupCmdInfo &groupCmdInfo)
{
    switch(groupCmdInfo.subkey) {
        case GROUP_SUBKEY_NONE:
            PCL_AddMultiGroupAll(groupCmdInfo);
            break;
        case GROUP_SUBKEY_AREA_ID:
            PCL_AddMultiGroupWithArea(groupCmdInfo, groupCmdInfo.areaId);
            break;
        case GROUP_SUBKEY_MASK_ID:
            PCL_AddOneMultiGroup(groupCmdInfo);
            break;
        default:
            break;
    }
}

/*********************************************************************
 * Function: group del one entry
 * Input: groupCmdInfo: multicast related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
VOID PCL_DelOneMultiGroup(PclMultiGroupCmdInfo &groupCmdInfo)
{
    if (g_mapGroupInfo.find(groupCmdInfo.bitmask) == g_mapGroupInfo.end()) {
        bfshell_printf(groupCmdInfo.clishContext, "Info: bitmask %u has not been added\n", groupCmdInfo.bitmask);
        return;
    }
    
    /* delete pre-node */
    PCLNDN_UpdatePreNodeTableEntry(groupCmdInfo);
    /* delete pre-grp */
    PCLNDN_UpdatePreMgIdTableEntry(groupCmdInfo);

    /* delete list */
    g_mapGroupInfo.erase(groupCmdInfo.bitmask);
    bfshell_printf(groupCmdInfo.clishContext, "Info: bitmask %u was deleted\n", groupCmdInfo.bitmask);
    return;
}


/*********************************************************************
 * Function: group del entries by area
 * Input: groupCmdInfo: multicast related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
VOID PCL_DelMultiGroupWithArea(PclMultiGroupCmdInfo &groupCmdInfo, UINT8 areaId)
{
    UINT32 maskBase = areaId << 8;

    groupCmdInfo.areaId = areaId;
    for (UINT32 bitmap = 0; bitmap <= MAX_UINT8; bitmap++) {
        groupCmdInfo.bitmap = (UINT8)bitmap;
        groupCmdInfo.bitmask = maskBase + bitmap;
        PCL_DelOneMultiGroup(groupCmdInfo);
    }
}

/*********************************************************************
 * Function: group del all entries
 * Input: groupCmdInfo: multicast related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
VOID PCL_DelMultiGroupAll(PclMultiGroupCmdInfo &groupCmdInfo)
{
    for (UINT8 areaId = 0; areaId < g_pclndnMngInfo.maxArea; areaId++) {
        PCL_AddMultiGroupWithArea(groupCmdInfo, areaId);
    }
}

/*********************************************************************
 * Function: port del command line processing
 * Input: portCmdInfo: port related info
 * Output: None
 * Return: PCL_OK: continue processing command line, others: end command line processing
 * *******************************************************************/
VOID PCL_ProcGroupDelCmd(PclMultiGroupCmdInfo &groupCmdInfo)
{
    switch(groupCmdInfo.subkey) {
        case GROUP_SUBKEY_NONE:
            PCL_DelMultiGroupAll(groupCmdInfo);
            break;
        case GROUP_SUBKEY_AREA_ID:
            PCL_DelMultiGroupWithArea(groupCmdInfo, groupCmdInfo.areaId);
            break;
        case GROUP_SUBKEY_MASK_ID:
            PCL_DelOneMultiGroup(groupCmdInfo);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: group add/del command line processing
 * Input: groupCmdInfo: multicast group related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ProcGroupConfigCmd(PclMultiGroupCmdInfo &groupCmdInfo)
{
    switch (groupCmdInfo.subCmd) {
        case PCL_NDN_ENTRY_ADD_ONLY:
            PCL_ProcGroupAddCmd(groupCmdInfo);
            break;
        case PCL_NDN_ENTRY_DEL:
            PCL_ProcGroupDelCmd(groupCmdInfo);
            break;
        default:
            bfshell_printf(groupCmdInfo.clishContext, "not support type:%u\n", groupCmdInfo.subCmd);
            break;
    }
}

/*********************************************************************
 * Function: Show the configuration of a multicast group
 * Input: groupCmdInfo: multicast group related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowMultiGroupConfig(PclMultiGroupCmdInfo &groupCmdInfo)
{
    if (g_mapGroupInfo.find(groupCmdInfo.bitmask) == g_mapGroupInfo.end()) {
        bfshell_printf(groupCmdInfo.clishContext, "Info: bitmask %u has not exsit\n", groupCmdInfo.bitmask);
        return;
    }
    PclMultiGroupInfo &groupInfo = g_mapGroupInfo[groupCmdInfo.bitmask];

    bfshell_printf(groupCmdInfo.clishContext, "group config info:\n");
    bfshell_printf(groupCmdInfo.clishContext, "=====================================================================================\n");
    bfshell_printf(groupCmdInfo.clishContext, "| Area | Bitmap | Bitmask |\n");
    bfshell_printf(groupCmdInfo.clishContext, "| %4u | %6u | %7u |\n",
        groupInfo.areaId, groupInfo.bitmap, groupInfo.bitmask);
    bfshell_printf(groupCmdInfo.clishContext, "=====================================================================================\n");
}

/*********************************************************************
 * Function: Show the configuration of all multicast groups
 * Input: groupCmdInfo: multicast group related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowAllPortConfig(PclMultiGroupCmdInfo &groupCmdInfo, UINT32 fileter)
{
    map<UINT32, PclMultiGroupInfo>::iterator it;

    if (g_mapGroupInfo.size() == 0) {
        bfshell_printf(groupCmdInfo.clishContext, "Info: no port has been added\n");
        return;
    }

    bfshell_printf(groupCmdInfo.clishContext, "group config infos:\n");
    bfshell_printf(groupCmdInfo.clishContext, "=====================================================================================\n");
    bfshell_printf(groupCmdInfo.clishContext, "| Area | Bitmap | Bitmask |\n");
    it = g_mapGroupInfo.begin();
    while (it != g_mapGroupInfo.end()) {
        PclMultiGroupInfo &groupInfo = it->second;
        if (fileter == PCL_TRUE) {
            if (groupInfo.areaId == groupCmdInfo.areaId) {
                bfshell_printf(groupCmdInfo.clishContext, "| %4u | %6u | %7u |\n",
                            groupInfo.areaId, groupInfo.bitmap, groupInfo.bitmask);
            }
        } else {
            bfshell_printf(groupCmdInfo.clishContext, "| %4u | %6u | %7u |\n",
            groupInfo.areaId, groupInfo.bitmap, groupInfo.bitmask);
        }
        it++;
    }
    bfshell_printf(groupCmdInfo.clishContext, "=====================================================================================\n");
    return;
}
/*********************************************************************
 * Function: Show one entry of multicast group
 * Input: groupCmdInfo: multicast group related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowGroupEntryInfo(PclMultiGroupCmdInfo &groupCmdInfo)
{
    bfshell_printf(groupCmdInfo.clishContext, "$pre.node info:\n");
    PCLNDN_ShowPreNodeEntry(groupCmdInfo, 1, PCL_FALSE);
    bfshell_printf(groupCmdInfo.clishContext, "$pre.mgid info:\n");
    PCLNDN_ShowPreMgidEntry(groupCmdInfo, 1, PCL_FALSE);
}
/*********************************************************************
 * Function: Show all entries of multicast group
 * Input: groupCmdInfo: multicast group related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowGroupAllEntryInfo(PclMultiGroupCmdInfo &groupCmdInfo)
{
    bfshell_printf(groupCmdInfo.clishContext, "$pre.node infos:\n");
    PCLNDN_CommonShowTcamTableInfo(g_preNodeTable, PCL_FALSE, 0, groupCmdInfo.clishContext);
    bfshell_printf(groupCmdInfo.clishContext, "$pre.mgid infos:\n");
    PCLNDN_CommonShowTcamTableInfo(g_preMgidTable, PCL_FALSE, 0, groupCmdInfo.clishContext);
}

/*********************************************************************
 * Function: Filter and show pre.node info by area from group
 * Input: groupCmdInfo: multicast group related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ShowGroupPreNodeWithArea(PclMultiGroupCmdInfo &groupCmdInfo)
{
    UINT32 index = 1;
    UINT8 hideAttr = PCL_FALSE;
    UINT8 hasShow = PCL_FALSE;
 
    map<UINT32, PclMultiGroupInfo>::iterator it;
    if (g_mapGroupInfo.size() == 0) {
        bfshell_printf(groupCmdInfo.clishContext, "Info: no pre.node has been added\n");
        return;
    }
    bfshell_printf(groupCmdInfo.clishContext, "$pre.node info:\n");
    it = g_mapGroupInfo.begin();
    while (it != g_mapGroupInfo.end()) {
        PclMultiGroupInfo &groupInfo = it->second;
        if (groupInfo.areaId == groupCmdInfo.areaId) {
            if (hasShow == PCL_FALSE) {
                hasShow = PCL_TRUE;
                hideAttr = PCL_FALSE;
            } else {
                hideAttr = PCL_TRUE;
            }
            groupCmdInfo.bitmap = groupInfo.bitmap;
            groupCmdInfo.bitmask = groupInfo.bitmask;
            PCLNDN_ShowPreNodeEntry(groupCmdInfo, index, hideAttr);
            index++;
        }
        it++;
    }
}

/*********************************************************************
 * Function: Filter and show pre.mgid info by area from group
 * Input: groupCmdInfo: multicast group related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ShowGroupPreMgidWithArea(PclMultiGroupCmdInfo &groupCmdInfo)
{
    UINT32 index = 1;
    UINT8 hideAttr = PCL_FALSE;
    UINT8 hasShow = PCL_FALSE;
 
    map<UINT32, PclMultiGroupInfo>::iterator it;
    if (g_mapGroupInfo.size() == 0) {
        bfshell_printf(groupCmdInfo.clishContext, "Info: no pre.mgid has been added\n");
        return;
    }
    bfshell_printf(groupCmdInfo.clishContext, "$pre.mgid info:\n");
    it = g_mapGroupInfo.begin();
    while (it != g_mapGroupInfo.end()) {
        PclMultiGroupInfo &groupInfo = it->second;
        if (groupInfo.areaId == groupCmdInfo.areaId) {
            if (hasShow == PCL_FALSE) {
                hasShow = PCL_TRUE;
                hideAttr = PCL_FALSE;
            } else {
                hideAttr = PCL_TRUE;
            }
            groupCmdInfo.bitmap = groupInfo.bitmap;
            groupCmdInfo.bitmask = groupInfo.bitmask;
            PCLNDN_ShowPreMgidEntry(groupCmdInfo, index, hideAttr);
            index++;
        }
        it++;
    }
}

/*********************************************************************
 * Function: group show command line processing
 * Input: groupCmdInfo: multicast group related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCL_ProcGroupShowCmd(PclMultiGroupCmdInfo &groupCmdInfo)
{
    switch(groupCmdInfo.subkey) {
        case GROUP_SUBKEY_NONE:
            PCLNDN_ShowAllPortConfig(groupCmdInfo, PCL_FALSE);
            PCLNDN_ShowGroupAllEntryInfo(groupCmdInfo);
            break;
        case GROUP_SUBKEY_AREA_ID:
            PCLNDN_ShowAllPortConfig(groupCmdInfo, PCL_TRUE);
            PCL_ShowGroupPreNodeWithArea(groupCmdInfo);
            PCL_ShowGroupPreMgidWithArea(groupCmdInfo);
            break;
        case GROUP_SUBKEY_MASK_ID:
            PCLNDN_ShowMultiGroupConfig(groupCmdInfo);
            PCLNDN_ShowGroupEntryInfo(groupCmdInfo);
            break;
        default:
            bfshell_printf(groupCmdInfo.clishContext, "not support type:%u\n", groupCmdInfo.subkey);
            break;
    }
}
/*********************************************************************
 * Function: group xxx command line processing
 * Input: cmdInfo: command line info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_ProcGroupCmd(const PclNdnCmdInfo *cmdInfo)
{
    PclMultiGroupCmdInfo groupCmdInfo = {0};

    PCL_GetGroupInfoFromCmd(cmdInfo, groupCmdInfo);
    if (groupCmdInfo.parseResult != PCL_OK) {
        return PCL_OK;
    }
    switch (groupCmdInfo.subCmd) {
        case PCL_NDN_ENTRY_ADD_ONLY:
        case PCL_NDN_ENTRY_ADD_MOD:
        case PCL_NDN_ENTRY_DEL:
            PCL_ProcGroupConfigCmd(groupCmdInfo);
            break;
        case PCL_NDN_ENTRY_SHOW:
            PCL_ProcGroupShowCmd(groupCmdInfo);
            break;
        default:
            bfshell_printf(groupCmdInfo.clishContext, "Error: not support now\n");
            break;
    }

    return PCL_OK;
}

/*********************************************************************
 * Function: Show the info of the backend servers
 * Input: serverCmdInfo: server related info
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ShowServerNum(PclServerCmdInfo &serverCmdInfo)
{
    PclNdnTableFiledShowInfo showInfo = {0};

    bfshell_printf(serverCmdInfo.clishContext, "Info: %u server(s) has been configured, reg table entry:\n", g_pclndnMngInfo.serverNumber);

    /* Initialize arguments */
    showInfo.clishContext = serverCmdInfo.clishContext;
    showInfo.tcamTable = (bfrt::BfRtTable*)g_serverNumReg;
    g_serverNumReg->keyReset(g_serverNumRegKey.get());
    g_serverNumReg->dataReset(g_serverNumRegData.get());
    /* configure key */
    g_serverNumRegKey->setValue(g_serverNumKey, 0);
    /* configure key-value arguments */
    showInfo.tableKey = g_serverNumRegKey.get();
    showInfo.tableData = g_serverNumRegData.get();

    PCLNDN_ShowTableOneEntry(showInfo, PCL_FALSE, 0);
    return;
}

/*********************************************************************
 * Function: Get related info from the server xxx command line
 * Input: cmdInfo: command related info pointer
 * Output: serverCmdInfo: server related info
 * Return: None
 * *******************************************************************/
VOID PCL_ProcServerUpdateCmd(PclServerCmdInfo &serverCmdInfo)
{
    if (g_pclndnMngInfo.serverNumber == serverCmdInfo.serverNumber) {
        bfshell_printf(serverCmdInfo.clishContext, "Info: the same with current config, nothing will be changed.\n");
        return;
    }
    UINT32 status = PCLNDN_UpdateServerNumEntry(serverCmdInfo.serverNumber);
    if (status != PCL_OK) {
        bfshell_printf(serverCmdInfo.clishContext, "Error: change fail for code 0x%x.\n", status);
        return;
    }
    bfshell_printf(serverCmdInfo.clishContext, "Info: change the support server number from %u to %u success.\n", g_pclndnMngInfo.serverNumber, serverCmdInfo.serverNumber);
    g_pclndnMngInfo.serverNumber = serverCmdInfo.serverNumber;
}

/*********************************************************************
 * Function: Get the number of server from the server xxx command line
 * Input: argValue: argument value
 * Output: serverCmdInfo: server related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateServerNumberInfo(const char* argValue, PclServerCmdInfo &serverCmdInfo)
{
    UINT32 number = strtoul(argValue, 0, 0);

    if (number >= PCL_MAX_SERVER_NUM) {
        bfshell_printf(serverCmdInfo.clishContext, "Error: server number %u is bigger than max: %u\n", number, PCL_MAX_SERVER_NUM);
        serverCmdInfo.parseResult = SHIFT_LEFT_BITS(SERVER_CMD_ARG_NUMBER);
        return;
    }
    serverCmdInfo.serverNumber = (UINT8)number;
}
/*********************************************************************
 * Function: Get related info from the server xxx command line
 * Input: type: type
 *       argValue: argument value
 * Output: serverCmdInfo: server related info
 * Return: None
 * *******************************************************************/
VOID PCL_UpdateServerCmdInfo(UINT32 type, const char* argValue, PclServerCmdInfo &serverCmdInfo)
{
    switch(type) {
        case SERVER_CMD_ARG_NUMBER:
            PCL_UpdateServerNumberInfo(argValue, serverCmdInfo);
            break;
        default:
            break;
    }
}
/*********************************************************************
 * Function: Get related info from the server xxx command line
 * Input: argName: argument name
 *       serverCmdInfo: server related info
 * Output: None
 * Return: argument type
 * *******************************************************************/
UINT32 PCL_GetServerCmdArgType(const char *argName, PclServerCmdInfo &serverCmdInfo)
{
    if (strcmp(argName, "number") == 0) {
        serverCmdInfo.subCmd = PCL_NDN_ENTRY_ADD_MOD;
        return SERVER_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "show") == 0) {
        serverCmdInfo.subCmd = PCL_NDN_ENTRY_SHOW;
        return SERVER_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "nums") == 0) {
        serverCmdInfo.subkey = SERVER_SUBKEY_NUMBER;
        return SERVER_CMD_ARG_NUMBER;
    }
    if (strcmp(argName, "type") == 0) {
        return SERVER_CMD_ARG_SKIP;
    }
    if (strcmp(argName, "number") == 0) {
        return SERVER_CMD_ARG_SKIP;
    }
    bfshell_printf(serverCmdInfo.clishContext, "Error: can not process arg:%s\n", argName);
    return SERVER_CMD_ARG_BUT;
}
/*********************************************************************
 * Function: Get related info from the server xxx command line
 * Input: cmdInfo: command related info pointer
 * Output: serverCmdInfo: server related info
 * Return: None
 * *******************************************************************/
VOID PCL_GetServerInfoFromCmd(const PclNdnCmdInfo *cmdInfo, PclServerCmdInfo &serverCmdInfo)
{
    UINT32 type = 0;
    serverCmdInfo.clishContext = cmdInfo->clishContext;
    for (UINT32 index = 0; index < cmdInfo->argNum; index++) {
        type = PCL_GetServerCmdArgType(cmdInfo->argNames[index], serverCmdInfo);
        PCL_UpdateServerCmdInfo(type, cmdInfo->argValues[index], serverCmdInfo);
    }
}
/*********************************************************************
 * Function: server xxx command line processing
 * Input: cmdInfo: command line info
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_ProcServerCmd(const PclNdnCmdInfo *cmdInfo)
{
    PclServerCmdInfo serverCmdInfo = {0};

    PCL_GetServerInfoFromCmd(cmdInfo, serverCmdInfo);
    if (serverCmdInfo.parseResult != PCL_OK) {
        return PCL_OK;
    }
    switch (serverCmdInfo.subCmd) {
        case PCL_NDN_ENTRY_ADD_MOD:
            PCL_ProcServerUpdateCmd(serverCmdInfo);
            break;
        case PCL_NDN_ENTRY_SHOW:
            PCLNDN_ShowServerNum(serverCmdInfo);
            break;
        default:
            bfshell_printf(serverCmdInfo.clishContext, "Error: not support now\n");
            break;
    }

    return PCL_OK;
}


const PclNdnCmdProcMngInfo g_pclNdnCmdProc[PCL_NDN_CMD_BUT] = {
    { "pcct",                 PCLNDN_ProcPcctCmd              },
    { "mac",                  PCLNDN_ProcMacCmd               },
    { "bitmap",               PCLNDN_ProcBitmapCmd            },
    { "port",                 PCLNDN_ProcPortCmd              },
    { "group",                PCLNDN_ProcGroupCmd             },
    { "server",               PCLNDN_ProcServerCmd            }
};

/*********************************************************************
 * Function: Get the index according to the command line name
 * Input: cmdName: command line name
 * Output: None
 * Return: None
 * *******************************************************************/
UINT32 PCLNDN_GetCommandIndex(string cmdName)
{
    for (UINT32 index = 0; index < PCL_NDN_CMD_BUT; index++) {
        if (cmdName == g_pclNdnCmdProc[index].cmdName) {
            return index;
        }
    }
    return PCL_NDN_CMD_BUT;
}
/*********************************************************************
 * Function: Command line related processing
 * Input: cmdInfo: command line info
 * Output: None
 * Return: None
 * *******************************************************************/
extern "C" VOID PCLNDN_ProcCommandInfo(const PclNdnCmdInfo *cmdInfo)
{
    UINT32 cmdIndex = PCLNDN_GetCommandIndex(cmdInfo->commandName);
#if 0
    printf("Info: processing command %s with index:%u. Paras info:\n", cmdInfo->commandName, cmdIndex);
    for (UINT32 index = 0; index < cmdInfo->argNum; index++) {
        printf(" para:%u, name:%s, value:%s\n", index, cmdInfo->argNames[index], cmdInfo->argValues[index]);
    }
#endif
    if ((cmdIndex < PCL_NDN_CMD_BUT) && (g_pclNdnCmdProc[cmdIndex].cmdProc != NULL)) {
        g_pclNdnCmdProc[cmdIndex].cmdProc(cmdInfo);
    }
    g_session->sessionCompleteOperations();
}
