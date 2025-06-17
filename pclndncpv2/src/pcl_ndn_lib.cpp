/***************************************************************
 * Name:      pcl_ndn_switch.cpp
 * Purpose:   Pegasus switch main interface processing related
 **************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <sched.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include "pubdef.h"
#include "pcl_ndn_cp.h"

using namespace std;
bf_switchd_context_t g_switchdContex;
pthread_t g_backgroudThread;

/*********************************************************************
 * Function: Switch context initialization
 * Input: None
 * Output: None
 * Return: 0: Run successfully, Others: Abnormality occurs
 * *******************************************************************/
INT32 PCL_InitBfSwitchd(const char *progname)
{
    bf_status_t bf_status = 0;
    char *install_dir = getenv("SDE_INSTALL");
    char target_conf_file[128] = {0};
    bf_switchd_context_t* switchdContex = &g_switchdContex;

#ifdef TNA_TOFINO
    sprintf(target_conf_file, "%s/share/p4/targets/tofino/%s.conf", install_dir, progname);
#else
    sprintf(target_conf_file, "%s/share/p4/targets/tofino2/%s.conf", install_dir, progname);
#endif
    memset(&g_switchdContex, 0, sizeof(bf_switchd_context_t));
    g_switchdContex.install_dir = install_dir;
    g_switchdContex.conf_file = target_conf_file;
    g_switchdContex.skip_p4 = false;
    g_switchdContex.skip_port_add = false;
    g_switchdContex.dev_sts_thread = true;
    g_switchdContex.dev_sts_port = THRIFT_PORT_NUM;

    bf_status = bf_switchd_lib_init(&g_switchdContex);
    printf("PCLNDN: Initialized bf_switchd, status:%d, switch context:%p\n", bf_status, switchdContex);
    return bf_status;
}

/*********************************************************************
 * Function: Custom background thread startup
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID* PCLNDN_PclBackgroudThreadProc(VOID *args)
{
    printf("Info: pcl ndn backgroud thread start.\n");
    PCLNDN_InitPort();
    PCLNDN_InitPktDriverCallback();
    PCLNDN_InitTables();
    PCLNDN_InitTableEntry();
    printf("Info: pcl ndn router start successful.\nPlease use the CLI interface to control.\n");
}

/*********************************************************************
 * Function: program entry
 * Input:   appPath: App running path
 *          progname: P4 program name
 * Output: None
 * Return: 0: Run successfully, Others: Abnormality occurs
 * *******************************************************************/
INT32 PCLNDN_LibInit(const char *appPath, const char *progname)
{
    bf_status_t bf_status = 0;

    PCLNDN_InitDeviceManager(appPath, PCL_NDN_INIT_WITH_DEFAULT);
    bf_status = PCL_InitBfSwitchd(progname);
    if (bf_status != PCL_OK) {
        printf("Switchd lib init fail, the app will exit\n");
        return PCL_ERROR;
    }

    PCLNDN_SetUpBfrt(progname);
    INT32 ret = 0;
    static pthread_attr_t tmr_t_attr;
    pthread_attr_init(&tmr_t_attr);
    ret = pthread_create(&g_backgroudThread, &tmr_t_attr, PCLNDN_PclBackgroudThreadProc, NULL);
    if  (ret != PCL_OK) {
        printf("Error: PCLNDN lib init fail, create back groud thread failed as 0x%x\n", ret);
        return ret;
    }
    pthread_setname_np(g_backgroudThread, "pclndn_backgroud");
    return PCL_OK;
}

/*********************************************************************
 * Function: Switch initialization post-processing
 * Input: None
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_LibInitPostProc()
{
    pthread_join(g_backgroudThread, NULL);

    /* wait for thread */
    pthread_join(g_switchdContex.tmr_t_id, NULL);
    pthread_join(g_switchdContex.dma_t_id, NULL);
    pthread_join(g_switchdContex.int_t_id, NULL);
    pthread_join(g_switchdContex.pkt_t_id, NULL);
    pthread_join(g_switchdContex.port_fsm_t_id, NULL);
    pthread_join(g_switchdContex.drusim_t_id, NULL);
    pthread_join(g_switchdContex.accton_diag_t_id, NULL);
    for (UINT32 index = 0; index < PCL_SWITCHD_MAX_AGENTS; index++) {
        if (g_switchdContex.agent_t_id[index] != 0) {
            pthread_join(g_switchdContex.agent_t_id[index], NULL);
        }
    }
    printf("PCLNDN: All thread joined\n");
}

/*********************************************************************
 * Function: Program exit notification
 * Input: signum: Exit semaphore
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_LibExit(int signum)
{
    /* Notify Exit */
    printf("Switchd lib exit with signum %d\n", signum);
    bf_switchd_exit_sighandler(signum);
    PCLNDN_LibExitProc();
}
