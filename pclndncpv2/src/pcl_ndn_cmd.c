/***************************************************************
 * Name:      pcl_ndn_cmd.c
 * Purpose:   Pegasus switch command line processing entry
 **************************************************************/
#include <stdio.h>
#ifdef SDE_9XX_OLD
#include <bfutils/clish/shell.h>
#else
#include <target-utils/clish/shell.h>
#endif
#include "pcl_ndn_cmd.h"

extern void PCLNDN_ProcCommandInfo(const PclNdnCmdInfo *cmdInfo);   // from pcl_ndn_cp.cpp

/*********************************************************************
 * Function: Command line processing entry
 * Input: clish_context: command line context
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ProcessCliCommand(void *clish_context)
{
    PclNdnCmdInfo cmdInfo = { 0 };

    const clish_command_t *command = clish_context__get_cmd(clish_context);
    if (command != NULL) {
        cmdInfo.commandName = (char *)clish_command__get_name(command);
    } else {
        bfshell_printf(clish_context, "Error: get command name NULL\n");
        return;
    }

    clish_pargv_t *pargv_t = clish_context__get_pargv(clish_context);
    if (pargv_t != NULL) {
        cmdInfo.argNum = clish_pargv__get_count(pargv_t);
        if (cmdInfo.argNum >= PCL_NDN_MAX_CMD_PARAMS) {
            bfshell_printf(clish_context, "Error: command args num fail as we support %u params, current is:%u\n", PCL_NDN_MAX_CMD_PARAMS, cmdInfo.argNum);
            return;
        }
        for (UINT32 i = 0; i < cmdInfo.argNum; i++) {
            clish_parg_t *parg_t = clish_pargv__get_parg(pargv_t, i);
            cmdInfo.argNames[i] = (char *)clish_parg__get_name(parg_t);
            cmdInfo.argValues[i] = (char *)clish_parg__get_value(parg_t);
        }
    } else {
        bfshell_printf(clish_context, "Error: get command args fail\n");
        return;
    }
    cmdInfo.clishContext = clish_context;
    /* Call internal processing */
    PCLNDN_ProcCommandInfo(&cmdInfo);
}
