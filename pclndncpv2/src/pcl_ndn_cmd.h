/***************************************************************
 * Name:      pcl_ndn_cmd.h
 * Purpose:   Command line related statements
 **************************************************************/
#ifndef __PCL_NDN_CMD_H__
#define __PCL_NDN_CMD_H__

#include "pubdef.h"

#define PCL_NDN_MAX_CMD_PARAMS 16

typedef enum {
    PCL_NDN_CMD_PIT_SHOW,             /* pit-show */
    PCL_NDN_CMD_MAC,                  /* mac XXX */
    PCL_NDN_CMD_BITMAP,               /* bitmap XXX */
    PCL_NDN_CMD_PORT,                 /* port XXX */
    PCL_NDN_CMD_GROUP,                /* group XXX */
    PCL_NDN_CMD_SERVER,                /* group XXX */
    PCL_NDN_CMD_BUT
} PclNdnCmdType;

typedef struct {
    UINT32 argNum;       /* Number of arguments */
    void *clishContext;  /* command line context */
    char *commandName;   /* Name of command */
    char *argNames[PCL_NDN_MAX_CMD_PARAMS]; /* Array of arg names */
    char *argValues[PCL_NDN_MAX_CMD_PARAMS]; /* Array of arg values */
} PclNdnCmdInfo;


#endif // __PCL_NDN_CMD_H__
