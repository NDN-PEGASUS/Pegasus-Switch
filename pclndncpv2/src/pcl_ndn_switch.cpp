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
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <string>
#include <getopt.h>
#include<sys/time.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include<vector>
#include <string>
#include <arpa/inet.h>
#include <execinfo.h>
#include "pubdef.h"

using namespace std;

#define PCL_NDN_SIG_TERNINAL_HUP 1
#define PCLNDN_REG_SIG_START SIGINT
#define PCLNDN_REG_SIG_END SIGKILL

extern char *optarg;
string g_p4progname = "pclndndpv2";
char g_tempBuffer[2048] = {0};
UINT32 g_appRunning = PCL_TRUE;
typedef VOID (*PCLNDNSIGNOPROFUNC)(int signo);

extern INT32 PCLNDN_LibInit(const char *appPath, const char *progname);
extern VOID  PCLNDN_LibInitPostProc();
extern VOID  PCLNDN_LibExit(int signum);
/*********************************************************************
 * Function: Parsing command line arguments
 * Input:   argc: number of arguments
 *          argv: value of arguments
 * Output: None
 * Return: None
 * *******************************************************************/
VOID PCLNDN_ProcessArguments(int argc, char *argv[])
{
    int option = 0;

    /* get Input */
    while ((option = getopt(argc, argv, "p:h:")) != EOF) {
        switch (option)
        {
            case 'p':
                /* P4 program */
                g_p4progname = optarg;
                printf("PCL_NDN: get p4 program name= %s\n", g_p4progname.c_str());
                break;
            case 'h':
            case '?':
                exit(SIGTERM);
                break;
        }
    }
}

/*********************************************************************
 * Function: the processing when program exits
 * Input: None
 * Output: None
 * Return: VOID
 * *******************************************************************/
VOID PCLNDN_UiTerminate()
{
    printf("PCLNDN: goodbye, app will exit now.\n");
    return;
}

/*********************************************************************
 * Function: Handling SIGSEGV semaphore
 * Input: None
 * Output: None
 * Return: VOID
 * *******************************************************************/
VOID PCLNDN_ShowSigEgvInfo()
{
    VOID *array[20];
    size_t size;
    char **stacks;
    size_t i;

    size = backtrace(array, 20);
    stacks = backtrace_symbols (array, size);

    for (i = 0; i < size; i++) {
        printf("func: %s\n", stacks[i]);
    }

    free(stacks);
}

/*********************************************************************
 * Function: Determine whether a print call is needed
 * Input: signo: semaphore
 * Output: None
 * Return: OK: print, Others: do not print
 * *******************************************************************/
UINT32 PCLNDN_IfShowStackTrace(int signo)
{
    UINT32 ret = PCL_OK;
    if ((signo >= 1 && signo <= 2) || (signo >= 9 && signo <= 10) || (signo >= 12 && signo <= 16)) {
        ret = PCL_ERROR;
    }
    return ret;
}
/*********************************************************************
 * Function: Processing semaphore
 * Input: signo: semaphore
 * Output: None
 * Return: VOID
 * *******************************************************************/
VOID PCLNDN_SigEnd(int signo)
{
    if (g_appRunning != PCL_TRUE) {
        exit(PCL_OK);
        return;
    }
    printf("receiving sig= %d\n", signo);
    UINT32 ret = PCLNDN_IfShowStackTrace(signo);
    if (ret == PCL_OK) {
#ifdef PCLNDN_DEBUG
        printf("show the call stack trace with sig %d\n", signo);
        PCLNDN_ShowSigEgvInfo();
#endif
    }
    if (signo != PCL_NDN_SIG_TERNINAL_HUP) {
        g_appRunning = PCL_FALSE;
        PCLNDN_LibExit(signo);
        exit(PCL_OK);
    }
}

/*********************************************************************
 * Function: Processing semaphore
 * Input: signo: semaphore
 * Output: None
 * Return: VOID
 * *******************************************************************/
PCLNDNSIGNOPROFUNC PCLNDN_RegSignal(int signo, PCLNDNSIGNOPROFUNC func)
{
    struct sigaction act = {0};
    struct sigaction oact = {0};

    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(signo, &act, &oact ) < 0 ) {
        return SIG_ERR;
    }
    return (oact.sa_handler);
}
/*********************************************************************
 * Function: Semaphore registration processing
 * Input: None
 * Output: None
 * Return: VOID
 * *******************************************************************/
VOID PCLNDN_InitSignalHandler()
{
    /* Set the exit semaphore */
    atexit(PCLNDN_UiTerminate);
    for(int signo = PCLNDN_REG_SIG_START; signo < PCLNDN_REG_SIG_END; signo++ ) {
        if (PCLNDN_RegSignal(signo, PCLNDN_SigEnd) == SIG_ERR) {
            printf("reg signo %u failed...\n", signo);
            exit(PCL_ERROR);
        }
    }
    if (PCLNDN_RegSignal(SIGTERM, PCLNDN_SigEnd) == SIG_ERR) {
        printf("reg signo %u failed...\n", SIGTERM);
        exit(PCL_ERROR);
    }
    if (PCLNDN_RegSignal(SIGSEGV, PCLNDN_SigEnd) == SIG_ERR) {
        printf("reg signo %u failed...\n", SIGSEGV);
        exit(PCL_ERROR);
    }
    if (PCLNDN_RegSignal(SIGPIPE, PCLNDN_SigEnd) == SIG_ERR) {
        printf("reg signo %u failed...\n", SIGPIPE);
        exit(PCL_ERROR);
    }
}
/*********************************************************************
 * Function: Initialize semaphores and add relevant semaphores  
 * Input: None
 * Output: None
 * Return: VOID
 * *******************************************************************/
VOID PCLNDN_SigAddSet(sigset_t &sigset)
{
    /* initialization */
    sigemptyset(&sigset);
    /* Add related semaphores */
    for(int signo = PCLNDN_REG_SIG_START; signo < PCLNDN_REG_SIG_END; signo++ ) {
        sigaddset(&sigset, signo);
    }
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGSEGV);
    sigaddset(&sigset, SIGPIPE);
}
/*********************************************************************
 * Function: main entry
 * Input:   argc: number of arguments
 *          argv: value of arguments
 * Output: None
 * Return: 0: Run successfully, Others: Abnormality occurs
 * *******************************************************************/
int main(int argc, char **argv)
{
    /* Get the current working directory */
    getcwd(g_tempBuffer, sizeof(g_tempBuffer));
    printf("PCL_NDN: App work path is %s\n", g_tempBuffer);
    /* Get command line arguments information */
    PCLNDN_ProcessArguments(argc, argv);

    /* Initialize the semaphore and lock the main thread */
    sigset_t sigset;
    PCLNDN_SigAddSet(sigset);
    INT32 sigRet = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    if (sigRet != 0) {
        printf("ERROR: PCLNDN pthread_sigmask fail as 0x%x", sigRet);
        exit(1);
    }

    /* Register semaphore, process exit, etc. */
    PCLNDN_InitSignalHandler();

    /* start switch */
    INT32 ret = PCLNDN_LibInit(g_tempBuffer, g_p4progname.c_str());

    /* unlock main thread */
    sigRet = pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
    if ((sigRet != 0) || (ret != PCL_OK)) {
        printf("ERROR: PCLNDN start fail as lib init:0x%x, sigmask:0x%x\n", ret, sigRet);
        exit(1);
    }
    /* Set the running state */
    g_appRunning = PCL_TRUE;
    PCLNDN_LibInitPostProc();
    /* The main process enters the waiting state */
    while(1) {
        sleep(10);
        if (g_appRunning != PCL_TRUE) {
            break;
        }
    }
    return 0;
}
