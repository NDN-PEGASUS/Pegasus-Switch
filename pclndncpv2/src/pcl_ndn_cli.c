/***************************************************************
 * Name:      pcl_ndn_cli.cpp
 * Purpose:   Pegasus switch command line processing plugin, 
 *            generate so file separately
 **************************************************************/
#include <stdio.h>
#ifdef SDE_9XX_OLD
#include <bfutils/clish/shell.h>
#else
#include <target-utils/clish/shell.h>
#endif  

extern void reg_set_instream(FILE *);
extern void reg_set_outstream(FILE *);
extern void PCLNDN_ProcessCliCommand(void *clish_context); // from pcl_ndn_cmd.c
CLISH_PLUGIN_SYM(pclndn_cmd) {
    (void)script;
    (void)out;
    clish_shell_t *shell = clish_context__get_shell(clish_context);
    //tinyrl_t *tinyrl = clish_shell__get_tinyrl(shell);
    //reg_set_instream(tinyrl__get_istream(tinyrl));
    //reg_set_outstream(tinyrl__get_ostream(tinyrl));
    /* command line processing */
    PCLNDN_ProcessCliCommand(clish_context);
    //reg_set_instream(stdin);
    //reg_set_outstream(stdout);
    return 0;
}

CLISH_PLUGIN_INIT(pclndn) {
    (void)clish_shell;
    clish_plugin_add_sym(plugin, pclndn_cmd, "pclndn_cmd");
    return 0;
}
