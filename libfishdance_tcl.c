#include "XSalsa20Poly1305.h"
#include <tcl.h>
#include <sodium.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>

static int
Fishdance_encrypt_Cmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    if (objc != 3)
        return TCL_ERROR;
    const char *key = Tcl_GetString(objv[1]);
    const char *str = Tcl_GetString(objv[2]);
    char bf_dest[1000] = "";
    char *dest;
    int len = strlen(str);
    if (!key || !key[0])
        return 0;
    strcpy(bf_dest, "+OK ");
    encrypt_string_xs(key, str, bf_dest + 4, strlen(str));
    Tcl_SetObjResult(interp, Tcl_NewStringObj(bf_dest, -1));
    return TCL_OK;
}

static int
Fishdance_decrypt_Cmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    if (objc != 3)
        return TCL_ERROR;
    const char *key = Tcl_GetString(objv[1]);
    const char *str = Tcl_GetString(objv[2]);
    char bf_dest[1000] = "";
    char *dest;
    int len = strlen(str);
    if (!key || !key[0])
        return 0;
    decrypt_string_xs(key, str, bf_dest, strlen(str));
    Tcl_SetObjResult(interp, Tcl_NewStringObj(bf_dest, -1));
    return TCL_OK;
}

int DLLEXPORT
Fishdance_Init(Tcl_Interp *interp)
{
    Tcl_Namespace *nsPtr; /* pointer to hold our own new namespace */

    if (Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL) {
        return TCL_ERROR;
    }

    /* create the namespace  */
    nsPtr = Tcl_CreateNamespace(interp, "fishdance", NULL, NULL);
    if (nsPtr == NULL) {
        return TCL_ERROR;
    }
    /* fishdance::encrypt KEY MESSAGE */
    Tcl_CreateObjCommand(interp, "fishdance::encrypt", Fishdance_encrypt_Cmd, NULL, NULL);
    /* fishdance::decrypt KEY ENCRYPTED_MESSAGE */
    Tcl_CreateObjCommand(interp, "fishdance::decrypt", Fishdance_decrypt_Cmd, NULL, NULL);
    Tcl_PkgProvide(interp, "fishdance", "1.0");
    return TCL_OK;
}
