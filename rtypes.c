#include <iostream.h>
#include <stdlib.h>
#include "rtypebase.h"
#include "rtypes.h"

char * A_1(u_char * packet, bpf_u_int32 pos, u_short rdlength) {
    char * data = (char *)malloc(sizeof(char)*16);

    if (rdlength != 4) {
        fprintf(stderr, "Bad A record\n");
        free(data);
        return NULL;
    }
    
    sprintf(data, "%d.%d.%d.%d", packet[pos], packet[pos+1],
                                 packet[pos+2], packet[pos+3]);

    return data;
}


