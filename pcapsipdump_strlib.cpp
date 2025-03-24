#include <string.h>
#include <stdlib.h>
#include "pcapsipdump_strlib.h"

const char * gettag(const char *ptr, unsigned long len, const char *tag, unsigned long *gettaglen){
    unsigned long tl;
    const char *r, *lp;

    if(len > 1){
        tl = strlen(tag);
        for(r = ptr; r != NULL;){
            r = (const char*)memmem(r+1, len-(r-ptr)-2, tag, tl);
            if(r && (r[-1] == '\r' || r[-1] == '\n')) {
                r += tl;
                while (r[0] == ' ') {
                    r++;
                }
                for(lp = r; lp < (ptr+len); lp++){
                    if(*lp == '\r' || *lp == '\n'){
                        *gettaglen = lp - r;
                        return r;
                    }
                }
            }
        }
    }
    *gettaglen = 0;
    return NULL;
}


uint8_t sdp_get_rtpmap_event(const char *sdp) {
    // a=rtpmap:101 telephone-event/8000
    uint32_t sdp_len = strlen(sdp);
    unsigned long l;
    const char *s;
    const char *te = " telephone-event/";
    int tel = strlen(te);

    s = gettag(sdp, sdp_len, "a=rtpmap:", &l);
    if (s && (strncmp(te, s + 1, tel) == 0 ||
              strncmp(te, s + 2, tel) == 0 ||
              strncmp(te, s + 3, tel) == 0 )) {
        l = atol(s);
        if (l <= 256) {
            return l;
        }
    }
    return 0;
}

