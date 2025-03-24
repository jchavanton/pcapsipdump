#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <arpa/inet.h>

#include "pcapsipdump_lib.h"
#include "pcapsipdump_endian.h"
#include "pcapsipdump.h"

extern int verbosity;

// equivalent of "mkdir -p"
int mkdir_p(const char *path, mode_t mode) {
    char s[256];
    char *p;
    struct stat sb;

    if (stat(path, &sb) == 0) {
        return 0;
    } else {
        strlcpy(s, path, sizeof(s));
        p = strrchr(s, '/');
        if (p != NULL) {
            *p = '\0';
            if (mkdir_p(s, mode) != 0) {
                return -1;
            }
        }
        return mkdir(path, mode);
    }
    return -1;
}


size_t expand_dir_template(char *s, size_t max, const char *format,
                           const char *from,
                           const char *to,
                           const char *callid,
                           const time_t t) {
    struct tm *tm = localtime(&t);
    size_t fl = strlen(format);
    size_t s1l = fl + 256;
    char *s1 = (char *)malloc(s1l);
    char *s1p = s1;
    char asciisan[128] = {
        '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_',
        '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_', '_',
        '_', '_', '_', '#', '_', '_', '&', '_', '(', ')', '_', '+', ',', '-', '.', '_',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '_', ';', '_', '=', '_', '_',
        '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
        'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '_', ']', '^', '_',
        '_', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
        'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '_', '}', '~', '_'
    };
    for (size_t i = 0; i <= fl; i++) {
        char c0 = format[i];
        if (c0 == '%' && i < fl - 1) {
            char c1 = format[i+1];
            if (c1 == 'f' && (s1l - (s1p - s1)) > strlen(from) ){
                strcpy(s1p, from);
                for(;*s1p;s1p++){
                    *s1p = asciisan[*s1p & 0x7f];
                }
                i++;
            } else if (c1 == 't' && (s1l - (s1p - s1)) > strlen(to) ){
                strcpy(s1p, to);
                for(;*s1p;s1p++){
                    *s1p = asciisan[*s1p & 0x7f];
                }
                i++;
            } else if (c1 == 'i' && (s1l - (s1p - s1)) > strlen(callid) ){
                strcpy(s1p, callid);
                for(;*s1p;s1p++){
                    *s1p = asciisan[*s1p & 0x7f];
                }
                i++;
            } else {
                *(s1p++) = c0;
            }
        } else {
            *(s1p++) = c0;
        }
    }
    {
        size_t r = strftime(s, max, s1, tm);
        free(s1);
        return r;
    }
}


int opts_sanity_check_d(char **opt_fntemplate)
{
    char s[2048];
    char *orig_opt_fntemplate = *opt_fntemplate;
    struct stat sb;
    FILE *f;

    expand_dir_template(s, sizeof(s), *opt_fntemplate, "", "", "", (int)time(NULL));
    if (stat(s, &sb) == 0) {
        if (!S_ISDIR(sb.st_mode)) {
            fprintf(stderr, "Bad option '-d %s': File exists (expecting directory name or filename template)", orig_opt_fntemplate);
            return(2);
        }
        // Looks like user has specified bare directory in '-d' option.
        // First, make sure we can create files in that directory
        strcat(s, "/tmp-siJNlSdiugQ3iyjaPNW");
        if ((f = fopen(s, "a")) == NULL){
            fprintf(stderr, "Can't create file for '-d %s': ", orig_opt_fntemplate);
            perror (s);
            return(2);
        }
        fclose(f);
        unlink(s);
        // Then append some default filename template to be backwards-compatible
        *opt_fntemplate = (char *)malloc(strlen(s) + 128);
        strcpy(*opt_fntemplate, orig_opt_fntemplate);
        strcat(*opt_fntemplate, "/%Y%m%d/%H/%Y%m%d-%H%M%S-%f-%t-%i.pcap");
        expand_dir_template(s, sizeof(s), orig_opt_fntemplate, "", "", "", 0);
    } else {
        if (!strchr(*opt_fntemplate, '%') || !strchr(s, '/')) {
            fprintf(stderr, "Bad option '-d %s': Neither directory nor filename template", orig_opt_fntemplate);
            return(2);
        // (try to) create directory hierarchy
        } else if (mkdir_p(dirname(s), 0777)) {
            fprintf(stderr, "Can't create directory for '-d %s': ", orig_opt_fntemplate);
            perror (s);
            return(2);
        }
    }
    return(0);
}

struct iphdr* ethernet_get_header_ip(const void *pkt_data){
    // skip source & destination MACs (12 bytes = 6 uint16s)
    const uint16_t *pkt_ethertype = ((uint16_t *)pkt_data) + 6;
    // possible 802.1Q, 802.1ad, and Q-in-Q formats:
    // as indexed from pkt_ethertype[]:
    //   [0]    [1]   [2]  [3]   [4]  [5]
    // 0x0800  IP                         <- untagged
    // 0x86dd  IP6                        <- untagged IPv6
    // 0x8100  tag   0x0800 IP            <- 802.1Q
    // 0x8100  tag   0x88dd IP6           <- 802.1Q, then IPv6
    // 0x8100  tag   0x8864 ..  ..     .. <- 802.1Q, then PPPoE
    // 0x8100  tag   0x8100 tag 0x0800 IP <- non-standard Q-in-Q
    // 0x9100  tag   0x8100 tag 0x0800 IP <- old standard Q-in-Q
    // 0x88a8  tag   0x8100 tag 0x0800 IP <- 802.1ad Q-in-Q
    // 0x8864 0x1100 sessid len 0x0021 IP <- RFC2516 PPPoE Session Stage IPv4
    // 0x8864 0x1100 sessid len 0x0057 IP <- RFC2516 PPPoE Session Stage IPv6
    switch(pkt_ethertype[0]){
        case HTONS(0x0800):
            return (struct iphdr*)(pkt_ethertype + 1);
        case HTONS(0x86dd):
            return (struct iphdr*)(pkt_ethertype + 1);
        case HTONS(0x8100):
            if (pkt_ethertype[2] == htons(0x0800) ||
                pkt_ethertype[2] == htons(0x86dd)){
                return (struct iphdr*)(pkt_ethertype + 3);
            } else if (pkt_ethertype[2] == htons(0x8864)){
                // recurse
                return ethernet_get_header_ip((uint16_t *)pkt_data+2);
            }
            // fallthrough
        case HTONS(0x9100):
            // fallthrough
        case HTONS(0x88a8):
            if (pkt_ethertype[2] == htons(0x8100) &&
                pkt_ethertype[4] == htons(0x0800)){
                return (struct iphdr*)(pkt_ethertype + 5);
            }
            goto fail;
        case HTONS(0x8864):
            if (pkt_ethertype[1] == htons(0x1100) &&
                (pkt_ethertype[4] == htons(0x0021) ||
                 pkt_ethertype[4] == htons(0x0057))){
                return (struct iphdr*)(pkt_ethertype + 5);
            }
            if (pkt_ethertype[4] == htons(0xc021)){ // LCP
                return NULL;
            }
    }
fail:
    // bail on unfamiliar ethertype
    if(verbosity >= 4){
        printf("Can't parse Ethernet tags: %04x %04x %04x %04x %04x %04x\n",
            htons(pkt_ethertype[0]),
            htons(pkt_ethertype[1]),
            htons(pkt_ethertype[2]),
            htons(pkt_ethertype[3]),
            htons(pkt_ethertype[4]),
            htons(pkt_ethertype[5]));
    }
    return NULL;
}

struct iphdr* skip_tunnel_ip_header(struct iphdr* ip){
    struct ipv6hdr *ipv6 = (ipv6hdr*)ip;

    if(ipv6->version == 6 && ipv6->nexthdr == 4){
        return (iphdr*)(((char*)ip)+sizeof(*ipv6));
    }
    return (struct iphdr*)ip;
}
