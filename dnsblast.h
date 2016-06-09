
#ifndef __DNSBLAST_H__
#define __DNSBLAST_H__ 1

#define _POSIX_C_SOURCE 200112L

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netdb.h>
#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "dns.h"

#define MAX_UDP_DATA_SIZE    (0xffff - 20U - 8U)

#ifndef UPDATE_STATUS_PERIOD
# define UPDATE_STATUS_PERIOD 500000000ULL
#endif

#ifndef MAX_UDP_BUFFER_SIZE
# define MAX_UDP_BUFFER_SIZE  (16 * 1024 * 1024)
#endif

#define REPEATED_NAME_PROBABILITY (int) ((RAND_MAX * 13854LL) / 100000LL)
#define REFUZZ_PROBABILITY (int) ((RAND_MAX * 500LL) / 100000LL)

typedef struct Context_ {
    unsigned char          question[MAX_UDP_DATA_SIZE];
    const struct addrinfo *ai;
    unsigned long long     last_status_update;
    unsigned long long     startup_date;
    unsigned long          pps;
    unsigned long          received_packets;
    unsigned long          sent_packets;
    int                    sock;
    uint16_t               id;
    _Bool                  fuzz;
    _Bool                  sending;
} Context;

typedef struct WeightedType_ {
    int      weight;
    uint16_t type;
} WeightedType;

const WeightedType weighted_types[] = {
    { .type = TYPE_A,    .weight = (int) ((RAND_MAX * 77662LL) / 100000LL) },
    { .type = TYPE_SOA,  .weight = (int) ((RAND_MAX *   803LL) / 100000LL) },
    { .type = TYPE_MX,   .weight = (int) ((RAND_MAX *  5073LL) / 100000LL) },
    { .type = TYPE_TXT,  .weight = (int) ((RAND_MAX *  2604LL) / 100000LL) },
    { .type = TYPE_AAAA, .weight = (int) ((RAND_MAX * 13858LL) / 100000LL) }
};

#ifndef SO_RCVBUFFORCE
# define SO_RCVBUFFORCE SO_RCVBUF
#endif
#ifndef SO_SNDBUFFORCE
# define SO_SNDBUFFORCE SO_SNDBUF
#endif

#endif
