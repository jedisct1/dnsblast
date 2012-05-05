
#ifndef __DNS_H__
#define __DNS_H__

#include <sys/types.h>
#include <inttypes.h>

#define TYPE_A     1U
#define TYPE_SOA   6U
#define TYPE_MX   15U
#define TYPE_TXT  16U
#define TYPE_AAAA 28U

#define FLAGS_OPCODE_QUERY 0x0
#define FLAGS_RECURSION_DESIRED 0x100

#define CLASS_IN 1U

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((__packed__)) DNS_Header;

#define PUT_HTONS(dst, val) do { \
    *dst++ = val >> 8; \
    *dst++ = val & 0xff; \
} while (0)

#endif
