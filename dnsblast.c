
#include "dnsblast.h"

static unsigned long long
get_nanoseconds(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;
}

static int
init_context(Context * const context, const int sock,
             const struct addrinfo * const ai, const _Bool fuzz)
{
    const unsigned long long now = get_nanoseconds();
    *context = (Context) {
        .received_packets = 0UL, .sent_packets = 0UL,
        .last_status_update = now, .startup_date = now,
        .sock = sock, .ai = ai, .fuzz = fuzz, .sending = 1
    };

    DNS_Header * const question_header = (DNS_Header *) context->question;
    *question_header = (DNS_Header) {
        .flags = htons(FLAGS_OPCODE_QUERY | FLAGS_RECURSION_DESIRED),
        .qdcount = htons(1U), .ancount = 0U, .nscount = 0U, .arcount = 0U
    };

    return 0;
}

static int
find_name_component_len(const char *name)
{
    int name_pos = 0;

    while (name[name_pos] != '.' && name[name_pos] != 0) {
        if (name_pos >= UCHAR_MAX) {
            return EOF;
        }
        name_pos++;
    }
    return name_pos;
}

static int
encode_name(unsigned char ** const encoded_ptr, size_t encoded_size,
            const char * const name)
{
    unsigned char *encoded = *encoded_ptr;
    const char    *name_current = name;
    int            name_current_pos;

    assert(encoded_size > (size_t) 0U);
    encoded_size--;
    for (;;) {
        name_current_pos = find_name_component_len(name_current);
        if (name_current_pos == EOF ||
            encoded_size <= (size_t) name_current_pos) {
            return -1;
        }
        *encoded++ = (unsigned char) name_current_pos;
        memcpy(encoded, name_current, name_current_pos);
        encoded_size -= name_current_pos - (size_t) 1U;
        encoded += name_current_pos;
        if (name_current[name_current_pos] == 0) {
            break;
        }
        name_current += name_current_pos + 1U;
    }
    *encoded++ = 0;
    *encoded_ptr = encoded;

    return 0;
}

static int
fuzz(unsigned char * const question, const size_t packet_size)
{
    int p = REFUZZ_PROBABILITY;

    do {
        question[rand() % packet_size] = rand() % 0xff;
    } while (rand() < p && (p = p / 2) > 0);

    return 0;
}

static int
blast(Context * const context, const char * const name, const uint16_t type)
{
    unsigned char * const question = context->question;
    DNS_Header    * const question_header = (DNS_Header *) question;
    unsigned char * const question_data = question + sizeof *question_header;
    const size_t          sizeof_question_data =
        sizeof question - sizeof *question_header;

    question_header->id = context->id++;
    unsigned char *msg = question_data;
    assert(sizeof_question_data > (size_t) 2U);
    encode_name(&msg, sizeof_question_data - (size_t) 2U, name);
    PUT_HTONS(msg, type);
    PUT_HTONS(msg, CLASS_IN);
    const size_t packet_size = (size_t) (msg - question);

    if (context->fuzz != 0) {
        fuzz(question, packet_size);
    }
    while (sendto(context->sock, question, packet_size, 0,
                  context->ai->ai_addr, context->ai->ai_addrlen)
           != (ssize_t) packet_size) {
        if (errno != EAGAIN && errno != EINTR) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }
    }
    context->sent_packets++;

    return 0;
}

static void
usage(void) {
    puts("\nUsage: dnsblast [fuzz] <host> [<count>] [<pps>] [<port>]\n");
    exit(EXIT_SUCCESS);
}

static struct addrinfo *
resolve(const char * const host, const char * const port)
{
    struct addrinfo *ai, hints;

    memset(&hints, 0, sizeof hints);
    hints = (struct addrinfo) {
        .ai_family = AF_UNSPEC, .ai_flags = 0, .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };
    const int gai_err = getaddrinfo(host, port, &hints, &ai);
    if (gai_err != 0) {
        fprintf(stderr, "[%s:%s]: [%s]\n", host, port, gai_strerror(gai_err));
        exit(EXIT_FAILURE);
    }
    return ai;
}

static int
get_random_name(char * const name, size_t name_size)
{
    const char charset_alnum[36] = "abcdefghijklmnopqrstuvwxyz0123456789";

    assert(name_size > (size_t) 8U);
    const int r1 = rand(), r2 = rand();
    name[0] = charset_alnum[(r1) % sizeof charset_alnum];
    name[1] = charset_alnum[(r1 >> 16) % sizeof charset_alnum];
    name[2] = charset_alnum[(r2) % sizeof charset_alnum];
    name[3] = charset_alnum[(r2 >> 16) % sizeof charset_alnum];
    name[4] = '.';    name[5] = 'c';    name[6] = 'o';    name[7] = 'm';
    name[8] = 0;

    return 0;
}

static uint16_t
get_random_type(void)
{
    const size_t weighted_types_len =
        sizeof weighted_types / sizeof weighted_types[0];
    size_t       i = 0U;
    const int    rnd = rand();
    int          pos = RAND_MAX;

    do {
        pos -= weighted_types[i].weight;
        if (rnd > pos) {
            return weighted_types[i].type;
        }
    } while (++i < weighted_types_len);

    return weighted_types[rand() % weighted_types_len].type;
}

static int
get_sock(const char * const host, const char * const port,
         struct addrinfo ** const ai_ref)
{
    int flag = 1;
    int sock;

    *ai_ref = resolve(host, port);
    sock = socket((*ai_ref)->ai_family, (*ai_ref)->ai_socktype,
                  (*ai_ref)->ai_protocol);
    if (sock == -1) {
        return -1;
    }
    setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE,
               &(int[]) { MAX_UDP_BUFFER_SIZE }, sizeof (int));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE,
               &(int[]) { MAX_UDP_BUFFER_SIZE }, sizeof (int));
#if defined(IP_PMTUDISC_OMIT)
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER,
               &(int[]) { IP_PMTUDISC_OMIT }, sizeof (int));
#elif defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER,
               &(int[]) { IP_PMTUDISC_DONT }, sizeof (int));
#elif defined(IP_DONTFRAG)
    setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, &(int[]) { 0 }, sizeof (int));
#endif
    assert(ioctl(sock, FIONBIO, &flag) == 0);

    return sock;
}

static int
receive(Context * const context)
{
    unsigned char buf[MAX_UDP_DATA_SIZE];

    while (recv(context->sock, buf, sizeof buf, 0) == (ssize_t) -1) {
        if (errno == EAGAIN) {
            return 1;
        }
        assert(errno == EINTR);
    }
    context->received_packets++;

    return 0;
}

static int
update_status(const Context * const context)
{
    const unsigned long long now = get_nanoseconds();
    const unsigned long long elapsed = now - context->startup_date;
    unsigned long long rate =
        context->received_packets * 1000000000ULL / elapsed;
    if (rate > context->pps) {
        rate = context->pps;
    }
    printf("Sent: [%lu] - Received: [%lu] - Reply rate: [%llu pps] - "
           "Ratio: [%.2f%%]  \r",
           context->sent_packets, context->received_packets, rate,
           (double) context->received_packets * 100.0 /
           (double) context->sent_packets);
    fflush(stdout);

    return 0;
}

static int
periodically_update_status(Context * const context)
{
    unsigned long long now = get_nanoseconds();

    if (now - context->last_status_update < UPDATE_STATUS_PERIOD) {
        return 1;
    }
    update_status(context);
    context->last_status_update = now;

    return 0;
}

static int
empty_receive_queue(Context * const context)
{
    while (receive(context) == 0)
        ;
    periodically_update_status(context);

    return 0;
}

static int
throttled_receive(Context * const context)
{
    unsigned long long       now = get_nanoseconds(), now2;
    const unsigned long long elapsed = now - context->startup_date;
    const unsigned long long max_packets =
        context->pps * elapsed / 1000000000UL;

    if (context->sending == 1 && context->sent_packets <= max_packets) {
        empty_receive_queue(context);
    }
    const unsigned long long excess = context->sent_packets - max_packets;
    const unsigned long long time_to_wait = excess / context->pps;
    int                      remaining_time = (int) (time_to_wait * 1000ULL);
    int                      ret;
    struct pollfd            pfd = { .fd = context->sock,
                                     .events = POLLIN | POLLERR };
    if (context->sending == 0) {
        remaining_time = -1;
    } else if (remaining_time < 0) {
        remaining_time = 0;
    }
    do {
        ret = poll(&pfd, (nfds_t) 1, remaining_time);
        if (ret == 0) {
            periodically_update_status(context);
            return 0;
        }
        if (ret == -1) {
            if (errno != EAGAIN && errno != EINTR) {
                perror("poll");
                exit(EXIT_FAILURE);
            }
            continue;
        }
        assert(ret == 1);
        empty_receive_queue(context);
        now2 = get_nanoseconds();
        remaining_time -= (now2 - now) / 1000;
        now = now2;
    } while (remaining_time > 0);

    return 0;
}

int
main(int argc, char *argv[])
{
    char             name[100U] = ".";
    Context          context;
    struct addrinfo *ai;
    const char      *host;
    const char      *port = "domain";
    unsigned long    pps        = ULONG_MAX;
    unsigned long    send_count = ULONG_MAX;
    int              sock;
    uint16_t         type;
    _Bool            fuzz = 0;

    if (argc < 2 || argc > 6) {
        usage();
    }
    if (strcasecmp(argv[1], "fuzz") == 0) {
        fuzz = 1;
        argv++;
        argc--;
    }
    if (argc < 1) {
        usage();
    }
    host = argv[1];
    if (argc > 2) {
        send_count = strtoul(argv[2], NULL, 10);
    }
    if (argc > 3) {
        pps = strtoul(argv[3], NULL, 10);
    }
    if (argc > 4) {
        port = argv[4];
    }
    if ((sock = get_sock(host, port, &ai)) == -1) {
        perror("Oops");
        exit(EXIT_FAILURE);
    }
    init_context(&context, sock, ai, fuzz);
    context.pps = pps;
    srand(0U);
    assert(send_count > 0UL);
    do {
        if (rand() > REPEATED_NAME_PROBABILITY) {
            get_random_name(name, sizeof name);
        }
        type = get_random_type();
        blast(&context, name, type);
        throttled_receive(&context);
    } while (--send_count > 0UL);
    update_status(&context);

    context.sending = 0;
    while (context.sent_packets != context.received_packets) {
        throttled_receive(&context);
    }
    freeaddrinfo(ai);
    assert(close(sock) == 0);
    update_status(&context);
    putchar('\n');

    return 0;
}
