DNSBlast
========

`dnsblast` is a simple and really stupid load testing tool for DNS resolvers.

Give it the IP address of a resolver, the total number of queries you
want to send, the rate (number of packets per second), and `dnsblast`
will tell you how well the resolver is able to keep up.

What it is:
-----------

- a tool to spot bugs in DNS resolvers.
- a tool to help you tune and tweak DNS resolver code in order to
improve it in some way.
- a tool to help you tune and tweak the operating system so that it
can properly cope with a slew of UDP packets.
- a tool to test a resolver with real queries sent to the real and
scary interwebz, not to a sandbox.

What it is not:
---------------

- a tool for DoS'ing resolvers. There are way more efficient ways to
achieve this.
- a benchmarking tool.
- a tool for testing anything but how the server behaves under load.
If you need a serious test suite, take a look at what Unbound
provides.

What it does:
-------------

It sends queries for names like
`<random char><random char><random char><random char>.com`.

Yes, that's 4 random characters dot com. Doing that achieves a
NXDOMAIN vs "oh cool, we got a reply" ratio that is surprisingly close
to the one you get from real queries made by real users.

Different query types are sent. Namely SOA, A, AAAA, MX and TXT, and
the probability that a query type gets picked is also close to its
probability in the real world.

Names are occasionally repeated, also to get closer to what happens in
the real world. That triggers resolver code responsible for queuing
and merging queries.

The test is deterministic: the exact same sequence of packets is sent
every time you fire up `dnsblast`. The magic resides in the power of
the `rand()` function with a fixed seed.

What it does not:
-----------------

It doesn't support DNSSec, it doesn't send anything using TCP, it
doesn't pay attention to the content the resolver sents.

Fuzzing:
--------

In addition, `dnsblast` can send malformed queries.

Most resolvers just ignore these, so don't expect a high
replies/queries ratio. But this feature can also help spotting bugs.

The fuzzer is really, really, really simple, though. It just changes
some random bytes. It doesn't even pay attention to the server's
behavior.

How do I compile it?
--------------------

Type: `make`.

The code it trivial and should be fairly portable, although it only
gets tested on OSX and OpenBSD.

How do I use it?
----------------

To send a shitload of queries to 127.0.0.1:
    dnsblast 127.0.0.1

To send 50,000 queries to 127.0.0.1:

    dnsblast 127.0.0.1 50000

To send 50,000 queries at a rate of 100 queries per second:

    dnsblast 127.0.0.1 50000 100

To send 50,000 queries at a rate of 100 qps to a non standard-port, like 5353:

    dnsblast 127.0.0.1 50000 100 5353

To send malformed packets, prepend "fuzz":

    dnsblast fuzz 127.0.0.1
    dnsblast fuzz 127.0.0.1 50000
    dnsblast fuzz 127.0.0.1 50000 100
    dnsblast fuzz 127.0.0.1 50000 100 5353

If you think that it desperately cries for `getopt()`, you're absolutely correct.

