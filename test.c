#include "ipv6.h"
#include "ipv6_config.h"
#include "ipv6_test_config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

#ifdef HAVE_WINSOCK_2_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#endif

#ifdef HAVE_WS_2_TCPIP_H
#include <ws2tcpip.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#define __USE_MISC
#include <arpa/inet.h>
#endif

#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif

//
// Leading zeros MUST be suppressed.
// For example, 2001:0db8::0001 is not acceptable and must be represented as 2001 : db8::1
// The use of the symbol "::" MUST be used to its maximum capability.
// For example, 2001 : db8 : 0 : 0 : 0 : 0 : 2 : 1 must be shortened to 2001 : db8::2 : 1.
// The symbol "::" MUST NOT be used to shorten just one 16 - bit 0 field.
// For example, the representation 2001 : db8 : 0 : 1 : 1 : 1 : 1 : 1 is correct, but 2001 : db8::1 : 1 : 1 : 1 : 1 is not correct.
// The characters "a", "b", "c", "d", "e", and "f" in an IPv6 address MUST be represented in lowercase.
//
// IPv6 addresses including a port number
// IPv6 addresses including a port number should be enclosed in brackets[rfc5952]:
// [2001:db8:a0b:12f0::1] : 21
//
//
// IPv6 addresses with prefix
// The prefix is appended to the IPv6 address separated by a slash "/" character(CIDR notation)[rfc4291]:
// 2001 : db8 : a0b : 12f0::1 / 64
//
// IPv6 address types
// RFC 4291 defines three types of IPv6 addresses :
//
// ## Unicast
//
//    An identifier for a single interface.A packet sent to a unicast address is delivered to the interface identified by that address.
//    An example for an IPv6 unicast address is 3731 :54 : 65fe : 2::a7
//
// ## Anycast
//
//    An identifier for a set of interfaces(typically belonging to different nodes).A packet sent to an anycast address is
//    delivered to one of the interfaces identified by that address(the "nearest" one, according to the routing protocols' measure of distance).
//    Anycast addresses are allocated from the Unicast address space and are not syntactically distinguishable from unicast addresses.
//
//    An example for an IPv6 Anycast address is 3731:54 : 65fe : 2::a8
//
// ## Multicast
//
//    An identifier for a set of interfaces(typically belonging to different nodes).A packet sent to a multicast address is delivered to all
//    interfaces identified by that address.
//
//    An example for an IPv6 Multicast address is FF01 : 0 : 0 : 0 : 0 : 0 : 0 : 1
//
//    There are no broadcast addresses in IPv6, their function being superseded by multicast addresses.
//

// Capture high level test run status
typedef struct {
    uint32_t                total_tests;
    uint32_t                failed_count;
} test_status_t;

// Structure to represent function over group of tests
typedef struct {
    const char*             name;
    void                    (*func)(test_status_t* status);
} test_group_t;

// Representation of mainline test data
typedef struct {
    const char*             input;
    uint16_t                components[IPV6_NUM_COMPONENTS];
    uint16_t                port;
    uint32_t                mask;
    uint32_t                flags;
} test_data_t;

// Representation of diagnostic test data
typedef struct {
    const char*             input;
    ipv6_diag_event_t       expected_event;
} diag_test_data_t;

typedef struct {
    const char*             message;
    ipv6_diag_event_t       event;
    uint32_t                calls;
} diag_test_capture_t;


// Representation of comparison test data
typedef struct {
    const char*             left;
    const char*             right;
    uint32_t                ignore_flags;
    ipv6_compare_result_t   expected;
} compare_test_data_t;


// Comparison that converts inputs to strings for textual output
#define COMPARE(a, b) compare(#a, a, #b, b)

#define LENGTHOF(x) ((uint32_t)(sizeof(x)/sizeof(x[0])))

#define TEST_FAILED(...) \
    printf("  FAILED %s:%d", (const char *)__FILE__, (int32_t)__LINE__); \
    printf(__VA_ARGS__); \
    failed = true; \
    status->failed_count++; \
    status->total_tests++; \
    assert(false);

#define TEST_PASSED(...) \
    status->total_tests++;

static bool compare(const char* aname, const ipv6_address_full_t* a, const char* bname, const ipv6_address_full_t* b) {
    for (int i = 0; i < IPV6_NUM_COMPONENTS; ++i) {
        if (a->address.components[i] != b->address.components[i]) {
            printf("  address element %s [%d]: %04x != %s[%d]: %04x\n",
                aname, i, a->address.components[i],
                bname, i, b->address.components[i]);
            return false;
        }
        if (a->port != b->port) {
            printf("  port doesn't match. %s: %d != %s: %d\n",
                aname, a->port, bname, b->port);
            return false;
        }
        if (a->mask != b->mask) {
            printf("  mask doesn't match. %s: %d != %s: %d\n",
                aname, a->mask, bname, b->mask);
            return false;
        }
    }
    return true;
}

static bool wrapped_to_str(
    const ipv6_address_full_t* in,
    char *output,
    size_t output_bytes)
{
    size_t used_output_bytes = ipv6_to_str(in, output, output_bytes);
    if (used_output_bytes >= output_bytes) {
        printf("  used output bytes exceeded available!\n");
        return false;
    }
    if (output_bytes == 0) {
        printf("  string conversion truncated!\n");
        return false;
    }
    if (output[used_output_bytes] != '\0') {
        printf("  string conversion not correctly terminated!\n");
        return false;
    }

    return true;
}

static void copy_test_data(ipv6_address_full_t* dst, const test_data_t* src) {
    memset(dst, 0, sizeof(ipv6_address_full_t));
    memcpy(&(dst->address.components[0]), &src->components[0], sizeof(uint16_t) * IPV6_NUM_COMPONENTS);
    dst->port = src->port;
    dst->mask = src->mask;
}


// Function that is called by the address parser to report diagnostics
static void test_parsing_diag_fn (
        ipv6_diag_event_t event,
        const ipv6_diag_info_t* info,
        void* user_data)
{
    diag_test_capture_t* capture = (diag_test_capture_t*)user_data;

    capture->event = event;
    capture->message = info->message;
    capture->calls++;
}

static const char *diag_event_to_str(ipv6_diag_event_t ev) {
    switch (ev) {
        case IPV6_DIAG_STRING_SIZE_EXCEEDED     : return "IPV6_DIAG_STRING_SIZE_EXCEEDED";
        case IPV6_DIAG_INVALID_INPUT            : return "IPV6_DIAG_INVALID_INPUT";
        case IPV6_DIAG_INVALID_INPUT_CHAR       : return "IPV6_DIAG_INVALID_INPUT_CHAR";
        case IPV6_DIAG_TRAILING_ZEROES          : return "IPV6_DIAG_TRAILING_ZEROES";
        case IPV6_DIAG_V6_BAD_COMPONENT_COUNT   : return "IPV6_DIAG_V6_BAD_COMPONENT_COUNT";
        case IPV6_DIAG_V4_BAD_COMPONENT_COUNT   : return "IPV6_DIAG_V4_BAD_COMPONENT_COUNT";
        case IPV6_DIAG_V6_COMPONENT_OUT_OF_RANGE: return "IPV6_DIAG_V6_COMPONENT_OUT_OF_RANGE";
        case IPV6_DIAG_V4_COMPONENT_OUT_OF_RANGE: return "IPV6_DIAG_V4_COMPONENT_OUT_OF_RANGE";
        case IPV6_DIAG_INVALID_PORT             : return "IPV6_DIAG_INVALID_PORT";
        case IPV6_DIAG_INVALID_CIDR_MASK        : return "IPV6_DIAG_INVALID_CIDR_MASK";
        case IPV6_DIAG_IPV4_REQUIRED_BITS       : return "IPV6_DIAG_IPV4_REQUIRED_BITS";
        case IPV6_DIAG_IPV4_INCORRECT_POSITION  : return "IPV6_DIAG_IPV4_INCORRECT_POSITION";
        case IPV6_DIAG_INVALID_BRACKETS         : return "IPV6_DIAG_INVALID_BRACKETS";
        case IPV6_DIAG_INVALID_ABBREV           : return "IPV6_DIAG_INVALID_ABBREV";
        case IPV6_DIAG_INVALID_DECIMAL_TOKEN    : return "IPV6_DIAG_INVALID_DECIMAL_TOKEN";
        case IPV6_DIAG_INVALID_HEX_TOKEN        : return "IPV6_DIAG_INVALID_HEX_TOKEN";
        default: return "UNKNOWN";
    }
}

static void test_output_diag_fn (
        ipv6_diag_event_t event,
        const ipv6_diag_info_t* info,
        void* user_data)
{
    printf("    DIAG: [%u] %s: %s from: '%s' pos %u\n",
           event, diag_event_to_str(event), info->message, info->input, info->position);
}

//
// CIDR positive tests:
//
// 2001:0DB8:0000:CD30:0000:0000:0000:0000/60
// 2001:0DB8::CD30:0:0:0:0/60
// 2001:0DB8:0:CD30::/60
//
//
// When writing both a node address and a prefix of that node address
//      (e.g., the node's subnet prefix), the two can be combined as follows:
//   the node address      2001:0DB8:0:CD30:123:4567:89AB:CDEF
//   and its subnet number 2001:0DB8:0:CD30::/60
//   can be abbreviated as 2001:0DB8:0:CD30:123:4567:89AB:CDEF/60
//
static void test_parsing (test_status_t* status) {
    // input, alternate, components, mask, port
    test_data_t tests[] = {
        { "::1:2:3:4:5", { 0, 0, 0, 1, 2, 3, 4, 5 }, 0, 0, 0 },
        { "0:0:0:1:2:3:4:5", { 0, 0, 0, 1, 2, 3, 4, 5 }, 0, 0, 0 },
        { "1:2::3:4:5", { 1, 2, 0, 0, 0, 3, 4, 5 }, 0, 0, 0 },
        { "1:2:0:0:0:3:4:5", { 1, 2, 0, 0, 0, 3, 4, 5 }, 0, 0, 0 },
        { "1:2:3:4:5::", { 1, 2, 3, 4, 5, 0, 0, 0 }, 0, 0, 0 },
        { "1:2:3:4:5:0:0:0", { 1, 2, 3, 4, 5, 0, 0, 0 }, 0, 0, 0 },
        { "0:0:0:0:0:ffff:102:405", { 0, 0, 0, 0, 0, 0xffff, 0x102, 0x405 }, 0, 0, 0 },
        { "::", { 0, 0, 0, 0, 0, 0, 0, 0 }, 0, 0, 0 },
        { "::0", { 0, 0, 0, 0, 0, 0, 0, 0 }, 0, 0, 0 },
        { "::1", { 0, 0, 0, 0, 0, 0, 0, 1 }, 0, 0, 0 },
        { "0:0:0::1", { 0, 0, 0, 0, 0, 0 , 0, 1 }, 0, 0, 0 },
        { "ffff::1", { 0xffff, 0, 0, 0, 0, 0, 0, 1 }, 0, 0, 0 },
        { "ffff:0:0:0:0:0:0:1", { 0xffff, 0, 0, 0, 0, 0, 0, 1 }, 0, 0, 0 },
        { "2001:0db8:0a0b:12f0:0:0:0:1", { 0x2001, 0x0db8, 0x0a0b, 0x12f0, 0, 0, 0, 1 }, 0, 0, 0 },
        { "2001:db8:a0b:12f0::1", { 0x2001, 0xdb8, 0xa0b, 0x12f0, 0, 0, 0, 1 }, 0, 0, 0 },
        { "::ffff:1.2.3.4", { 0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304 }, 0, 0, IPV6_FLAG_IPV4_EMBED },
        { "::ffff:1.2.3.4/32", { 0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304 }, 0, 32, IPV6_FLAG_IPV4_EMBED|IPV6_FLAG_HAS_MASK },
        { "[::ffff:1.2.3.4/32]:5678", { 0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304 }, 5678, 32, IPV6_FLAG_IPV4_EMBED|IPV6_FLAG_HAS_MASK|IPV6_FLAG_HAS_PORT },
        { "1:2:3:4:5:0:0:0/128", { 1, 2, 3, 4, 5, 0, 0, 0 }, 0, 128, IPV6_FLAG_HAS_MASK },
        { "[1:2:3:4:5:0:0:0/128]:5678", { 1, 2, 3, 4, 5, 0, 0, 0 }, 5678, 128, IPV6_FLAG_HAS_MASK|IPV6_FLAG_HAS_PORT },
        { "[1:2:3:4:5::]:5678", { 1, 2, 3, 4, 5, 0, 0, 0 }, 5678, 0, IPV6_FLAG_HAS_PORT },
        { "[::1]:5678", { 0, 0, 0, 0, 0, 0, 0, 1 }, 5678, 0, IPV6_FLAG_HAS_PORT },
        { "1.2.3.4", { 0x102, 0x304, 0, 0, 0, 0, 0, 0 }, 0, 0, IPV6_FLAG_IPV4_COMPAT },
        { "1.2.3.4:5678", { 0x102, 0x304, 0, 0, 0, 0, 0, 0 }, 5678,0,  IPV6_FLAG_IPV4_COMPAT|IPV6_FLAG_HAS_PORT },
        { "1", { 0x0000, 0x0001, 0, 0, 0, 0, 0, 0 }, 0, 0, IPV6_FLAG_IPV4_COMPAT },
        { "1:5678", { 0x0000, 0x0001, 0, 0, 0, 0, 0, 0 }, 5678, 0, IPV6_FLAG_IPV4_COMPAT|IPV6_FLAG_HAS_PORT },
        { "1.2", { 0x0100, 0x0002, 0, 0, 0, 0, 0, 0 }, 0, 0, IPV6_FLAG_IPV4_COMPAT },
        { "1.2:5678", { 0x0100, 0x0002, 0, 0, 0, 0, 0, 0 }, 5678, 0, IPV6_FLAG_IPV4_COMPAT|IPV6_FLAG_HAS_PORT },
        { "1.2.3", { 0x0102, 0x0003, 0, 0, 0, 0, 0, 0 }, 0, 0, IPV6_FLAG_IPV4_COMPAT },
        { "1.2.3:5678", { 0x0102, 0x0003, 0, 0, 0, 0, 0, 0 }, 5678, 0, IPV6_FLAG_IPV4_COMPAT|IPV6_FLAG_HAS_PORT },
        { "127.0.0.1", { 0x7f00, 0x0001, 0, 0, 0, 0, 0, 0 }, 0, 0, IPV6_FLAG_IPV4_COMPAT },
        { "255.255.255.255", { 0xffff, 0xffff, 0, 0, 0, 0, 0, 0 }, 0, 0, IPV6_FLAG_IPV4_COMPAT },
        { "255.255.255.255:65123", { 0xffff, 0xffff, 0, 0, 0, 0, 0, 0 }, 65123, 0, IPV6_FLAG_IPV4_COMPAT|IPV6_FLAG_HAS_PORT },
    };

    char* tostr = (char*)alloca(IPV6_STRING_SIZE);

    for (uint32_t i = 0; i < LENGTHOF(tests); ++i) {
        ipv6_address_full_t test;
        ipv6_address_full_t parsed;
        bool failed = false;

        memset(&test, 0, sizeof(test));
        memset(&parsed, 0, sizeof(parsed));

        //
        // Test the string conversion into the 'parsed' structure
        //
        printf("ipv6_from_str index: %u \"%s\"\n",
            i,
            tests[i].input);

        if (!tests[i].port != !(tests[i].flags & IPV6_FLAG_HAS_PORT)) {
            TEST_FAILED("  Test is poorly defined, port doesn't match the flag.");
        }
        if (!tests[i].mask != !(tests[i].flags & IPV6_FLAG_HAS_MASK)) {
            TEST_FAILED("  Test is poorly defined, mask doesn't match the flag.");
        }

        if (!ipv6_from_str_diag(
                tests[i].input,
                strlen(tests[i].input),
                &parsed,
                test_output_diag_fn,
                NULL)) {
            TEST_FAILED("  ipv6_from_str failed\n");
        }
        else {
            TEST_PASSED();
        }

        copy_test_data(&test, &tests[i]);
        if (!COMPARE(&test, &parsed)) {
            TEST_FAILED("  compare failed\n");
        }
        else {
            TEST_PASSED();
        }

        // Test to_str and back with comparion
        if (!wrapped_to_str(&parsed, tostr, IPV6_STRING_SIZE)) {
            TEST_FAILED("  ipv6_to_str failed\n");
        }
        else {
            TEST_PASSED();
        }

        // printf("  ipv6_to_str -> %s\n", tostr);
        if (!ipv6_from_str(tostr, strlen(tostr), &parsed)) {
            TEST_FAILED("  ipv6 string round-trip failed\n");
        }
        else {
            TEST_PASSED();
        }

        if (!COMPARE(&parsed, &test)) {
            TEST_FAILED("  compare failed\n");
        }
        else {
            TEST_PASSED();
        }
    }
}

// CIDR negative tests:
//
// The following are NOT legal representations of the above prefix:
//
// 2001:0DB8:0:CD3/60   may drop leading zeros, but not trailing
//     zeros, within any 16-bit chunk of the address
//
// 2001:0DB8::CD30/60   address to left of "/" expands to
//     2001:0DB8:0000:0000:0000:0000:0000:CD30
//
// 2001:0DB8::CD3/60    address to left of "/" expands to
//     2001:0DB8:0000:0000:0000:0000:0000:0CD3
//
static void test_parsing_diag (test_status_t* status) {
    diag_test_data_t tests[] = {
        { "", IPV6_DIAG_INVALID_INPUT },      // invalid input
        { "-f::", IPV6_DIAG_INVALID_INPUT_CHAR }, // invalid character
        { "%f::", IPV6_DIAG_INVALID_INPUT }, // valid character wrong position
        { "0:0:0", IPV6_DIAG_V6_BAD_COMPONENT_COUNT }, // too few components
        { "0:0:0:0:0:0:0:0:0", IPV6_DIAG_V6_BAD_COMPONENT_COUNT }, // too many components
        { "0:::", IPV6_DIAG_INVALID_ABBREV }, // invalid abbreviation
        { "1ffff::", IPV6_DIAG_V6_COMPONENT_OUT_OF_RANGE }, // out of bounds separator
        { "f", IPV6_DIAG_INVALID_INPUT },
        { "f:f", IPV6_DIAG_INVALID_INPUT },
        { "1:f", IPV6_DIAG_INVALID_INPUT },
        { "f:1", IPV6_DIAG_INVALID_INPUT },
        { "ffff::/129", IPV6_DIAG_INVALID_CIDR_MASK }, // out of bounds CIDR mask
        { "[[f::]", IPV6_DIAG_INVALID_BRACKETS }, // invalid brackets
        { "[f::[", IPV6_DIAG_INVALID_BRACKETS }, // invalid brackets
        { "]f::]", IPV6_DIAG_INVALID_INPUT }, // invalid brackets
        { "[f::]::", IPV6_DIAG_INVALID_INPUT }, // invalid port spec
        { "[f::]:70000", IPV6_DIAG_INVALID_PORT }, // invalid port spec
        { "ffff::1.2.3.4:bbbb", IPV6_DIAG_IPV4_INCORRECT_POSITION }, // ipv6 separator after embedding
        { "1.2.3.4:bbbb::", IPV6_DIAG_INVALID_INPUT }, // invalid port string
        { "ffff::1.2.3.4.5", IPV6_DIAG_V4_BAD_COMPONENT_COUNT }, // invalid octet count
        { "111.222.333.444", IPV6_DIAG_V4_COMPONENT_OUT_OF_RANGE }, // component is too large for IPv4
        { "111.222.255.255:70000", IPV6_DIAG_INVALID_PORT }, // port is too large
    };

    for (uint32_t i = 0; i < LENGTHOF(tests); ++i) {
        ipv6_address_full_t addr;
        diag_test_capture_t capture;
        bool failed = false;

        memset(&addr, 0, sizeof(addr));
        memset(&capture, 0, sizeof(capture));

        printf("ipv6_from_str_diag index: %u \"%s\"\n",
            i,
            tests[i].input);

        if (ipv6_from_str_diag(
                tests[i].input,
                strlen(tests[i].input),
                &addr,
                test_parsing_diag_fn,
                &capture))
        {
            TEST_FAILED("    ipv6_from_str_diag was expected to fail with diagnostic\n");
        }
        else {
            if (capture.calls != 1) {
                TEST_FAILED("    ipv6_from_str_diag failed, wrong # diag calls: %u\n",
                    capture.calls);
            }
            else {
                TEST_PASSED();
            }

            if (capture.message == NULL) {
                TEST_FAILED("    ipv6_from_str_diag failed, message was NULL\n");
            } 
            else {
                TEST_PASSED();
            }

            if (capture.event != tests[i].expected_event) {
                TEST_FAILED("    ipv6_from_str_diag failed, event %u != %u (expected), message: %s\n",
                    capture.event,
                    tests[i].expected_event,
                    capture.message);
            }
            else {
                TEST_PASSED();
            }
        }
    }
}

// CIDR negative tests:
//
// The following are NOT legal representations of the above prefix:
//
// 2001:0DB8:0:CD3/60   may drop leading zeros, but not trailing
//     zeros, within any 16-bit chunk of the address
//
// 2001:0DB8::CD30/60   address to left of "/" expands to
//     2001:0DB8:0000:0000:0000:0000:0000:CD30
//
// 2001:0DB8::CD3/60    address to left of "/" expands to
//     2001:0DB8:0000:0000:0000:0000:0000:0CD3
//
static void test_comparisons(test_status_t* status) {
    compare_test_data_t tests[] = {
        // Negative tests (addresses)
        { "::1",                "127.0.0.1",                0, IPV6_COMPARE_FORMAT_MISMATCH },
        { "::",                 "0.0.0.0",                  0, IPV6_COMPARE_FORMAT_MISMATCH },

        // Negative tests (ports)
        { "[::1]:1",            "[::1]:0",                  0, IPV6_COMPARE_PORT_MISMATCH },
        { "[::1]:0",            "[::1]:1",                  0, IPV6_COMPARE_PORT_MISMATCH },
        { "192.168.2.3:50000", "192.168.2.3:50001",         0, IPV6_COMPARE_PORT_MISMATCH },
        { "192.168.2.3:50001", "192.168.2.3:50000",         0, IPV6_COMPARE_PORT_MISMATCH },

        // Ignore port
        { "1.2.3.4:12344",      "[::1.2.3.4]:12345",        IPV6_FLAG_HAS_PORT|IPV6_FLAG_IPV4_EMBED, IPV6_COMPARE_OK },  // ignore port
        { "1.2.3.4:12345",      "[::1.2.3.4]:12344",        IPV6_FLAG_HAS_PORT|IPV6_FLAG_IPV4_EMBED, IPV6_COMPARE_OK },  // ignore port
        { "[::1]:12345",        "[::1]:12344",              IPV6_FLAG_HAS_PORT, IPV6_COMPARE_OK },  // ignore port
        { "[::1]:12344",        "[::1]:12345",              IPV6_FLAG_HAS_PORT, IPV6_COMPARE_OK },  // ignore port

        // Negative tests (masks)
        { "[::1/60]:1", "[::1/59]:1",                       0, IPV6_COMPARE_MASK_MISMATCH },
        { "[::1/59]:1", "[::1/60]:1",                       0, IPV6_COMPARE_MASK_MISMATCH },
        //{ "1.2.3.4:12345/15", "1.2.3.4:12345/16",           0, IPV6_COMPARE_MASK_MISMATCH },

        // Ignore mask
        { "[::1/60]:1", "[::1/59]:1",                       IPV6_FLAG_HAS_MASK, IPV6_COMPARE_OK },
        { "[::1/59]:1", "[::1/60]:1",                       IPV6_FLAG_HAS_MASK, IPV6_COMPARE_OK },
        //{ "1.2.3.4:12345/15", "1.2.3.4:12345/16",           IPV6_FLAG_HAS_MASK, IPV6_COMPARE_OK },

        // IPv4 compatibility tests
        { "::0.0.0.0",          "0.0.0.0",                  IPV6_FLAG_IPV4_EMBED, IPV6_COMPARE_OK },
        { "::11.22.33.44",      "11.22.33.44",              IPV6_FLAG_IPV4_EMBED, IPV6_COMPARE_OK },
        { "::11.22.33.44",      "::b16:212c",               IPV6_FLAG_IPV4_EMBED, IPV6_COMPARE_OK },
        { "::11.22.33.44",       "0:0:0:0:0:0:b16:212c",    IPV6_FLAG_IPV4_EMBED, IPV6_COMPARE_OK },

        // IPv4 explicit compatibility check tests
        { "::0.0.0.0",          "0.0.0.0",                  0, IPV6_COMPARE_FORMAT_MISMATCH },
        { "::11.22.33.44",      "11.22.33.44",              0, IPV6_COMPARE_FORMAT_MISMATCH },
        { "::11.22.33.44",      "::b16:212c",               0, IPV6_COMPARE_FORMAT_MISMATCH },
        { "::11.22.33.44",       "0:0:0:0:0:0:b16:212c",    0, IPV6_COMPARE_FORMAT_MISMATCH },

        // Expansions
        { "1:0:0:0:0:0:0:0",    "1::",                      0, IPV6_COMPARE_OK },

        // Ports
        { "1.2.3.4:12345",      "[::1.2.3.4]:12345",        IPV6_FLAG_IPV4_EMBED, IPV6_COMPARE_OK },


        // Masks
        { "[::1/32]:10", "[::1/32]:10",                     0, IPV6_COMPARE_OK },
        //{ "1.2.3.4:12345/16", "1.2.3.4:12345/16",           0, IPV6_COMPARE_OK },
    };

    for (uint32_t i = 0; i < LENGTHOF(tests); ++i) {
        ipv6_address_full_t left, right;
        diag_test_capture_t capture;
        bool failed = false;

        memset(&left, 0, sizeof(left));
        memset(&right, 0, sizeof(right));
        memset(&capture, 0, sizeof(capture));

        printf("ipv6_from_str_diag index: %u \"%s\" == \"%s\", %d\n",
            i,
            tests[i].left,
            tests[i].right,
            tests[i].expected);

        if (!ipv6_from_str_diag(
            tests[i].left,
            strlen(tests[i].left),
            &left,
            test_parsing_diag_fn,
            &capture))
        {
            TEST_FAILED("    ipv6_from_str_diag failed - left (%s)\n", tests[i].left);
        }
        else {
            TEST_PASSED();
        }

        if (!ipv6_from_str_diag(
            tests[i].right,
            strlen(tests[i].right),
            &right,
            test_parsing_diag_fn,
            &capture))
        {
            TEST_FAILED("    ipv6_from_str_diag failed - right (%s)\n", tests[i].right);
        }
        else {
            TEST_PASSED();
        }

        ipv6_compare_result_t compare_result = ipv6_compare(&left, &right, tests[i].ignore_flags);
        if (compare_result != tests[i].expected) {
            TEST_FAILED("    ipv6_compare failed (%s == %s [%08x]), compare result: %u, expected: %u\n",
                tests[i].left, tests[i].right, tests[i].ignore_flags, compare_result, tests[i].expected);
        }
        else {
            TEST_PASSED();
        }
    }
}

static void test_api_use_loopback_const (test_status_t* status) {
    // Just treat all of the checks in this function as a single test
    bool failed = false;
    status->total_tests = 1;

    // test using the host order network constant directly in an ipv6_address_full_t
    static const uint32_t TESTADDR = 0x7f6f0201;
    static const char TESTADDR_STR[] = "127.111.2.1";

    uint16_t components[IPV6_NUM_COMPONENTS];
    memset(components, 0, sizeof(components));
    components[0] = TESTADDR >> 16;
    components[1] = TESTADDR & 0xffff;

    struct in_addr in_addr;
#if WIN32
    inet_pton(AF_INET, TESTADDR_STR, &in_addr);
#else
    inet_aton(TESTADDR_STR, &in_addr);
#endif
    if (TESTADDR != ntohl(in_addr.s_addr)) {
        TEST_FAILED("    ntohl(inet_aton(LOOPBACK_STR)) does not match host constant\n");
    }

    // Make the raw address from the in-memory version
    ipv6_address_full_t addr;
    memset(&addr, 0, sizeof(addr));
    memcpy(&addr.address.components[0], &components[0], sizeof(components));
    addr.flags |= IPV6_FLAG_IPV4_COMPAT;

    ipv6_address_full_t parsed;
    if (!ipv6_from_str(TESTADDR_STR, sizeof(TESTADDR_STR) -1, &parsed)) {
        TEST_FAILED("    ipv6_from_str failed on LOOPBACK_STR\n");
    }
    else {
        TEST_PASSED();
    }

    if (!COMPARE(&parsed, &addr)) {
        TEST_FAILED("    ipv4 compat loopback comparison failed\n");
    }
    else {
        TEST_PASSED();
    }

    char buffer[64];
    if (!wrapped_to_str(&addr, buffer, sizeof(buffer))) {
        TEST_FAILED("    ipv6_to_str failed for raw address\n");
    }
    else {
        TEST_PASSED();
    }

    ipv6_address_full_t roundtrip;
    if (!ipv6_from_str(buffer, strlen(buffer), &roundtrip)) {
        TEST_FAILED("    ipv6_from_str failed for roundtrip string: %s\n", buffer);
    }
    else {
        TEST_PASSED();
    }

    if (!COMPARE(&roundtrip, &addr)) {
        TEST_FAILED("    compare failed for roundtrip\n");
    }
    else {
        TEST_PASSED();
    }
}

static void test_invalid_to_str(test_status_t* status) {
    ipv6_address_full_t address;
    const char* test_str = "::1:2:3:4:5";
    bool failed;

    if (!ipv6_from_str_diag(test_str, strlen(test_str), &address, test_output_diag_fn, NULL)) {
        TEST_FAILED("    ipv6_from_str failed for %s\n", test_str);
    }
    else {
        TEST_PASSED();
    }

    // invalid pointer
    if (ipv6_to_str(&address, NULL, 100)) {
        TEST_FAILED("    ipv6_to_str should not accept nullptr");
    }
    else {
        TEST_PASSED();
    }

    // too short
    char buffer[7];
    if (ipv6_to_str(&address, buffer, sizeof(buffer)) || buffer[0] != '\0') {
        TEST_FAILED("    ipv6_to_str should not silently truncate");
    }
    else {
        TEST_PASSED();
    }    
}

int main (void) {
    test_group_t test_groups[] = {
        { "test_parsing", test_parsing },
        { "test_parsing_diag", test_parsing_diag },
        { "test_comparisons", test_comparisons },
        { "test_api_use_loopback_const", test_api_use_loopback_const },
        { "test_invalid_to_str", test_invalid_to_str }
    };

    uint32_t total_failures = 0;
    uint32_t total_tests = 0;

    for (uint32_t i = 0; i < LENGTHOF(test_groups); ++i) {
        test_status_t status = { 0, };
        printf("%s\n===\n", test_groups[i].name);
        test_groups[i].func(&status);

        printf("\n%u/%u passed (%u failures).\n\n",
            (uint32_t)(status.total_tests - status.failed_count),
            status.total_tests,
            status.failed_count);

        total_tests += status.total_tests;
        total_failures += status.failed_count;
    }

    printf("======\n  total: %u/%u passed (%u failures).\n\n",
        (uint32_t)(total_tests - total_failures),
        total_tests,
        total_failures);

    return 0;
}

