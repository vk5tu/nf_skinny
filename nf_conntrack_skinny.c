/* nf_conntrack_skinny -- Connection tracking for Skinny.
 *
 * $Id$
 *
 *
 * PRINCIPLES OF OPERATION
 *
 * Skinny is a TCP connection from a Call Manager to each IP Phone. Messages
 * across Skinny alter the display, ring the bell, and so on. Some messages
 * request the establishment of a RTP connection, these messages are the ones
 * which concern us for connection tracking.
 *
 * The TCP connection transfers Skinny protocol data units. These have
 * a header followed by a few commands in a type-length-value format.
 *
 * Some commands contain IP addresses and RTP/UDP port numbers, these are:
 *  - RegisterMessage (phone IP address)
 *  - IpPortMessage (phone UDP port)
 *  - StartMediaTransmission (remote IP address, remote UDP port,
 *    IP precedence)
 *  - OpenReceiveChannelAck (IP address, port number)
 *
 * There are also matching commands which can mark an end to tracking some
 * connections:
 *  - CloseReceiveChannel (paired with OpenRecieveChannelAck)
 *  - StopMediaTransmission (paired with StartMediaTransmission)
 * these do not contain IP addresses but Conference IDs.
 *
 * KeepAlive messages are tracked so that running but idle connections
 * do not time out.
 *
 * Cisco Systems' document "SCCP Messaging Guide for Cisco Unified
 * Communications Manager 5.0(1)" suggests that these commands also
 * establish RTP/UDP sessions, but I have no packet capture of these:
 *  - StationSubscribeDtmfPayloadReqMessage
 *  - StationUnSubscribeDtmfPayloadReqMessage
 * If DTMF does not work via this module these messages are the likely
 * cause and a packet capture in PCAP (tcpdump or wireshark) format
 * would be appreciated by the maintainer.
 *
 *
 * COPYRIGHT AND OTHER HASSLES
 *
 * Copyright © Glen David Turner of Semaphore, South Australia, 2008.
 *
 * This file is part of nf_skinny.
 *
 * nf_skinny is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 2 of the License,
 * or (at your option) any later version.
 *
 * nf_skinny is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with nf_skinny.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <linux/init.h> /* For module_init/fini */
#include <linux/module.h>
#include <linux/stat.h> /* for S_* */
#include <linux/kernel.h> /* for printk() */
#include <asm/byteorder.h>
#include <linux/ctype.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <linux/netfilter.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include "nf_conntrack_skinny.h"


#include <linux/moduleparam.h>

#define PFX "nf_conntrack_skinny: "

static unsigned int __read_mostly skinny_port = SKINNY_CONTROL_TCP_PORT;
module_param(skinny_port, uint, S_IRUGO);
MODULE_PARM_DESC(skinny_port,
                 "Well-known TCP port for Skinny control connection, "
                 "default " __MODULE_STRING(SKINNY_CONTROL_TCP_PORT));

static unsigned int __read_mostly skinny_timeout = SKINNY_TIMEOUT;
module_param(skinny_timeout, uint, S_IRUGO);
MODULE_PARM_DESC(skinny_timeout,
                 "Timeout for Skinny connection tracking, in seconds, "
                 "default "__MODULE_STRING(SKINNY_TIMEOUT));

static unsigned int __read_mostly skinny_max_expected = SKINNY_MAX_EXPECTED;
module_param(skinny_max_expected, uint, S_IRUGO);
MODULE_PARM_DESC(skinny_max_expected,
                 "Maximum Skinny control connections, one used per IP phone, "
                 "default " __MODULE_STRING(SKINNY_MAX_EXPECTED));

/* Access to this symbol is locked using RCU. */
unsigned int
(*nf_nat_skinny_hook)(struct sk_buff**pskb,
                      enum ip_conntrack_info ctinfo,
                      struct nf_conntrack_expect exp,
                      const char *dptr) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_skinny_hook);

char *skinny_buffer = NULL;
static DEFINE_SPINLOCK(skinny_buffer_lock);


/* This error message is a hack. We don't want to blow lots of memory
 * for strings literals that are 90% this same for this bizaare error
 * so the string literals are made to be identical at compile time.
 *
 * Usage:
 *   printk_no_skb_header_pointer(__func__);
 */
static void
printk_no_skb_header_pointer(const char *func)
{
    if (likely(net_ratelimit())) {
        printk(KERN_ERR PFX
               "%s(): Packet contents missing.\n",
               func);
    }
}


/* Take string "str" of allocated size "length", possibly not
 * 0-terminated, possibly filled to the right with trailing
 * spaces. Turn this into a printable 0-terminated string with no
 * trailing spaces. This may truncate the last character, regardless
 * if it is a space or not.
 */
static void 
str_tidy(char *str, size_t length)
{
    char *p;

    /* Ensure 0-termination. */
    str[length] = '\0';
    /* Zap non-printable characters */
    for (p = str; *p != '\0'; p++) {
        if (!isprint(*p)) {
            *p = ' ';
        }
    }
    /* Remove trailing spaces. */
    while (p != str) {
        if (isspace(*p)) {
            *p = '\0';
        } else {
            break;
        }
        p--;
    }
}

/* Parse a Station Register message.
 *
 * Returns: !0: do not parse further PDUs in this packet.
 */
static int
parse_station_register(struct sk_buff *matching_skb,
                       unsigned int offset,
                       unsigned int end_offset,
                       struct nf_conn *ct,
                       enum ip_conntrack_info ct_info)
{
    struct skinny_station_register *station_register;
    struct skinny_station_register station_register_buffer;
    char device_name[SKINNY_STATION_REGISTER_DEVICE_NAME_LENGTH];
    u_int32_t station_user_id;
    u_int32_t station_instance;
    u_int32_t ip_address;
    u_int32_t device_type;
    u_int32_t max_streams;
    
    printk("parse_station_register\n");
    printk("parse_station_register() offset = %u\n", offset);
    printk("parse_station_register() end_offset = %u\n", end_offset);

    if (offset + sizeof(struct skinny_station_register) > end_offset) {
        if (net_ratelimit()) {
            printk(KERN_INFO PFX
                   "Station Register message is too short "
                   "(it is %u-%u bytes, but should be at least %u).\n",
                   end_offset,
                   offset,
                   sizeof(struct skinny_station_register));
        }
        return 0;
    }
    station_register = skb_header_pointer(matching_skb,
                                          offset,
                                          sizeof(struct skinny_station_register),
                                          &station_register_buffer);
    if (!station_register) {
        printk_no_skb_header_pointer(__func__);
        return !0;
    }

    memcpy(device_name,
           station_register->device_name,
           SKINNY_STATION_REGISTER_DEVICE_NAME_LENGTH);
    str_tidy(device_name, SKINNY_STATION_REGISTER_DEVICE_NAME_LENGTH);
    printk("station register: device name = %s\n", device_name);
    station_user_id = le32_to_cpu(station_register->station_user_id);
    printk("station register: station user id = %u\n", station_user_id);
    station_instance = le32_to_cpu(station_register->station_instance);
    printk("station register: station instance = %u\n", station_instance);
    ip_address = ntohl(station_register->ip_address);
    printk("station register: ip address = " NIPQUAD_FMT "\n",
           HIPQUAD(ip_address));
    device_type = le32_to_cpu(station_register->device_type);
    printk("station register: device type = %u\n", device_type);
    max_streams = le32_to_cpu(station_register->max_streams);
    printk("station register: max_streams = %u\n", max_streams);

    return 0;
}


/* Parse a Station IP Port message.
 *
 * This message informs the Call Manager that the IP Phone has
 * selected UDP port "udp_port" for incoming call-progress sounds.
 *
 * Might need to pass IP address to this to set up connection tracking.
 *
 * Returns: !0: do not parse further PDUs in this packet.
 */
static int
parse_station_ip_port(struct sk_buff *matching_skb,
                      unsigned int offset,
                      unsigned int end_offset,
                      struct nf_conn *ct,
                      enum ip_conntrack_info ct_info)
{
    struct skinny_station_ip_port *station_ip_port;
    struct skinny_station_ip_port station_ip_port_buffer;
    struct nf_conntrack_expect *expect;
    int problems;

    printk("parse_station_ip_port\n");
    printk("parse_station_ip_port() offset = %u\n", offset);
    printk("parse_station_ip_port() end_offset = %u\n", end_offset);

    station_ip_port = skb_header_pointer(
                           matching_skb,
                           offset,
                           sizeof(struct skinny_station_ip_port),
                           &station_ip_port_buffer);
    if (unlikely(!station_ip_port)) {
        printk_no_skb_header_pointer(__func__);
        return !0;
    }

    printk("station register: udp port = %u\n",
           ntohs(station_ip_port->udp_port));

    /* Set up conntrack */
    expect = nf_ct_expect_alloc(ct);
    if (!expect) {
        return 0;
    }
    printk("nf_ct_expect_init("
           "src ipv4:" NIPQUAD_FMT ",udp:* --> "
           "dst ipv4:" NIPQUAD_FMT ",udp:%u)\n",
           NIPQUAD(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3),
           NIPQUAD(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3),
           ntohs(station_ip_port->udp_port));
    
    nf_ct_expect_init(expect,
                      ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num,
                      &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3,
                      &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3,
                      IPPROTO_UDP,
                      NULL,  /* Any UDP source port. */
                      &station_ip_port->udp_port);
    expect->dir = IP_CT_DIR_REPLY;
    problems = nf_ct_expect_related(expect);
    if (problems) {
        printk(KERN_INFO PFX
               "Request for connection tracking failed with error code %d for "
               "ipv4:" NIPQUAD_FMT ",udp:* -> ipv4:" NIPQUAD_FMT ",udp:%u.\n",
               problems,
               NIPQUAD(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3),
               NIPQUAD(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3),
               ntohs(station_ip_port->udp_port));
        return 0;
    }

    return 0;
}


/* Parse a Open Recieve Channel Acknowledge message.
 *
 * Returns: !0: do not parse further PDUs in this packet.
 */
static int
parse_open_receive_channel_ack(struct sk_buff *matching_skb,
                               unsigned int offset,
                               unsigned int length,
                               struct nf_conn *ct,
                               enum ip_conntrack_info ct_info)
{
    struct skinny_open_receive_channel_ack *open_receive_channel_ack;
    struct skinny_open_receive_channel_ack open_receive_channel_ack_buffer;

    open_receive_channel_ack = skb_header_pointer(
                           matching_skb,
                           offset,
                           sizeof(struct skinny_open_receive_channel_ack),
                           &open_receive_channel_ack_buffer);
    if (!open_receive_channel_ack) {
        printk_no_skb_header_pointer(__func__);
        return !0;
    }

    printk(KERN_INFO PFX
           "open_receive_channel_ack\n");
    /* Extract Port */
    /* Set up conntrack */

    return 0;
}


/* Parse a Start Media Transmission message.
 *
 * Returns: !0: do not parse further PDUs in this packet.
 */
static int
parse_start_media_transmission(struct sk_buff *matching_skb,
                               unsigned int offset,
                               unsigned int length,
                               struct nf_conn *ct,
                               enum ip_conntrack_info ct_info)
{
    struct skinny_start_media_transmission *start_media_transmission;
    struct skinny_start_media_transmission start_media_transmission_buffer;

    printk(KERN_INFO "start_media_transmission\n");

    start_media_transmission = skb_header_pointer(
                                   matching_skb,
                                   offset,
                                   sizeof(struct skinny_start_media_transmission),
                                   &start_media_transmission_buffer);
    if (!start_media_transmission) {
        printk_no_skb_header_pointer(__func__);
        return !0;
    }

    printk(KERN_INFO PFX
           "start_media_transmission\n");
    /* Extract Port */
    /* Set up conntrack */

    return 0;
}


/* Parse a Skinny protocol data unit.
 * Input:
 *   matching_skb
 *   skinny_offset
 *   skinny_length
 *   direction
 * Output:
 *   updated skinny_offset
 * Returns: !0: do not parse further PDUs in this packet.
 */
static int
parse_skinny_pdu(struct sk_buff *matching_skb,
                 unsigned int *skinny_offset,
                 unsigned int skinny_length,
                 struct nf_conn *ct,
                 enum ip_conntrack_info ct_info)
{
    struct skinny_tcp_msg_header *tcp_msg_header;
    struct skinny_tcp_msg_header tcp_msg_header_buffer;
    struct skinny_msg_id *msg_id_header;
    struct skinny_msg_id msg_id_buffer;
    unsigned int offset;
    unsigned int end_offset;
    unsigned int msg_len;
    unsigned int msg_id;
    int problems = 0;

    offset = *skinny_offset;
    end_offset = skinny_length;

    /* Each Skinny PDU begins with a header named TcpMsgHeader. It
     * contains a MsgLen (the number of bytes following this header)
     * and a LinkMsgType (indicating compression, encryption and so
     * on).
     *
     * Since this is reverse-engineered, we don't know if MsgLen can
     * be validly 0 (from a conceptual point of view a zero-length
     * Skinny PDU could be useful for keep alives). So we had better
     * allow for that.
     *
     * LinkMsgType has only been reported with value 0. We punt on
     * other values as trying to parse a compressed or encrypted
     * packet isn't going to work.
     */
    if (offset + sizeof(struct skinny_tcp_msg_header) > end_offset) {
        printk(KERN_INFO PFX
               "Too short for a Skinny packet "
               "(it is %u-%u, but should be at least %u). "
               "Perhaps not Skinny traffic?\n",
               end_offset,
               offset,
               sizeof(struct skinny_tcp_msg_header));
        return !0;
    }
    tcp_msg_header = skb_header_pointer(matching_skb,
                                        offset,
                                        sizeof(struct skinny_tcp_msg_header),
                                        &tcp_msg_header_buffer);
    if (unlikely(!tcp_msg_header)) {
        printk_no_skb_header_pointer(__func__);
        return !0;
    }
    offset += sizeof(struct skinny_tcp_msg_header);

    msg_len = le32_to_cpu(tcp_msg_header->msg_len);
    /* Validate reasonableness of msg_len. */
    if (offset + msg_len > end_offset) {
        if (likely(net_ratelimit())) {
            printk(KERN_ERR PFX
                   "Message length from Skinny header (%u bytes) is longer "
                   "than data in packet (%u-%u bytes). Perhaps not Skinny "
                   "traffic?\n",
                   msg_len,
                   end_offset,
                   offset);
        }
        /* If the message length is outrageous we don't know where
         * this message ends and thus can't parse any following
         * messages in the remainder of this packet.
         */
        return !0;
    }
    /* End of PDU is now set by msg_len rather than packet length */
    end_offset = offset + msg_len;

    if (unlikely(le32_to_cpu(tcp_msg_header->link_msg_type)) !=
                 SKINNY_LINK_MSG_TYPE_PLAINTEXT) {
        if (likely(net_ratelimit())) {
            printk(KERN_INFO PFX
                   "Cannot analyse this message. It is not plaintext but has "
                   "Link Message Type %u. Perhaps not Skinny traffic? "
                   "Perhaps Skinny is using compression or encryption?\n",
                   le32_to_cpu(tcp_msg_header->link_msg_type));
        }
        /* Try to parse the next message in the packet. Perhaps not
         * all messages are encrypted or compressed.
         */
        *skinny_offset = end_offset;
        return 0;
    }

    /* The msg_id identifies the purpose and structure of the
     * message.  We only need to parse some msg_id types to be
     * able to track a connection.
     */
    if (offset + sizeof(struct skinny_msg_id) > end_offset) {
        if (likely(net_ratelimit())) {
            printk(KERN_INFO PFX
                   "Message is too short to contain a MsgID "
                   "(it is %u-%u, but should be at least %u).\n",
                   end_offset,
                   offset,
                   sizeof(struct skinny_msg_id));
        }
        /* Try to parse the rest of the packet. The protocol design
         * seems to allow for message headers followed by no actual
         * message.
         */
        *skinny_offset = end_offset;
        return 0;
    }
    msg_id_header = skb_header_pointer(matching_skb,
                                       offset,
                                       sizeof(struct skinny_msg_id),
                                       &msg_id_buffer);
    
    if (unlikely(!msg_id_header)) {
        printk_no_skb_header_pointer(__func__);
        return !0;
    }
    msg_id = le16_to_cpu(msg_id_header->msg_id);
    offset += sizeof(struct skinny_msg_id);

    switch (msg_id) {
    case SKINNY_MSG_ID_STATION_REGISTER:
        problems = parse_station_register(matching_skb,
                                          offset,
                                          end_offset,
                                          ct,
                                          ct_info);
        break;
    case SKINNY_MSG_ID_STATION_IP_PORT:
        problems = parse_station_ip_port(matching_skb,
                                         offset,
                                         end_offset,
                                         ct,
                                         ct_info);
        break;
    case SKINNY_MSG_ID_OPEN_RECEIVE_CHANNEL_ACK:
        problems = parse_open_receive_channel_ack(matching_skb,
                                                  offset,
                                                  end_offset,
                                                  ct,
                                                  ct_info);
        break;
    case SKINNY_MSG_ID_START_MEDIA_TRANSMISSION:
        problems = parse_start_media_transmission(matching_skb,
                                                  offset,
                                                  end_offset,
                                                  ct,
                                                  ct_info);
        break;

#if 0
    case SKINNY_MSG_ID_KEEPALIVE:
        /* Keep alive packets call nf_ct_refresh() so that connections
         * don't time out. This allows the NAT timeout to be dropped
         * to ~100s from 1 hour.
         */
        break;
#endif
    }

    *skinny_offset = end_offset;
    return problems;
}


/* Parse a packet containing Skinny PDUs.
 * Input:
 *   matching_skb
 *   skinny_offset
 *   skinny_length
 *   direction
 * Returns: accept or reject packet and all its PDUs.
 */
static int
parse_skinny_packet(struct sk_buff *matching_skb,
                    unsigned int skinny_offset,
                    unsigned int skinny_length,
                    struct nf_conn *ct,
                    enum ip_conntrack_info ct_info)
{
    unsigned int pdu_offset;
    int problems = 0;

    /* The packet can contain one or more Skinny protocol data units.
     * Accept the packet unless a subordinate parser says to toss it.
     */
    pdu_offset = skinny_offset;
    while (pdu_offset < skinny_length && !problems) {
        problems = parse_skinny_pdu(matching_skb,
                                    &pdu_offset,
                                    skinny_length,
                                    ct,
                                    ct_info);
    }
    return NF_ACCEPT;
}


/* The Skinny TCP control connecction exchanges information about the
 * establishment of RTP flows. This helper module tracks the TCP
 * connection adding expected RTP flows to the connection tracking
 * system.
 */
static int
skinny_conntrack_helper(struct sk_buff *matching_skb,
                        unsigned int matching_offset,
                        struct nf_conn *ct,
                        enum ip_conntrack_info conntrack_info)
{
    struct tcphdr tcp_buffer,
                  *tcp_header;
    int ret = NF_ACCEPT;
    unsigned int skinny_offset;

    /* Don't track connections until the TCP connection is fully
     * established. TCP handshakes carry no application data.
     */
    if (unlikely(conntrack_info != IP_CT_ESTABLISHED &&
                 conntrack_info != (IP_CT_ESTABLISHED + IP_CT_IS_REPLY))) {
        return NF_ACCEPT;
    }

    /* Do we need to see if the TCP checksum is valid? If so, it goes
     * here.
     */

    /* Like most other conntrack modules we are too slack to
     * handle non-linear SKBs.
     */
    if (unlikely(skb_is_nonlinear(matching_skb))) {
        return NF_ACCEPT;
    }

    /* Replace with finer RCU lock when data structure usage fully sorted. */
    spin_lock_bh(&skinny_buffer_lock);
    tcp_header = skb_header_pointer(matching_skb,
                                    matching_offset,
                                    sizeof(tcp_buffer),
                                    &tcp_buffer);
    if (unlikely(!tcp_header)) {
        printk_no_skb_header_pointer(__func__);
        ret = NF_ACCEPT;
        goto unlock_end;
    }

    /* Skinny protocol data unit is after TCP header and its options.
     * TCP stores the length of its header in .doff in units of 4-byte
     * words.
     */
    /* Is doff in network byte order? */
    skinny_offset = matching_offset + tcp_header->doff * 4;

    /* No data to parse? */
    if (unlikely(skinny_offset == matching_skb->len)) {
        ret = NF_ACCEPT;
        goto unlock_end;
    }

    if (unlikely(skinny_offset > matching_skb->len)) {
        if (likely(net_ratelimit())) {
            printk(KERN_ERR PFX
                   "Unexpectedly short packet, perhaps not Skinny traffic? "
                   "Expected Skinny data to begin at byte %u, but packet "
                   "too short with only %u bytes.\n",
                   skinny_offset,
                   matching_skb->len);
        }
        ret = NF_ACCEPT;
        goto unlock_end;
    }

    /* Do the heavy-duty Skinny parsing, setting up connection
     * tracking if relevant protocol data units are encountered.
     */
    ret = parse_skinny_packet(matching_skb,
                              skinny_offset,
                              matching_skb->len,
                              ct,
                              conntrack_info);

 unlock_end:
    spin_unlock_bh(&skinny_buffer_lock);
    return ret;
}


static struct nf_conntrack_helper helper __read_mostly;

static int __init
nf_test_init(void)
{
    int problems;

#if 1
    /* "Hello world, this is John Laws".
     * During development it's useful to know if the module binary in
     * the kernel matches the module source in the editor. You'd be
     * surprised how many head-scratching bugs are because they don't
     * match.
     */
    printk(KERN_INFO PFX
           "Version $Id$ compiled on " __DATE__ " at " __TIME__ ".\n");
#endif

    /* Validate parameters. */
    if (skinny_max_expected < 1) {
      printk(KERN_ERR PFX
             "Module parameter skinny_max_expected must be 1 or more. "
             "Abandoning module installation.\n");
      return -EINVAL;
    }
    if (skinny_timeout < SKINNY_TIMEOUT_REASONABLE_MIN) {
      printk(KERN_INFO PFX
             "Module parameter skinny_timeout is perhaps too low at less "
             "than %d seconds. Proceeeding regardless.\n",
             SKINNY_TIMEOUT_REASONABLE_MIN);
    }

    /* Allocate resources.
     * A non-NULL value for a resource is a flag that it should be
     * freed upon module removal.
     */
    skinny_buffer = kmalloc(0x10000, GFP_KERNEL);
    if (!skinny_buffer) {
      /* If they even see this message then the author of printk() has
       * done fine work.
       */
      printk(KERN_ERR PFX
             "Insufficient kernel memory for 64KB packet parsing buffer. "
             "Abandoning module installation.\n");
      return -ENOMEM;
    }

    memset(&helper, 0, sizeof(struct nf_conntrack_helper));
    /* Information about this conntrack helper. */
    /* .name also indicates that this helper has been registered. */
    helper.name = "skinny";
    helper.me = THIS_MODULE;
    helper.help = skinny_conntrack_helper;
    helper.max_expected = skinny_max_expected;
    helper.timeout = skinny_timeout;
    /* Send all Skinny packets to this conntrack module. */
    helper.tuple.src.l3num = AF_INET;
    helper.tuple.dst.protonum = IPPROTO_TCP;
    helper.tuple.src.u.tcp.port = htons(skinny_port);

    /* Register this connection tracking helper. */
    problems = nf_conntrack_helper_register(&helper);
    if (problems) {
      printk(KERN_WARNING PFX
             "Failed to register connection tracking for TCP/IPv4 port %u. "
             "Abandoning module installation.\n",
             skinny_port);
      /* Registration of this helper failed, unset .name to indicate that */
      helper.name = NULL;
      kfree(skinny_buffer);
      skinny_buffer = NULL;
    } else {
      printk(KERN_INFO PFX
             "Module installed with parameters skinny_port %u, "
             "skinny_max_expected %u, "
             "skinny_timeout %u.\n",
             skinny_port,
             skinny_max_expected,
             skinny_timeout);
    }
    return problems;
}

static void __exit
nf_test_exit(void)
{
  /* Free resources which are in use. */
  if (helper.name) {
    nf_conntrack_helper_unregister(&helper);
    helper.name = NULL;
  }
  if (skinny_buffer) {
    kfree(skinny_buffer);
    skinny_buffer = NULL;
  }
  printk(KERN_INFO PFX "Module removed.\n");
}

module_init(nf_test_init);
module_exit(nf_test_exit);

MODULE_AUTHOR("Glen Turner <http://www.gdt.id.au/~gdt/>");
MODULE_DESCRIPTION("Cisco Skinny Station Protocol (formerly Selsius "
                   "Connection Control Protocol, SCCP) connection tracking");
MODULE_LICENSE("GPL");
