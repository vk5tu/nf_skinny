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

#define PRINTK_PREFIX "nf_conntrack_skinny: "
#define VALUE_PASTE(n) #n
#define VALUE(n) VALUE_PASTE(n)

static unsigned int __read_mostly skinny_port = SKINNY_CONTROL_TCP_PORT;
module_param(skinny_port, uint, S_IRUGO);
MODULE_PARM_DESC(skinny_port,
                 "Well-known TCP port for Skinny control connection "
                 "[" VALUE(SKINNY_CONTROL_TCP_PORT) "]");

static unsigned int __read_mostly skinny_timeout = SKINNY_TIMEOUT;
module_param(skinny_timeout, uint, S_IRUGO);
MODULE_PARM_DESC(skinny_timeout,
                 "Timeout for Skinny connection tracking, in seconds "
                 "[" VALUE(SKINNY_TIMEOUT) "]");

static unsigned int __read_mostly skinny_max_expected = SKINNY_MAX_EXPECTED;
module_param(skinny_max_expected, uint, S_IRUGO);
MODULE_PARM_DESC(skinny_max_expected,
                 "Maximum Skinny control connections, one used per IP phone "
                 "[" VALUE(SKINNY_MAX_EXPECTED) "]");

/* Access to this symbol is locked using RCU. */
unsigned int
(*nf_nat_skinny_hook)(struct sk_buff**pskb,
                      enum ip_conntrack_info ctinfo,
                      struct nf_conntrack_expect exp,
                      const char *dptr) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_skinny_hook);

char *skinny_buffer = NULL;
static DEFINE_SPINLOCK(skinny_buffer_lock);


/* Parse a Station Register message.
 *
 * Returns: !0: do not parse further PDUs in this packet.
 */
static int
parse_station_register(struct sk_buff *matching_skb,
                       unsigned int offset,
                       unsigned int length,
                       enum ip_conntrack_dir direction)
{
    struct skinny_station_register *station_register;
    struct skinny_station_register station_register_buffer;

    station_register = skb_header_pointer(
                           matching_skb,
                           offset,
                           sizeof(struct skinny_station_register),
                           &station_register_buffer);
    if (!station_register) {
        return !0;
    }
    /* Extract IP address */
    /* Set up conntrack */
    return 0;
}


/* Parse a Station IP Port message.
 *
 * Returns: !0: do not parse further PDUs in this packet.
 */
static int
parse_station_ip_port(struct sk_buff *matching_skb,
                      unsigned int offset,
                      unsigned int length,
                      enum ip_conntrack_dir direction)
{
    struct skinny_station_ip_port *station_ip_port;
    struct skinny_station_ip_port station_ip_port_buffer;

    station_ip_port = skb_header_pointer(
                           matching_skb,
                           offset,
                           sizeof(struct skinny_station_ip_port),
                           &station_ip_port_buffer);
    if (!station_ip_port) {
        return !0;
    }

    printk(KERN_INFO PRINTK_PREFIX
           "parse_station_ip_port\n");
    /* Extract Port */
    /* Set up conntrack */
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
                               enum ip_conntrack_dir direction)
{
    struct skinny_open_receive_channel_ack *open_receive_channel_ack;
    struct skinny_open_receive_channel_ack open_receive_channel_ack_buffer;

    open_receive_channel_ack = skb_header_pointer(
                           matching_skb,
                           offset,
                           sizeof(struct skinny_open_receive_channel_ack),
                           &open_receive_channel_ack_buffer);
    if (!open_receive_channel_ack) {
        return !0;
    }
    printk(KERN_INFO PRINTK_PREFIX
           "open_receive_channel_ack\n");
    /* Extract Port */
    /* Set up conntrack */
    return 0;
}


/* Parse a Open Recieve Channel Acknowledge message.
 *
 * Returns: !0: do not parse further PDUs in this packet.
 */
static int
parse_start_media_transmission(struct sk_buff *matching_skb,
                               unsigned int offset,
                               unsigned int length,
                               enum ip_conntrack_dir direction)
{
    struct skinny_start_media_transmission *start_media_transmission;
    struct skinny_start_media_transmission start_media_transmission_buffer;

    start_media_transmission = skb_header_pointer(
                                   matching_skb,
                                   offset,
                                   sizeof(struct skinny_start_media_transmission),
                                   &start_media_transmission_buffer);
    if (!start_media_transmission) {
        return !0;
    }
    printk(KERN_INFO PRINTK_PREFIX
           "start_media_transmission\n");
    /* Extract Port */
    /* Set up conntrack */
    return 0;
}


/* Parse a Skinny protocol data unit.
 *
 * Returns: !0: do not parse further PDUs in this packet.
 */
static int
parse_skinny_pdu(struct sk_buff *matching_skb,
                 unsigned int *skinny_offset,
                 unsigned int skinny_length,
                 enum ip_conntrack_dir direction)
{
    struct skinny_tcp_msg_header *tcp_msg_header;
    struct skinny_tcp_msg_header tcp_msg_header_buffer;
    struct skinny_msg_id *msg_id_header;
    struct skinny_msg_id msg_id_buffer;
    unsigned int offset;
    unsigned int msg_len;
    unsigned int msg_id;
    int ret;

    offset = *skinny_offset;

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
    tcp_msg_header = skb_header_pointer(matching_skb,
                                        offset,
                                        sizeof(struct skinny_tcp_msg_header),
                                        &tcp_msg_header_buffer);
    if (!tcp_msg_header) {
        if (net_ratelimit()) {
            printk(KERN_ERR PRINTK_PREFIX
                   "Skinny TcpMsgHeader contents missing.\n");
        }
        return !0;
    }
    msg_len = le32_to_cpu(tcp_msg_header->msg_len);
    if (msg_len > skinny_length) {
        if (net_ratelimit()) {
            printk(KERN_ERR PRINTK_PREFIX
                   "Skinny header length (%u) longer than packet (%u).\n",
                   msg_len,
                   skinny_length);
        }
        return !0;
    }
    offset += sizeof(struct skinny_tcp_msg_header);
    if (le32_to_cpu(tcp_msg_header->link_msg_type) !=
        SKINNY_LINK_MSG_TYPE_PLAINTEXT) {
        if (net_ratelimit()) {
            printk(KERN_INFO PRINTK_PREFIX
                   "Skinny protocol data unit not plaintext but is "
                   "link_msg_type %u. Cannot analyse this PDU,"
                   "continuing with next PDU.\n",
                   tcp_msg_header->link_msg_type);
        }
        *skinny_offset = offset;
        return 0;
    }

    /* The msg_id identifies the purpose and structure of the
     * message.  We only need to parse some msg_id types to be
     * able to track a connection.
     */
    msg_id_header = skb_header_pointer(matching_skb,
                                       offset,
                                       sizeof(struct skinny_msg_id),
                                       &msg_id_buffer);
    
    if (!msg_id_header) {
        if (net_ratelimit()) {
            printk(KERN_ERR PRINTK_PREFIX
                   "Skinny msg_id contents missing.\n");
        }
        return !0;
    }
    msg_id = le16_to_cpu(msg_id_header->msg_id);
    offset += sizeof(struct skinny_msg_id);

    switch (msg_id) {
    case SKINNY_MSG_ID_STATION_REGISTER:
        ret = parse_station_register(matching_skb,
                                     offset,
                                     msg_len,
                                     direction);
        break;
    case SKINNY_MSG_ID_STATION_IP_PORT:
        ret = parse_station_ip_port(matching_skb,
                                    offset,
                                    msg_len,
                                    direction);
        break;
    case SKINNY_MSG_ID_OPEN_RECEIVE_CHANNEL_ACK:
        ret = parse_open_receive_channel_ack(matching_skb,
                                             offset,
                                             msg_len,
                                             direction);
        break;
    case SKINNY_MSG_ID_START_MEDIA_TRANSMISSION:
        ret = parse_start_media_transmission(matching_skb,
                                             offset,
                                             msg_len,
                                             direction);
        break;
    default:
        /* Other PDUs have contents which don't need connection
         * tracking.
         */
        ret = 0;
    }
    *skinny_offset = offset + msg_len;

    return ret;
}


static int
parse_skinny_packet(struct sk_buff *matching_skb,
                    unsigned int skinny_offset,
                    unsigned int skinny_length,
                    enum ip_conntrack_dir direction)
{
    unsigned int offset;
    int problems = 0;

    /* The packet can contain one or more Skinny protocol data units.
     * Accept the packet unless a subordinate parser says to toss it.
     */
    offset = skinny_offset;
    while (offset <= skinny_length && !problems) {
        problems = parse_skinny_pdu(matching_skb,
                                    &offset,
                                    skinny_length,
                                    direction);
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
    unsigned int skinny_offset,
                 skinny_length;
    char *skinny_header;

    printk(KERN_INFO "helper\n");

    /* Don't track connections until the TCP connection is fully
     * established. TCP handshakes carry no application data.
     */
    if (conntrack_info != IP_CT_ESTABLISHED &&
        conntrack_info != (IP_CT_ESTABLISHED + IP_CT_IS_REPLY)) {
        return NF_ACCEPT;
    }

    /* Do we need to see if the TCP checksum is valid? */

    /* Like most other conntrack modules we are too slack to
     * handle non-linear SKBs.
     */
    if (skb_is_nonlinear(matching_skb)) {
        return NF_ACCEPT;
    }

    /* Replace with finer RCU lock when data structure usage fully sorted. */
    spin_lock_bh(&skinny_buffer_lock);
    tcp_header = skb_header_pointer(matching_skb,
                                    matching_offset,
                                    sizeof(tcp_buffer),
                                    &tcp_buffer);
    if (!tcp_header) {
        ret = NF_ACCEPT;
        goto unlock_end;
    }

    /* Skinny protocol data unit is after TCP header and its options.
     * TCP stores the length of its header in .doff in units of 4-byte
     * words.
     */
    /* Is doff in network byte order? */
    skinny_offset = matching_offset + tcp_header->doff * 4;

    if (skinny_offset >= matching_skb->len) {
        if (net_ratelimit()) {
            printk(KERN_ERR PRINTK_PREFIX
                   "Unexpectedly short packet ignored. "
                   "Expected Skinny data at offset %u, but socket buffer too "
                   "short with only %u.\n",
                   skinny_offset,
                   matching_skb->len);
        }
        ret = NF_ACCEPT;
        goto unlock_end;
    }

    skinny_length = matching_skb->len - skinny_offset;
    skinny_header = skb_header_pointer(matching_skb,
                                       skinny_offset,
                                       skinny_length,
                                       skinny_buffer);
    if (!skinny_header) {
        /* No data at all, a bit odd since we were just told that there
         * was data. Hmmm.
         */
        if (net_ratelimit()) {
            printk(KERN_ERR PRINTK_PREFIX
                   "Packet contents missing.\n");
        }
        ret = NF_ACCEPT;
        goto unlock_end;
    }

    /* Do the heavy-duty Skinny parsing, setting up connection
     * tracking if relevant protocol data units are encountered.
     */
    ret = parse_skinny_packet(matching_skb,
                              skinny_offset,
                              skinny_length,
                              CTINFO2DIR(conntrack_info));

 unlock_end:
    spin_unlock_bh(&skinny_buffer_lock);
    return ret;
}


static struct nf_conntrack_helper helper __read_mostly;

static int __init
nf_test_init(void)
{
    int problems;

    /* "Hello world, this is John Laws" */
    printk(KERN_INFO PRINTK_PREFIX
           "Compiled on " __DATE__ " at " __TIME__ ".\n");

    /* Validate parameters. */
    if (skinny_max_expected < 1) {
      printk(KERN_ERR PRINTK_PREFIX
             "Module parameter skinny_max_expected must be 1 or more. "
             "Abandoning module installation.\n");
      return -EINVAL;
    }
    if (skinny_timeout < SKINNY_TIMEOUT_REASONABLE_MIN) {
      printk(KERN_INFO PRINTK_PREFIX
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
      printk(KERN_ERR PRINTK_PREFIX
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
      printk(KERN_WARNING PRINTK_PREFIX
             "Failed to register connection tracking for TCP/IPv4 port %u. "
             "Abandoning module installation.\n",
             skinny_port);
      /* Registration of this helper failed, unset .name to indicate that */
      helper.name = NULL;
      kfree(skinny_buffer);
      skinny_buffer = NULL;
    } else {
      printk(KERN_INFO PRINTK_PREFIX
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
  printk(KERN_INFO PRINTK_PREFIX "Module removed.\n");
}

module_init(nf_test_init);
module_exit(nf_test_exit);

MODULE_AUTHOR("Glen Turner <http://www.gdt.id.au/~gdt/>");
MODULE_DESCRIPTION("Cisco Skinny Station Protocol (formerly Selsius "
                   "Connection Control Protocol, SCCP) connection tracking");
MODULE_LICENSE("GPL");
