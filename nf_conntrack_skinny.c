/* nf_conntrack_skinny -- Connection tracking for Skinny.
 *
 *
 * NAMING
 *
 * Skinny is Cisco Systems' propietary IP phone control protocol.
 * The protocol has gone by a number of names:
 *  - Cisco Skinny Station Protocol, Cisco Systems' currently preferred name.
 *  - Selsius Connection Control Protocol (SCCP, but this is also used for
 *    SS7 Signalling Connection Protocol)
 * so we'll just use Skinny, which has been the protocol's informal name
 * from the start.
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
                 "Well-known TCP port for Skinny control connection. "
                 "(Default: TCP port " VALUE(SKINNY_CONTROL_TCP_PORT) ")");

/* [1] suggests that the default connection tracking time for Skinny
 * should be 3600 seconds. In practice KeepAlive messages seem to be
 * sent down the control TCP connection by the handset every 20
 * seconds. Reasonable values for the connection tracking timeout
 * would be greater than a switch's spanning tree port forwarding hold
 * down, plus TCP retry time and would require at least three
 * KeepAlives to be lost. So values above 100 seconds are reasonable.
 *
 * [1] "Firewall Support of Skinny Client Control Protocol (SCCP)",
 *     Cisco Systems, 2005.
 *     <http://www.cisco.com/univercd/cc/td/doc/product/software/ios123/123newft/123_1/ftskinny.htm>
 */
static unsigned int __read_mostly skinny_timeout = SKINNY_TIMEOUT;
module_param(skinny_timeout, uint, S_IRUGO);
MODULE_PARM_DESC(skinny_timeout,
                 "Timeout for Skinny connection tracking. "
                 "(Default: " VALUE(SKINNY_TIMEOUT) " seconds)");

static unsigned int __read_mostly skinny_max_expected = SKINNY_MAX_EXPECTED;
module_param(skinny_max_expected, uint, S_IRUGO);
MODULE_PARM_DESC(skinny_max_expected,
                 "Maximum Skinny control connections (one used per IP phone). "
                 "(Default: " VALUE(SKINNY_MAX_EXPECTED) " connections)");

/* Access to this symbol is locked using RCU. */
unsigned int
(*nf_nat_skinny_hook)(struct sk_buff**pskb,
                      enum ip_conntrack_info ctinfo,
                      struct nf_conntrack_expect exp,
                      const char *dptr) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_skinny_hook);

char *skinny_buffer = NULL;
static DEFINE_SPINLOCK(skinny_buffer_lock);

static int
parse_skinny_pdu(char *skinny_data,
                 unsigned int skinny_length,
                 enum ip_conntrack_dir direction)
{
  /* Dump packet for debugging */
  {
    char *p;
    unsigned int i;
    char c;

    for (p = skinny_data, i = 0; i < skinny_length; p++, i++) {
      c = *p;
      if (c >= ' ' && c <= '~') {
        printk(KERN_INFO PRINTK_PREFIX
               "skinny_data[%u] = %d %02x %c\n",
               i, (int)c, (int)c, c);
      } else {
        printk(KERN_INFO PRINTK_PREFIX
               "skinny_data[%u] = %d %02x\n",
               i, (int)c, (int)c);
      }
    }
  }

  /* Skinny PDUs start with a header.
   * It contains:
   *  MsgLen, 4 bytes, unsigned integer
   *    The length of the message, not including this header.
   *  LinkMsgType, 4 bytes, unsigned integer
   *    Indicates encryption or compression of follwing content.
   *    The only known value is 0 -- plain text.
   */
  

    /* while not end of packet */
    /* if msg_len enough */
    /* if msg_type 0 */
    /* extract msg_id */
    /* case msg_id */
    /* parse msg types */
    return NF_ACCEPT;
}


/* The Skinny TCP control connecction exchanges information about the
 * establishment of RTP flows. This helper module tracks the TCP
 * connection adding expected RTP flows to the connection tracking
 * system.
 */

static int
skinny_conntrack_helper(struct sk_buff **matching_skb_p,
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
    if (skb_is_nonlinear(*matching_skb_p)) {
      return NF_ACCEPT;
    }

    spin_lock_bh(&skinny_buffer_lock);
    tcp_header = skb_header_pointer(*matching_skb_p,
                                    matching_offset,
                                    sizeof(tcp_buffer),
                                    &tcp_buffer);
    if (!tcp_header) {
      ret = NF_ACCEPT;
      goto unlock_end;
    }

    /* Skinny protocol data unit is after TCP header and its options. */
    skinny_offset = matching_offset + tcp_header->doff * 4;

    if (skinny_offset >= (*matching_skb_p)->len) {
     if (net_ratelimit()) {
        printk(KERN_ERR PRINTK_PREFIX
               "Unexpectedly short packet ignored. "
               "Expected Skinny data at offset %u, but socket buffer too "
               "short with only %u.\n",
               skinny_offset,
               (*matching_skb_p)->len);
      }
      ret = NF_ACCEPT;
      goto unlock_end;
    }
    skinny_length = (*matching_skb_p)->len - skinny_offset;
    skinny_header = skb_header_pointer(*matching_skb_p,
                                       skinny_offset,
                                       skinny_length,
                                       skinny_buffer);
    if (!skinny_header) {
      ret = NF_ACCEPT;
      goto unlock_end;
    }

    ret = parse_skinny_pdu(skinny_header,
                           skinny_length,
                           CTINFO2DIR(conntrack_info));

#if 0
    skinny_message_header = skb_header_pointer(*matching_skb_p,
                                               skinny_offset,
                                               sizeof(struct skinny_tcp_msg_header),
                                               skinny_tcp_msg_header_buffer);
    if (!skinny_message_header) {
      ret = NF_ACCEPT;
      goto unlock_end;
    }
    if (skinny_message_header->link_msg_type !=
        SKINNY_LINK_MSG_TYPE_PLAINTEXT) {
      ret = NF_ACCEPT;
      goto unlock_end;
    }
    remaining_skinny_msg = skinny_message_header->msg_len;
    if (!remaining_skinny_msg) {
      ret = NF_ACCEPT;
      goto unlock_end;
    }

    remaining_offset = skinny_offset + sizeof(struct skinny_tcp_msg_header);
    while (remaining_skinny_msg) {
      msg_id = skb_header_pointer(*matching_skb_p,
                                  remaining_offset,
                                  sizeof(__le16),   /* BUG IN STUCT */
                                  some sort of buffer
                                  /* UP TO HERE */
    }

#endif

 unlock_end:
    spin_unlock_bh(&skinny_buffer_lock);
    return ret;
}


static struct nf_conntrack_helper helper __read_mostly;

static int __init
nf_test_init(void)
{
    int problems;

    /* Hello world, this is John Laws */
    printk(KERN_INFO PRINTK_PREFIX
           "Compiled on " __DATE__ " at " __TIME__ ".\n");

    /* Validate parameters. */
    if (skinny_max_expected < 1) {
      printk(KERN_ERR PRINTK_PREFIX
             "Module parameter skinny_max_expected must be 1 or more. "
             "Abandoning module installation.\n");
      return -EINVAL;
    }
    if (skinny_timeout < 20) {
      printk(KERN_INFO PRINTK_PREFIX
             "Module parameter skinny_timeout is perhaps too low at less "
             "than 20 seconds. "
             "The Light Brigade charges onwards regardless.\n");
    }

    /* Allocate resources.
     * A non-NULL value for a resource is a flag that it should be
     * freed upon module removal.
     */
    skinny_buffer = kmalloc(0x10000, GFP_KERNEL);
    if (!skinny_buffer) {
      /* If they even see this message then the author of printk() has
       * done fine work. Linux doesn't yet run on 8-bit computers.
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
    helper.mask.src.l3num = 0xff;
    helper.tuple.dst.protonum = IPPROTO_TCP;
    helper.mask.dst.protonum = 0xff;
    helper.tuple.src.u.tcp.port = htons(skinny_port);
    helper.mask.src.u.tcp.port = __constant_htons(0xffff);

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

MODULE_AUTHOR("Glen Turner <gdt+linux@gdt.id.au>");
MODULE_DESCRIPTION("Cisco Skinny Station Protocol (formerly Selsius Connection "
                   "Control Protocol, SCCP) connection tracking");
MODULE_LICENSE("GPL");
