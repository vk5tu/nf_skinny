/* ip_conntrack_skinny.h --
 * Protocol definitions for network address translation for Skinny.
 *
 * $Id$
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
 *
 *
 * Note carefully that there is no public specification for Skinny.  A
 * lot of this file is educated guesswork verified by experimentation
 * and builds upon similar work in other openly-licensed software.
 *
 * As far as they are known, message and field names use the same
 * names as used in Cisco Systems' documentation, except that
 * StuddlyCapsNames are given as bsd_style_names. If you have seen
 * different field names in the log files of a Call Manager than
 * please let me know and I'll correct this code.
 *
 */

#ifndef _NF_CONNTRACK_SKINNY_H
#define _NF_CONNTRACK_SKINNY_H

#include <linux/netfilter/nf_conntrack_common.h>

/* The Skinny protocol uses a TCP/IP control connection from the IP
 * Phone to the Call Manager. This connection is used to negotiate
 * RTP/UDP/IP voice streams when a phone call is placed or
 * received. Regular keep-alives are also sent across the control
 * connection so the Call Manager knows if the IP Phone is alive and
 * ready for calls which may be placed to it.
*/
#define SKINNY_CONTROL_TCP_PORT 2000

#ifdef __KERNEL__

#include <stddef.h>  /* For offsetof() */

/* Netfilter parameters. */

/* Before changing this convert the conntrack module to use an array/ */
#define SKINNY_MAX_EXPECTED 8

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
#define SKINNY_TIMEOUT 3600
#define SKINNY_TIMEOUT_REASONABLE_MIN 100

/* The Skinny protocol may have multiple protocol data units within
 * one TCP packet. The stream of Skinny PDUs looks like this:
 *
 *   msg_len link_msg_type ... msg_len link_msg_type ...
 *
 * The msg_len is the number of bytes in ... It is possible that
 * msg_len could be 0, although this has never been seen.
 *
 * The link_msg_type specifies the encryption or compression of the
 * payload. Only 0 has been seen in the wild, meaning plain text.  If
 * other vaules are seen then the PDU cannot be safely decoded.
 *
 * In all packets seen to date the first 4 bytes of ... are the
 * msg_id. This indicates the function and structure of the remainder
 * of the PDU. Note carefully that the PDU is extensible -- depending
 * on the value of msg_len fields may or may not exist. So it is an
 * error to assume that seeing a particular value of msg_id implies
 * that *all* of that message's fields will follow.
 *
 * Field numeric values are usually lowest significant byte
 * first. Confusingly, networking fields (such as IPv4 Address and UDP
 * Port) are given as most significant byte first (ie, "network byte
 * order").
 *
 * Some 16-bit numeric values are padded with zeros. UDP Port is the
 * most confusing of these, with the port number in network byte order
 * but the padding in the LSB order resulting in this bizarre sequence
 * on the wire:
 *
 *    udp_port(msb) | udp_port(lsb) | 0 | 0
 *
 * Field string values appear to be left aligned and
 * '\0'-padded. Although a terminating '\0' has been seen on all
 * strings to date, in the absence of a specification there is no
 * assurance that this will remain so.
 */


/* Message IDs that contain network addresses or ports and thus need
 * to come to the attention of Network Address Translation.  In the
 * future we might want to additionally track OpenRecieveChannel,
 * CloseReceiveChannel and StopMediaTransmission and bring down the
 * RTP connections implied by those messages' ConferenceID and
 * PassThruPartyID.  That would free up resources in preference to
 * letting the NAT time out.
 */
enum {
    SKINNY_MSG_ID_STATION_REGISTER = 0x00000001,
    SKINNY_MSG_ID_STATION_IP_PORT = 0x00000002,
    SKINNY_MSG_ID_OPEN_RECEIVE_CHANNEL_ACK = 0x00000022,
    SKINNY_MSG_ID_START_MEDIA_TRANSMISSION = 0x0000008a,
};

/* Encryption or compression of following Skinny protocol data unit. */
enum {
    SKINNY_LINK_MSG_TYPE_PLAINTEXT = 0x00000000,
};

struct __attribute__((__packed__)) skinny_tcp_msg_header {
    /* Message length. Number of octets following struct
     * skinny_header. Note carefully that the number of octets may not
     * allow all of the fields in the struct skinny_...  messsage
     * descriptions below to be valid. This is because the message
     * definitions can grow over time.
     *
     * Since there is no specifiation we do not know if msg_len==0 is
     * valid traffic. Allowing for this value complicates parsing, but
     * not allowing this value might suppress important but empty
     * traffic (such as some sort of keepalive).
     */
    __le32 msg_len;

    /* Link message type, indicates services such as encryption,
     * compression, etc. Only value 0 has been observed in the
     * wild. Do not try to parse a message with a non-zero value as
     * the contents may not be in plain text.
     */
    __le32 link_msg_type;
};

struct __attribute__((__packed__)) skinny_msg_id {
    /* Message identifier contains the purpose and structure of the
     * remainder of this protocol data unit.
     */
    __le32 msg_id;
};

/* When the phone boots it sends this message to the Call Manager to
 * register the phone's availability to handle calls. That
 * availability is then continually tracked by the Call Manager
 * (through arriving keep_alive PDUs). The Call Manager's availability
 * is also tracked by the IP Phone (through incoming keep_alive_ack
 * PDUs).
 */
#define SKINNY_STATION_REGISTER_DEVICE_NAME_LENGTH 16
struct __attribute__((__packed__)) skinny_station_register {
    /* Device names encountered to date are printable ASCII,
     * left-justified, NUL filled and NUL terminated. But without a
     * specification this can't be relied upon.
     */
    char device_name[SKINNY_STATION_REGISTER_DEVICE_NAME_LENGTH];
    /* Guess is that this is the user of a multi-user device.
     */
    __le32 station_user_id;
    /* Guess is that this is the instance of a soft-phone program
     * where a host can run multiple soft phones. This would be easy
     * to check, but I have not done so.
     *
     * It is supposed that (device_name, station_user_id,
     * station_instance) fully identify a IP Phone independently of
     * ip_address. Certainly the Cisco Call Manager goes to some
     * lengths to keep registered device_names unique.
     */
    __le32 station_instance;
    /* This is the device's IP address. It should match that in the IP
     * header. It is supposed that it exists here to allow for Skinny
     * protocol proxies.
     *
     * This address should be re-written by NAT.
     */
    __be32 ip_address;
    /* End of data required for connection tracking. */
    /* Device type indicates the make and model of the IP Phone. */
    __le32 device_type;
    /*
     * Maximum streams is the concurrent call-handling capacity of the
     * IP Phone.
     */
    __le32 max_streams;
};
/* There is a coding trick used for writing a parser using this
 * header. Not all of the contents of a protocol data unit need to
 * appear, as msg_len could be shorter than the length of the full
 * PDU. But C allows a pointer to a structure to point to memory which
 * is less than the size of that structure as long as the overhanging
 * data is not read or written.
 *
 * This trick allows us to pull in msg_len worth of data, check that
 * the elements of the structure that interest us are less than
 * msg_len, and read out those elements. The USEFUL_LENGTH macros for
 * each structure give the minimum msg_len which is needed for
 * connection tracking and NAT.
 */
#define SKINNY_STATION_REGISTER_USEFUL_LENGTH \
        offsetof(struct skinny_station_register, device_type)

/* When the phone is booting this message is sent to the Call Manager
 * to allow the Call Manager to send media to the IP Phone using
 * RTP/UDP/IP.
 */
struct __attribute__((__packed__)) skinny_station_ip_port {
    /* 16 bit UDP port in a 32-bit field in this odd sequence of bytes:
     *  PORT_MSB PORT_LSB 00 00
     * The trailing bytes have always been observed to be zero and are
     * presumed to fill the value to a 4-byte boundary.
     *
     * This port should be re-written by NAT so that multiple IP Phones
     * can exist beyond the NAT device.
     */
    __be16 udp_port;
    __u16 expected_to_be_zero;
};
#define SKINNY_STATION_IP_PORT_USEFUL_LENGTH \
        offsetof(struct skinny_station_ip_port, expected_to_be_zero)

/* When a call is placed the Call Manager sends a open_receive_channel
 * to the IP Phone instructing it to open a RTP/UDP/IP port for media
 * with the other IP Phone. The IP Phone sends back a
 * open_receive_channel_ack to the Call Manager containing the details
 * of the UDP port to use for the soon-to-be incoming media.
 *
 * The Call Manager forwards these details to the other IP Phone in a
 * start_media_transmission.
 */
struct __attribute__((__packed__)) skinny_open_receive_channel_ack {
    __le32 open_receive_channel_status;
    __be32 ip_address;
    __be16 udp_port;
    /* These are in the message, but after the data we need for NAT,
     * so if a short message does not include this data we can still
     * proceed.
     */
    __u16 expected_to_be_zero;
    __le32 pass_thru_party_id;
};
#define SKINNY_OPEN_RECEIVE_CHANNEL_ACK_USEFUL_LENGTH \
        offsetof(struct skinny_open_receive_channel_ack, expected_to_be_zero)

/* The Call Manager sends a start_media_transmission to the IP Phone
 * instructing it to send RTP/UDP/IP traffic to (remote_ip_address,
 * remote_udp_port). The media is taken from the handset and sent
 * using the codec implied by payload_capability at the rate ms_packet
 * with silence_suppession and max_frames_per_packet.
 *
 * This packet does not need its contents NATed. But it does need to
 * participate in connection tracking so that a firewall rule which
 * blocks all outgoing UDP traffic except that related to Skinny
 * connections can be written.
 */
struct __attribute__((__packed__)) skinny_start_media_transmission {
    __le32 conference_id;
    __le32 pass_thru_party_id;
    __be32 remote_ip_address;
    __be16 remote_udp_port;
    /* These are in the message, but after the data we need for NAT,
     * so if a short message does not include this data we can still
     * proceed.
     */
    __u16 expected_to_be_zero;
    __le32 ms_packet;
    __le32 payload_capability;
    /* When we implement QoS we will also need Precedence from this
     * message, as that contains the DSCP that should be used for
     * RTP/UDP/IP traffic.
     */
    __le32 precedence;
    __le32 silence_suppression;
    __le16 max_frames_per_packet;
    __le32 g723_bit_rate;
};
#define SKINNY_START_MEDIA_TRANSMISSION_USEFUL_LENGTH \
        offsetof(struct skinny_start_media_transmission_length, \
                 expected_to_be_zero)


/* Connection tracking */
struct nf_skinny_ct_info {
    /* Identify the phone. */
    unsigned int station_instance;
    unsigned int station_user_id;
    char device_name[SKINNY_STATION_REGISTER_DEVICE_NAME_LENGTH];
};


/* IP Phone registration with the Call Manager works as follows:
 *
 * A phone boots, the DHCP response gives the phone a host name and
 * the address of a TFTP server for IP Phones (option 150). The TFTP
 * server holds the phone's configuration, in a filename containing
 * the phone's host name. That configuration has the address of the
 * Call Manager.
 *
 * The phone registers with the Call Manager using a
 * "register_device".
 *
 * ###FIX ME###
 *
 */

#endif /* defined(__KERNEL__) */

#endif /* !defined(_NF_CONNTRACK_SKINNY_H) */
