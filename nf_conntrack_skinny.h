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
 */

#ifndef _NF_CONNTRACK_SKINNY_H
#define _NF_CONNTRACK_SKINNY_H

#include <linux/netfilter/nf_conntrack_common.h>

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

/* The Skinny protocol may have multiple protocol data units with
 * one TCP packet. The stream of Skinny PDUs looks like this:
 *   msg_len link_msg_type ... msg_len link_msg_type ...
 * The msg_len is the number of bytes in ...
 * The link_msg_type specifies the encryption or compression of the
 * payload. Only 0 has been seen in the wild, meaning plain text.  If
 * other vaules are seen then this PDU cannot be safely decoded.
 *
 * In all packets seen to date the first 4 bytes of ... are the
 * msg_id. This is the function of the PDU. Note carefully that the
 * PDU is extensible -- depending on the value of msg_len fields may
 * or may not exist. So it is an error to assume that seeing a
 * particular value of msg_id implies that all of that message's
 * fields will follow.
 *
 * Field numeric values are usually lowest significant byte
 * first. Confusingly, some networking fields (such as IPv4 Address)
 * are given as most significant byte first (ie, "network byte
 * order"). The representation of UDP Port is a bizaare combination of
 * both.
 *
 * Field string values are left aligned and '\0' padded. There is no
 * terminating '\0'.
 */

/* As far as they are known, message and field names use the same
 * names as used in Cisco Systems' documentation, except that
 * StuddlyCapsNames are given as bsd_style_names.
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
    /* Message type. Identifies the purpose and structure of the
     * protocol data unit.
     */
    __le32 msg_id;
};

#define SKINNY_STATION_REGISTER_DEVICE_NAME_LENGTH 16
struct __attribute__((__packed__)) skinny_station_register {
    /* Device name is left-justified, SPace or NUL filled.
     * There is no NUL terminator.
     */
    char device_name[SKINNY_STATION_REGISTER_DEVICE_NAME_LENGTH];
    __le32 station_user_id;
    __le32 station_instance;
    __be32 ip_address;
    /* These are in the message, but after the data we need for NAT,
     * so if a short message does not include this data we can still
     * proceed.
     */
    __le32 device_type;
    __le32 max_streams;
};
#define SKINNY_STATION_REGISTER_USEFUL_LENGTH \
        offsetof(struct skinny_station_register, device_type)

struct __attribute__((__packed__)) skinny_station_ip_port {
    /* 16 bit UDP port in a 32-bit field in this odd sequence of bytes:
     *  PORT_MSB PORT_LSB 00 00
     * The trailing bytes have always been observed to be zero.
     */
    __be16 udp_port;
    __u16 expected_to_be_zero;
};
#define SKINNY_STATION_IP_PORT_USEFUL_LENGTH \
        offsetof(struct skinny_station_ip_port, expected_to_be_zero)

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

/* When we implement QoS we will also need Precedence from this
 * message, as that contains the DSCP that should be used for Skinny
 * RTP traffic out the interface this packet arrives on.
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

#endif /* defined(__KERNEL__) */

#endif /* !defined(_NF_CONNTRACK_SKINNY_H) */
