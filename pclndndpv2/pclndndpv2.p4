/***************************************************************
    PEGASUS SWITCH
 **************************************************************/
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "ndn_heads.p4"

/*********************************************************************
    Ingress Parser
 * *******************************************************************/
parser SwitchIngressParser(
    packet_in packet,
    out NdnHeader_t hdr,
    out metadata_t ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    /* start parse */
    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        /* initialize metadata */
        ig_md.isInvalid = PACKET_VALID;
        ig_md.fromServer = NOT_FROM_SERVER;
        ig_md.toServer = NOT_DIRECT_TO_SERVER;
        ig_md.hasFinger1 = LOOKUP_MISS;
        ig_md.hasFinger2 = LOOKUP_MISS;
        ig_md.isExpire1 = PIT_NOT_EXPIRE;
        ig_md.isExpire2 = PIT_NOT_EXPIRE;
        // ig_md._pad1 = 0;
        ig_md.isNack = 0;
        ig_md.pcctAction = PCCT_IDLE;
        ig_md.pcctFlag = PCCT_OPR_NONE;
        ig_md.firstDir = PACKET_DROP;
        ig_md.finalDir = PACKET_DROP;
        ig_md.servernum = 0;
        ig_md.serverindex = 0;
        ig_md.portbitmap = 0;
        ig_md.fingerprint = 0;
        ig_md.outGroup = 0;
        ig_md.inPort = 0;
        ig_md.remoteOutPort = 0;
        ig_md._pad2 = 0;
        ig_md.nameIndex = 0;
        ig_md._pad3 = 0;
        transition parse_ethernet;
    }
    /* Ether header */
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_NDN:  parse_if_from_server;    // 0x8624
            default:        parse_ndn_invalid_packet;
        }
    }
    /* invalid packet */
    state parse_ndn_invalid_packet {
        ig_md.isInvalid = PACKET_INVALID;
        transition accept;
    }
    /* check if the packet comes from internal */
    state parse_if_from_server {
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_FROM_SERVER:    parse_from_server;  // 0x71
            default:                parse_if_lpPacket;
        }
    }
    /* parse internal packets */
    state parse_from_server {
        packet.extract(hdr.linkServer);
        ig_md.fromServer = FROM_SERVER;
        // transition parse_if_need_name;
        transition parse_if_lpPacket;
    }
    /* check if the header is LpPacket */
    state parse_if_lpPacket {
        transition select(packet.lookahead<bit<8>>()) {
            TtLpPacket: parse_lpPacket_tl;              // 0x64
            default:    parse_if_ndnType;
        }
    }
    /* parse LpPacket header */
    state parse_lpPacket_tl {
        packet.extract(hdr.lpPacket_tl);
        transition select(hdr.lpPacket_tl.tlv_len_code) {
            ENCODING_2BYTE: parse_lpPacket_fd_len;
            ENCODING_4BYTE: parse_ndn_invalid_packet;
            ENCODING_8BYTE: parse_ndn_invalid_packet;
            default:        parse_if_sequence_or_pitToken;  // length less than 252 Bytes
        }
    }
    state parse_lpPacket_fd_len {
        packet.extract(hdr.lpPacket_fd_len);
        transition parse_if_sequence_or_pitToken;
    }
    /* check if the header is Sequence or PitToken */
    state parse_if_sequence_or_pitToken {
        transition select(packet.lookahead<bit<8>>()) {
            // 0x51:           parse_sequence;              // 0x51 => Sequence => Fragment
            TtPitToken:     parse_pitToken_tl;              // 0x62 => PitToken
            default:        parse_ndn_invalid_packet;
        }
    }
    // state parse_sequence {
    //     packet.extract(hdr.sequence_tl);
    //     packet.extract(hdr.sequence);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         0x52:       parse_fragIndex;
    //         default:    parse_ndn_invalid_packet;
    //     }
    // }
    // state parse_fragIndex {
    //     packet.extract(hdr.fragIndex_tl);
    //     packet.extract(hdr.fragIndex);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         0x53:       parse_fragCount;
    //         default:    parse_ndn_invalid_packet;
    //     }
    // }
    // state parse_fragCount {
    //     packet.extract(hdr.fragCount_tl);
    //     packet.extract(hdr.fragCount);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         0xFD:       parse_pitToken_tl;              // 0xFD => PitToken
    //         default:    parse_ndn_invalid_packet;
    //     }
    // }
    /* parse PitToken */
    state parse_pitToken_tl {
        packet.extract(hdr.pitToken_tl);
        transition select(hdr.pitToken_tl.tlv_len_code) {
            0x07:       parse_pitToken_sevenBytes;      // NDN-DPDK forwarder assigns token with 7 bytes
            0x0a:       parse_pitToken_tenBytes;        // NDN-DPDK consumer assigns token with 10 bytes
            default:    parse_ndn_invalid_packet;
        }
    }
    state parse_pitToken_sevenBytes {
        packet.extract(hdr.token_oneByte);
        packet.extract(hdr.token_twoByte);
        packet.extract(hdr.token_fourByte);
        transition parse_if_nack_or_fragment;
    }
    state parse_pitToken_tenBytes {
        packet.extract(hdr.token_twoByte);
        packet.extract(hdr.token_eightByte);
        transition parse_if_nack_or_fragment;
    }
    /* check if the header is NACK or Fragment */
    state parse_if_nack_or_fragment {
        transition select(packet.lookahead<bit<8>>()) {
            TtFragment: parse_fragment_tl;              // 0x50    
            0xFD:       parse_probe_nack;               // may be NACK
            default:    parse_ndn_invalid_packet;
        }
    }
    /* parse NACK */
    state parse_probe_nack {
        packet.extract(hdr.nack_tl);
        transition select(hdr.nack_tl.fd_type, hdr.nack_tl.fd_len_code) {
            (0x0320, 0x05): parse_nack;
            default:        parse_ndn_invalid_packet;
        }
    }
    state parse_nack {
        packet.extract(hdr.nack);
        packet.extract(hdr.nackReason);
        ig_md.isNack = 1;

        transition parse_fragment_tl;
    }
    /* parse Fragment header */
    state parse_fragment_tl {
        packet.extract(hdr.fragment_tl);
        transition select(hdr.fragment_tl.tlv_len_code) {
            ENCODING_2BYTE: parse_fragment_fd_len;
            ENCODING_4BYTE: parse_ndn_invalid_packet;
            ENCODING_8BYTE: parse_ndn_invalid_packet;
            default:        parse_if_ndnType;
        }
    }
    state parse_fragment_fd_len {
        packet.extract(hdr.fragment_fd_len);
        transition parse_if_ndnType;
    }
    /* check if the packet is Interest or Data */
    state parse_if_ndnType {
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_INTEREST:   parse_ndnType_tl;       // 0x05  
            NDNTYPE_DATA:       parse_ndnType_tl;       // 0x06
            default:            parse_ndn_invalid_packet; 
        }
    }
    /* parse NDN type header */
    state parse_ndnType_tl {
        packet.extract(hdr.ndnType_tl);
        transition select(hdr.ndnType_tl.tlv_len_code) {
            ENCODING_2BYTE: parse_ndnType_fd_len;
            ENCODING_4BYTE: parse_ndn_invalid_packet;
            ENCODING_8BYTE: parse_ndn_invalid_packet;
            default:        parse_if_ndnName;
        }
    }
    state parse_ndnType_fd_len {
        packet.extract(hdr.ndnType_fd_len);
        transition parse_if_ndnName;
    }
    /* check if the upcoming content is NDN name */
    state parse_if_ndnName {
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_NAME:   parse_ndnName_tl;           // 0x07  
            default:        parse_ndn_invalid_packet;       
        }
    }
    /* parse name header */
    state parse_ndnName_tl {
        packet.extract(hdr.ndnName_tl);
        transition select(hdr.ndnName_tl.tlv_len_code) {
            ENCODING_2BYTE: parse_ndn_direct_server;    // FD encoded long name forward to server 
            ENCODING_4BYTE: parse_ndn_invalid_packet;
            ENCODING_8BYTE: parse_ndn_invalid_packet;
            default: parse_ndn_name_com1_type;
        }
    }
    /* unhandleable packet forward to server */
    state parse_ndn_direct_server {
        ig_md.toServer = DIRECT_TO_SERVER;
        transition accept;
    }
    /* parse the 1st name component */
    state parse_ndn_name_com1_type {
        packet.extract(hdr.name1_tl);
        transition select(hdr.name1_tl.tlv_type) {
            // NDNTYPE_COMPONENT: accept;
            NDNTYPE_COMPONENT: parse_ndn_name_com1;
            default: parse_ndn_invalid_packet;
        }
    }
    state parse_ndn_name_com1 {
        transition select(hdr.name1_tl.tlv_len_code) {
            1: parse_name_com1_len1;
            2: parse_name_com1_len2;
            3: parse_name_com1_len3;
            4: parse_name_com1_len4;
            5: parse_name_com1_len5;
            6: parse_name_com1_len6;
            7: parse_name_com1_len7;
            8: parse_name_com1_len8;
            9: parse_name_com1_len9;
            // 10: parse_name_com1_len10;
            // 11: parse_name_com1_len11;
            // 12: parse_name_com1_len12;
            // 13: parse_name_com1_len13;
            // 14: parse_name_com1_len14;
            // 15: parse_name_com1_len15;
            default: parse_ndn_direct_server;
        }
    }
    state parse_name_com1_len1 {
        packet.extract(hdr.name1_part1);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com2;
            default: accept; // guide;
        }
    }
    state parse_name_com1_len2 {
        packet.extract(hdr.name1_part2);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com2;
            default: accept; // guide;
        }
    }
    state parse_name_com1_len3 {
        packet.extract(hdr.name1_part1);
        packet.extract(hdr.name1_part2);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com2;
            default: accept; // guide;
        }
    }
    state parse_name_com1_len4 {
        packet.extract(hdr.name1_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com2;
            default: accept; // guide;
        }
    }
    state parse_name_com1_len5 {
        packet.extract(hdr.name1_part1);
        packet.extract(hdr.name1_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com2;
            default: accept; // guide;
        }
    }
    state parse_name_com1_len6 {
        packet.extract(hdr.name1_part2);
        packet.extract(hdr.name1_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com2;
            default: accept; // guide;
        }
    }
    state parse_name_com1_len7 {
        packet.extract(hdr.name1_part1);
        packet.extract(hdr.name1_part2);
        packet.extract(hdr.name1_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com2;
            default: accept; // guide;
        }
    }
    state parse_name_com1_len8 {
        packet.extract(hdr.name1_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com2;
            default: accept; // guide;
        }
    }
    state parse_name_com1_len9 {
        packet.extract(hdr.name1_part1);
        packet.extract(hdr.name1_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com2;
            default: accept; // guide;
        }
    }
    // state parse_name_com1_len10 {
    //     packet.extract(hdr.name1_part2);
    //     packet.extract(hdr.name1_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com2;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com1_len11 {
    //     packet.extract(hdr.name1_part1);
    //     packet.extract(hdr.name1_part2);
    //     packet.extract(hdr.name1_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com2;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com1_len12 {
    //     packet.extract(hdr.name1_part4);
    //     packet.extract(hdr.name1_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com2;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com1_len13 {
    //     packet.extract(hdr.name1_part1);
    //     packet.extract(hdr.name1_part4);
    //     packet.extract(hdr.name1_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com2;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com1_len14 {
    //     packet.extract(hdr.name1_part2);
    //     packet.extract(hdr.name1_part4);
    //     packet.extract(hdr.name1_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com2;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com1_len15 {
    //     packet.extract(hdr.name1_part1);
    //     packet.extract(hdr.name1_part2);
    //     packet.extract(hdr.name1_part4);
    //     packet.extract(hdr.name1_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com2;
    //         default: accept; // guide;
    //     }
    // }
    /* parse the 2nd name component */
    state parse_ndn_name_com2 {
        packet.extract(hdr.name2_tl);
        transition select(hdr.name2_tl.tlv_len_code) {
            1: parse_name_com2_len1;
            2: parse_name_com2_len2;
            3: parse_name_com2_len3;
            4: parse_name_com2_len4;
            // 5: parse_name_com2_len5;
            // 6: parse_name_com2_len6;
            // 7: parse_name_com2_len7;
            // 8: parse_name_com2_len8;
            // 9: parse_name_com2_len9;
            // 10: parse_name_com2_len10;
            // 11: parse_name_com2_len11;
            // 12: parse_name_com2_len12;
            // 13: parse_name_com2_len13;
            // 14: parse_name_com2_len14;
            // 15: parse_name_com2_len15;
            default: parse_ndn_direct_server;
        }
    }
    state parse_name_com2_len1 {
        packet.extract(hdr.name2_part1);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com3;
            default: accept; // guide;
        }
    }
    state parse_name_com2_len2 {
        packet.extract(hdr.name2_part2);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com3;
            default: accept; // guide;
        }
    }
    state parse_name_com2_len3 {
        packet.extract(hdr.name2_part1);
        packet.extract(hdr.name2_part2);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com3;
            default: accept; // guide;
        }
    }
    state parse_name_com2_len4 {
        packet.extract(hdr.name2_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com3;
            default: accept; // guide;
        }
    }
    // state parse_name_com2_len5 {
    //     packet.extract(hdr.name2_part1);
    //     packet.extract(hdr.name2_part4);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com2_len6 {
    //     packet.extract(hdr.name2_part2);
    //     packet.extract(hdr.name2_part4);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com2_len7 {
    //     packet.extract(hdr.name2_part1);
    //     packet.extract(hdr.name2_part2);
    //     packet.extract(hdr.name2_part4);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com2_len8 {
    //     packet.extract(hdr.name2_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com2_len9 {
    //     packet.extract(hdr.name2_part1);
    //     packet.extract(hdr.name2_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com2_len10 {
    //     packet.extract(hdr.name2_part2);
    //     packet.extract(hdr.name2_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com2_len11 {
    //     packet.extract(hdr.name2_part1);
    //     packet.extract(hdr.name2_part2);
    //     packet.extract(hdr.name2_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com2_len12 {
    //     packet.extract(hdr.name2_part4);
    //     packet.extract(hdr.name2_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com2_len13 {
    //     packet.extract(hdr.name2_part1);
    //     packet.extract(hdr.name2_part4);
    //     packet.extract(hdr.name2_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com2_len14 {
    //     packet.extract(hdr.name2_part2);
    //     packet.extract(hdr.name2_part4);
    //     packet.extract(hdr.name2_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com2_len15 {
    //     packet.extract(hdr.name2_part1);
    //     packet.extract(hdr.name2_part2);
    //     packet.extract(hdr.name2_part4);
    //     packet.extract(hdr.name2_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com3;
    //         default: accept; // guide;
    //     }
    // }
    /* parse the 3rd name component */
    state parse_ndn_name_com3 {
        packet.extract(hdr.name3_tl);
        transition select(hdr.name3_tl.tlv_len_code) {
            1: parse_name_com3_len1;
            2: parse_name_com3_len2;
            3: parse_name_com3_len3;
            4: parse_name_com3_len4;
            5: parse_name_com3_len5;
            6: parse_name_com3_len6;
            7: parse_name_com3_len7;
            8: parse_name_com3_len8;
            9: parse_name_com3_len9;
            10: parse_name_com3_len10;
            // 11: parse_name_com3_len11;
            // 12: parse_name_com3_len12;
            // 13: parse_name_com3_len13;
            // 14: parse_name_com3_len14;
            // 15: parse_name_com3_len15;
            default: parse_ndn_direct_server;
        }
    }
    state parse_name_com3_len1 {
        packet.extract(hdr.name3_part1);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com4;
            default: accept; // guide;
        }
    }
    state parse_name_com3_len2 {
        packet.extract(hdr.name3_part2);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com4;
            default: accept; // guide;
        }
    }
    state parse_name_com3_len3 {
        packet.extract(hdr.name3_part1);
        packet.extract(hdr.name3_part2);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com4;
            default: accept; // guide;
        }
    }
    state parse_name_com3_len4 {
        packet.extract(hdr.name3_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com4;
            default: accept; // guide;
        }
    }
    state parse_name_com3_len5 {
        packet.extract(hdr.name3_part1);
        packet.extract(hdr.name3_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com4;
            default: accept; // guide;
        }
    }
    state parse_name_com3_len6 {
        packet.extract(hdr.name3_part2);
        packet.extract(hdr.name3_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com4;
            default: accept; // guide;
        }
    }
    state parse_name_com3_len7 {
        packet.extract(hdr.name3_part1);
        packet.extract(hdr.name3_part2);
        packet.extract(hdr.name3_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com4;
            default: accept; // guide;
        }
    }
    state parse_name_com3_len8 {
        packet.extract(hdr.name3_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com4;
            default: accept; // guide;
        }
    }
    state parse_name_com3_len9 {
        packet.extract(hdr.name3_part1);
        packet.extract(hdr.name3_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com4;
            default: accept; // guide;
        }
    }
    state parse_name_com3_len10 {
        packet.extract(hdr.name3_part2);
        packet.extract(hdr.name3_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com4;
            default: accept; // guide;
        }
    }
    // state parse_name_com3_len11 {
    //     packet.extract(hdr.name3_part1);
    //     packet.extract(hdr.name3_part2);
    //     packet.extract(hdr.name3_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com4;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com3_len12 {
    //     packet.extract(hdr.name3_part4);
    //     packet.extract(hdr.name3_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com4;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com3_len13 {
    //     packet.extract(hdr.name3_part1);
    //     packet.extract(hdr.name3_part4);
    //     packet.extract(hdr.name3_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com4;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com3_len14 {
    //     packet.extract(hdr.name3_part2);
    //     packet.extract(hdr.name3_part4);
    //     packet.extract(hdr.name3_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com4;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com3_len15 {
    //     packet.extract(hdr.name3_part1);
    //     packet.extract(hdr.name3_part2);
    //     packet.extract(hdr.name3_part4);
    //     packet.extract(hdr.name3_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_name_com4;
    //         default: accept; // guide;
    //     }
    // }
    /* parse the 4th name component */
    state parse_ndn_name_com4 {
        packet.extract(hdr.name4_tl);
        transition select(hdr.name4_tl.tlv_len_code) {
            1: parse_name_com4_len1;
            2: parse_name_com4_len2;
            3: parse_name_com4_len3;
            4: parse_name_com4_len4;
            5: parse_name_com4_len5;
            6: parse_name_com4_len6;
            7: parse_name_com4_len7;
            8: parse_name_com4_len8;
            // 9: parse_name_com4_len9;
            // 10: parse_name_com4_len10;
            // 11: parse_name_com4_len11;
            // 12: parse_name_com4_len12;
            // 13: parse_name_com4_len13;
            // 14: parse_name_com4_len14;
            // 15: parse_name_com4_len15;
            default: parse_ndn_direct_server;
        }
    }
    state parse_name_com4_len1 {
        packet.extract(hdr.name4_part1);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com5;
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com4_len2 {
        packet.extract(hdr.name4_part2);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com5;
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com4_len3 {
        packet.extract(hdr.name4_part1);
        packet.extract(hdr.name4_part2);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com5;
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com4_len4 {
        packet.extract(hdr.name4_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com5;
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com4_len5 {
        packet.extract(hdr.name4_part1);
        packet.extract(hdr.name4_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com5;
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com4_len6 {
        packet.extract(hdr.name4_part2);
        packet.extract(hdr.name4_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com5;
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com4_len7 {
        packet.extract(hdr.name4_part1);
        packet.extract(hdr.name4_part2);
        packet.extract(hdr.name4_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com5;
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com4_len8 {
        packet.extract(hdr.name4_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_name_com5;
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    // state parse_name_com4_len9 {
    //     packet.extract(hdr.name4_part1);
    //     packet.extract(hdr.name4_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_direct_server;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com4_len10 {
    //     packet.extract(hdr.name4_part2);
    //     packet.extract(hdr.name4_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_direct_server;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com4_len11 {
    //     packet.extract(hdr.name4_part1);
    //     packet.extract(hdr.name4_part2);
    //     packet.extract(hdr.name4_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_direct_server;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com4_len12 {
    //     packet.extract(hdr.name4_part4);
    //     packet.extract(hdr.name4_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_direct_server;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com4_len13 {
    //     packet.extract(hdr.name4_part1);
    //     packet.extract(hdr.name4_part4);
    //     packet.extract(hdr.name4_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_direct_server;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com4_len14 {
    //     packet.extract(hdr.name4_part2);
    //     packet.extract(hdr.name4_part4);
    //     packet.extract(hdr.name4_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_direct_server;
    //         default: accept; // guide;
    //     }
    // }
    // state parse_name_com4_len15 {
    //     packet.extract(hdr.name4_part1);
    //     packet.extract(hdr.name4_part2);
    //     packet.extract(hdr.name4_part4);
    //     packet.extract(hdr.name4_part8);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         NDNTYPE_COMPONENT: parse_ndn_direct_server;
    //         default: accept; // guide;
    //     }
    // }

    /* parse the 5th name component */
    state parse_ndn_name_com5 {
        packet.extract(hdr.name5_tl);
        transition select(hdr.name5_tl.tlv_len_code) {
            1: parse_name_com5_len1;
            2: parse_name_com5_len2;
            3: parse_name_com5_len3;
            4: parse_name_com5_len4;
            5: parse_name_com5_len5;
            6: parse_name_com5_len6;
            7: parse_name_com5_len7;
            8: parse_name_com5_len8;
            9: parse_name_com5_len9;
            10: parse_name_com5_len10;
            11: parse_name_com5_len11;
            12: parse_name_com5_len12;
            13: parse_name_com5_len13;
            14: parse_name_com5_len14;
            15: parse_name_com5_len15;
            16: parse_name_com5_len16;
            default: parse_ndn_direct_server;
        }
    }
    state parse_name_com5_len1 {
        packet.extract(hdr.name5_part1);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len2 {
        packet.extract(hdr.name5_part2);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len3 {
        packet.extract(hdr.name5_part1);
        packet.extract(hdr.name5_part2);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len4 {
        packet.extract(hdr.name5_part4);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len5 {
        packet.extract(hdr.name5_part1);
        packet.extract(hdr.name5_part4);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len6 {
        packet.extract(hdr.name5_part2);
        packet.extract(hdr.name5_part4);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len7 {
        packet.extract(hdr.name5_part1);
        packet.extract(hdr.name5_part2);
        packet.extract(hdr.name5_part4);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }

    state parse_name_com5_len8 {
        packet.extract(hdr.name5_part8);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len9 {
        packet.extract(hdr.name5_part1);
        packet.extract(hdr.name5_part8);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len10 {
        packet.extract(hdr.name5_part2);
        packet.extract(hdr.name5_part8);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len11 {
        packet.extract(hdr.name5_part1);
        packet.extract(hdr.name5_part2);
        packet.extract(hdr.name5_part8);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len12 {
        packet.extract(hdr.name5_part4);
        packet.extract(hdr.name5_part8);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len13 {
        packet.extract(hdr.name5_part1);
        packet.extract(hdr.name5_part4);
        packet.extract(hdr.name5_part8);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len14 {
        packet.extract(hdr.name5_part2);
        packet.extract(hdr.name5_part4);
        packet.extract(hdr.name5_part8);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len15 {
        packet.extract(hdr.name5_part1);
        packet.extract(hdr.name5_part2);
        packet.extract(hdr.name5_part4);
        packet.extract(hdr.name5_part8);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }
    state parse_name_com5_len16 {
        packet.extract(hdr.name5_part16);
        transition select(packet.lookahead<bit<8>>()) {
            // NDNTYPE_COMPONENT: parse_ndn_direct_server;
            NDNTYPE_COMPONENT: parse_ndn_name_com6;
            default: accept; // guide;
        }
    }

    /* parse the 6th name component */
    state parse_ndn_name_com6 {
        packet.extract(hdr.name6_tl);
        transition select(hdr.name6_tl.tlv_len_code) {
            1: parse_name_com6_len1;
            2: parse_name_com6_len2;
            3: parse_name_com6_len3;
            4: parse_name_com6_len4;
            5: parse_name_com6_len5;
            6: parse_name_com6_len6;
            7: parse_name_com6_len7;
            8: parse_name_com6_len8;
            9: parse_name_com6_len9;
            10: parse_name_com6_len10;
            11: parse_name_com6_len11;
            12: parse_name_com6_len12;
            13: parse_name_com6_len13;
            14: parse_name_com6_len14;
            15: parse_name_com6_len15;
            16: parse_name_com6_len16;
            17: parse_name_com6_len17;
            18: parse_name_com6_len18;
            19: parse_name_com6_len19;
            default: parse_ndn_direct_server;
        }
    }
    state parse_name_com6_len1 {
        packet.extract(hdr.name6_part1);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            // NDNTYPE_COMPONENT: parse_ndn_name_com5;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len2 {
        packet.extract(hdr.name6_part2);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            // NDNTYPE_COMPONENT: parse_ndn_name_com5;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len3 {
        packet.extract(hdr.name6_part1);
        packet.extract(hdr.name6_part2);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            // NDNTYPE_COMPONENT: parse_ndn_name_com5;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len4 {
        packet.extract(hdr.name6_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            // NDNTYPE_COMPONENT: parse_ndn_name_com5;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len5 {
        packet.extract(hdr.name6_part1);
        packet.extract(hdr.name6_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            // NDNTYPE_COMPONENT: parse_ndn_name_com5;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len6 {
        packet.extract(hdr.name6_part2);
        packet.extract(hdr.name6_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            // NDNTYPE_COMPONENT: parse_ndn_name_com5;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len7 {
        packet.extract(hdr.name6_part1);
        packet.extract(hdr.name6_part2);
        packet.extract(hdr.name6_part4);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            // NDNTYPE_COMPONENT: parse_ndn_name_com5;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len8 {
        packet.extract(hdr.name6_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len9 {
        packet.extract(hdr.name6_part1);
        packet.extract(hdr.name6_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len10 {
        packet.extract(hdr.name6_part2);
        packet.extract(hdr.name6_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len11 {
        packet.extract(hdr.name6_part1);
        packet.extract(hdr.name6_part2);
        packet.extract(hdr.name6_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len12 {
        packet.extract(hdr.name6_part4);
        packet.extract(hdr.name6_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len13 {
        packet.extract(hdr.name6_part1);
        packet.extract(hdr.name6_part4);
        packet.extract(hdr.name6_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len14 {
        packet.extract(hdr.name6_part2);
        packet.extract(hdr.name6_part4);
        packet.extract(hdr.name6_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len15 {
        packet.extract(hdr.name6_part1);
        packet.extract(hdr.name6_part2);
        packet.extract(hdr.name6_part4);
        packet.extract(hdr.name6_part8);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len16 {
        packet.extract(hdr.name6_part16);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len17 {
        packet.extract(hdr.name6_part1);
        packet.extract(hdr.name6_part16);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len18 {
        packet.extract(hdr.name6_part2);
        packet.extract(hdr.name6_part16);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }
    state parse_name_com6_len19 {
        packet.extract(hdr.name6_part1);
        packet.extract(hdr.name6_part2);
        packet.extract(hdr.name6_part16);
        transition select(packet.lookahead<bit<8>>()) {
            NDNTYPE_COMPONENT: parse_ndn_direct_server;
            default: accept; // guide;
        }
    }

    // state parse_guide {
    //     transition select(packet.lookahead<bit<8>>()) {
    //         0x21 : parse_canbeprefix_tl;
    //         0x12 : parse_mustbefresh_tl;
    //         0x0A : parse_nonce_tl;
    //         0x0C : parse_lifetime_tl;    
    //         default:    accept;
    //     }
    // }

    // state parse_canbeprefix_tl {
    //     packet.extract(hdr.canbeprefix_info_tl);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         0x12 : parse_mustbefresh_tl;
    //         0x0A : parse_nonce_tl;
    //         0x0C : parse_lifetime_tl;    
    //         default:    accept;
    //     }
    // }

    // state parse_mustbefresh_tl {
    //     packet.extract(hdr.mustbefresh_info_tl);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         0x0A : parse_nonce_tl;
    //         0x0C : parse_lifetime_tl;    
    //         default:    accept;
    //     }
    // }

    // state parse_nonce_tl {
    //     packet.extract(hdr.nonce_tl);
    //     packet.extract(hdr.nonce);
    //     transition select(packet.lookahead<bit<8>>()) {
    //         0x0C :      parse_lifetime_tl;    
    //         default:    accept;
    //     }
    // }

    // state parse_lifetime_tl {
    //     packet.extract(hdr.lifetime_tl);
    //     transition select(hdr.lifetime_tl.tlv_len_code) {
    //         0x01:   parse_lifetime_oneByte;
    //         0x02:   parse_lifetime_twoByte;
    //         default:        accept;
    //     }
    // }
    
    // state parse_lifetime_oneByte {
    //     packet.extract(hdr.lifetime_oneByte);
    //     transition accept;
    // }

    // state parse_lifetime_twoByte {
    //     packet.extract(hdr.lifetime_twoByte);
    //     transition accept;
    // }
}

/*********************************************************************
    Ingress Deparser
 * *******************************************************************/
control SwitchIngressDeparser(
    packet_out packet,
    inout      NdnHeader_t hdr,
    in         metadata_t ig_md,
    in         ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        packet.emit(hdr);
    }
}

/*********************************************************************
    Ingress
 * *******************************************************************/
control SwitchIngress(
    inout NdnHeader_t hdr,
    inout metadata_t ig_md,
    in    ingress_intrinsic_metadata_t ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    /* Definition of Temporary Variables */
    bit<8> serverhash = 0;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) name_hash_key;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) name_sig_hash;
    Hash<bit<8>>(HashAlgorithm_t.CRC8)  server_hash;
    // bit<8> cur_tstamp = ig_prsr_md.global_tstamp[39:32]; // 4.295s
    // bit<8> cur_tstamp = ig_prsr_md.global_tstamp[31:24]; // 0.017s

    Register<bit<8>, bit<1>>(1) reg_server_number;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_server_number) ServerNumberRead = {
        void apply(inout bit<8> servernum, out bit<8> outnum) {
            outnum = servernum;
        }
    };

    /* PIT Register Group 1 */
    Register<bit<8>, bit<17>>(PCCT_REG_SIZE) reg_table_time1;
    RegisterAction<bit<8>, bit<17>, bit<1>>(reg_table_time1) Time1Check = {
        void apply(inout bit<8> tstamp, out bit<1> isExpire) {
            isExpire = PIT_NOT_EXPIRE;
            if (tstamp != ig_prsr_md.global_tstamp[39:32]) {
                isExpire = PIT_EXPIRE;
                tstamp = ig_prsr_md.global_tstamp[39:32];
            }
        }
    };

    Register<bit<16>, bit<17>>(PCCT_REG_SIZE) reg_table_finger1;
    RegisterAction<bit<16>, bit<17>, bit<8>>(reg_table_finger1) Finger1AddAndUpdateEntry = {
        void apply(inout bit<16> fingerprint, out bit<8> pitflag) {
            pitflag = PCCT_OPR_NONE;
            if (fingerprint == 0 || ig_md.isExpire1 == PIT_EXPIRE) {
                fingerprint = ig_md.fingerprint;
                pitflag = PCCT_OPR_NEW;
            } else if (fingerprint == ig_md.fingerprint) {
                pitflag = PCCT_OPR_UPDATE;
            }
        }
    };
    RegisterAction<bit<16>, bit<17>, bit<1>>(reg_table_finger1) Finger1CheckAndClean = {
        void apply(inout bit<16> fingerprint, out bit<1> pitflag) {
            pitflag = LOOKUP_MISS;
            if (fingerprint == ig_md.fingerprint) {
                pitflag = LOOKUP_HIT;
                fingerprint = 0;
            }
        }
    };
    
    Register<bit<16>, bit<17>>(PCCT_REG_SIZE) reg_table_portmap1;
    RegisterAction<bit<16>, bit<17>, void>(reg_table_portmap1) Portmap1AddAndUpdateEntry = {
        void apply(inout bit<16> portbitmap) {
            portbitmap = portbitmap | ig_md.portbitmap;
        }
    };
    RegisterAction<bit<16>, bit<17>, bit<16>>(reg_table_portmap1) Portmap1CheckAndClean = {
        void apply(inout bit<16> portbitmap, out bit<16> result) {
            result = portbitmap;
            portbitmap = 0;
        }
    };

    /* PIT Register Group 2 */
    Register<bit<8>, bit<17>>(PCCT_REG_SIZE) reg_table_time2;
    RegisterAction<bit<8>, bit<17>, bit<1>>(reg_table_time2) Time2Check = {
        void apply(inout bit<8> tstamp, out bit<1> isExpire) {
            isExpire = PIT_NOT_EXPIRE;
            if (tstamp != ig_prsr_md.global_tstamp[39:32]) {
                isExpire = PIT_EXPIRE;
                tstamp = ig_prsr_md.global_tstamp[39:32];
            }
        }
    };

    Register<bit<16>, bit<17>>(PCCT_REG_SIZE) reg_table_finger2;
    RegisterAction<bit<16>, bit<17>, bit<8>>(reg_table_finger2)Finger2AddAndUpdateEntry = {
        void apply(inout bit<16> fingerprint, out bit<8> pitflag) {
            pitflag = PCCT_OPR_NONE;
            if (fingerprint == 0 || ig_md.isExpire2 == PIT_EXPIRE) {
                fingerprint = ig_md.fingerprint;
                pitflag = PCCT_OPR_NEW;
            } else if (fingerprint == ig_md.fingerprint) {
                pitflag = PCCT_OPR_UPDATE;
            }
        }
    };
    RegisterAction<bit<16>, bit<17>, bit<8>>(reg_table_finger2)Finger2OnlyCheckEntry = {
        void apply(inout bit<16> fingerprint, out bit<8> pitflag) {
            if (fingerprint == ig_md.fingerprint) {
                pitflag = PCCT_OPR_UPDATE;
            } else {
                pitflag = PCCT_OPR_NEW;
            }
        }
    };
    RegisterAction<bit<16>, bit<17>, bit<1>>(reg_table_finger2) Finger2CheckAndClean = {
        void apply(inout bit<16> fingerprint, out bit<1> pitflag) {
            pitflag = LOOKUP_MISS;
            if (fingerprint == ig_md.fingerprint) {
                pitflag = LOOKUP_HIT;
                fingerprint = 0;
            }
        }
    };
    
    Register<bit<16>, bit<17>>(PCCT_REG_SIZE) reg_table_portmap2;
    RegisterAction<bit<16>, bit<17>, void>(reg_table_portmap2) Portmap2AddAndUpdateEntry = {
        void apply(inout bit<16> portbitmap) {
            portbitmap = portbitmap | ig_md.portbitmap;
        }
    };
    RegisterAction<bit<16>, bit<17>, bit<16>>(reg_table_portmap2) Portmap2CheckAndClean = {
        void apply(inout bit<16> portbitmap, out bit<16> result) {
            result = portbitmap;
            portbitmap = 0;
        }
    };

    /* Hash for Index */
    action NdnNameHashProcess() {
        bit<32> namehashkey = name_hash_key.get({hdr.name1_part1.name, hdr.name1_part2.name, hdr.name1_part4.name, hdr.name1_part8.name,
                                                 hdr.name2_part1.name, hdr.name2_part2.name, hdr.name2_part4.name,
                                                 hdr.name3_part1.name, hdr.name3_part2.name, hdr.name3_part4.name, hdr.name3_part8.name,
                                                 hdr.name4_part1.name, hdr.name4_part2.name, hdr.name4_part4.name, hdr.name4_part8.name,
                                                 hdr.name5_part1.name, hdr.name5_part2.name, hdr.name5_part4.name, hdr.name5_part8.name, hdr.name5_part16.name,
                                                 hdr.name6_part1.name, hdr.name6_part2.name, hdr.name6_part4.name, hdr.name6_part8.name, hdr.name6_part16.name});
#if __TARGET_TOFINO__ == 2
        ig_md.nameIndex = namehashkey[31:15];   // 17 bits
#else
        ig_md.nameIndex = namehashkey[31:14];
#endif
    }

    /* Hash for Fingerprint */
    action NdnNameSigHashProcess() {
        ig_md.fingerprint = name_sig_hash.get({ hdr.name1_part1.name, hdr.name1_part2.name, hdr.name1_part4.name, hdr.name1_part8.name,
                                                hdr.name2_part1.name, hdr.name2_part2.name, hdr.name2_part4.name,
                                                hdr.name3_part1.name, hdr.name3_part2.name, hdr.name3_part4.name, hdr.name3_part8.name,
                                                hdr.name4_part1.name, hdr.name4_part2.name, hdr.name4_part4.name, hdr.name4_part8.name,
                                                hdr.name5_part1.name, hdr.name5_part2.name, hdr.name5_part4.name, hdr.name5_part8.name, hdr.name5_part16.name,
                                                hdr.name6_part1.name, hdr.name6_part2.name, hdr.name6_part4.name, hdr.name6_part8.name, hdr.name6_part16.name});
    }

    action NdnToServerMacHash() {
        serverhash = server_hash.get({hdr.ethernet.dstAddr, hdr.ethernet.srcAddr});
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* Set by Control Plane */
    action SetPortBitmap(bit<16> bitmap) {
        ig_md.portbitmap = bitmap;
    }
    table NdnPortBitmap {
        actions = {
            SetPortBitmap;
        }
        key = {
            ig_md.inPort: exact;
        }
        size = PORT_BITMAP_TBL_SIZE;
    }

    action SetToServerOutputPort(bit<9> outport) {
        ig_tm_md.ucast_egress_port = outport;
    }
    table NdnToServerTbl {
        key = {
            ig_md.serverindex : exact;
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            SetToServerOutputPort;
            drop;
        }
        default_action = drop;
        size = TO_SERVER_TABLE_SIZE;
    }

    /* Packet Category Table */
    action InterestNotDirectToServer() {
        ig_md.pcctAction = PCCT_ADD_MOD;
        ig_md.firstDir = UNICAST_TO_SERVER;
        ig_md.inPort = ig_intr_md.ingress_port;
    }
    action InterestDirectToServer() {
        ig_md.firstDir = UNICAST_TO_SERVER;
        ig_md.inPort = ig_intr_md.ingress_port;
    }
    action DataNotDirectToServer() {
        ig_md.firstDir = MULTICAST_TO_REMOTE;
        ig_md.pcctAction = PCCT_READ_CLEAN;
        ig_md.inPort = ig_intr_md.ingress_port;
    }
    action DataDirectToServer() {
        ig_md.firstDir = UNICAST_TO_SERVER;
        ig_md.inPort = ig_intr_md.ingress_port;
    }
    action InterestFromServer() {
        ig_md.inPort = (bit<9>)hdr.linkServer.inport;
        ig_md.remoteOutPort = (bit<9>)hdr.linkServer.outport;
        ig_md.pcctAction = hdr.linkServer.pcctflag;
        ig_md.firstDir = hdr.linkServer.sendDir;
    }
    action DataFromServer() {
        ig_md.inPort = (bit<9>)hdr.linkServer.inport;
        ig_md.remoteOutPort = (bit<9>)hdr.linkServer.outport;
        ig_md.firstDir = hdr.linkServer.sendDir;
    }
    table NdnNextActionTbl {
        key = {
            ig_md.isInvalid: exact;
            ig_md.fromServer: exact;
            ig_md.toServer: exact;
            hdr.ndnType_tl.tlv_type: exact;
        }
        actions = {
            InterestNotDirectToServer;
            InterestDirectToServer;
            DataNotDirectToServer;
            DataDirectToServer;
            InterestFromServer;
            DataFromServer;
            NoAction;
        }
        default_action = NoAction;
        size = FIRST_JUDGE_TABLE_SIZE;
        const entries = {
            (PACKET_VALID, NOT_FROM_SERVER, NOT_DIRECT_TO_SERVER, NDNTYPE_INTEREST) : InterestNotDirectToServer();
            (PACKET_VALID, NOT_FROM_SERVER, DIRECT_TO_SERVER,     NDNTYPE_INTEREST) : InterestDirectToServer();
            (PACKET_VALID, NOT_FROM_SERVER, NOT_DIRECT_TO_SERVER, NDNTYPE_DATA)     : DataNotDirectToServer();
            (PACKET_VALID, NOT_FROM_SERVER, DIRECT_TO_SERVER,     NDNTYPE_DATA)     : DataDirectToServer();
            (PACKET_VALID, FROM_SERVER,     NOT_DIRECT_TO_SERVER, NDNTYPE_INTEREST) : InterestFromServer();
            (PACKET_VALID, FROM_SERVER,     DIRECT_TO_SERVER,     NDNTYPE_INTEREST) : InterestFromServer();
            (PACKET_VALID, FROM_SERVER,     NOT_DIRECT_TO_SERVER, NDNTYPE_DATA)     : DataFromServer();
            (PACKET_VALID, FROM_SERVER,     DIRECT_TO_SERVER,     NDNTYPE_DATA)     : DataFromServer();
        }
    }

    /* Forwarding Action Table */
    action SetFinalStop() {
        ig_md.finalDir = PACKET_DROP;
    }
    action SetFinalUnicastToServer() {
        ig_md.finalDir = UNICAST_TO_SERVER;
    }
    action SetFinalUnicastToRemote() {
        ig_md.finalDir = UNICAST_TO_REMOTE;
    }
    action SetFinalMulticastToRemote() {
        ig_md.finalDir = MULTICAST_TO_REMOTE;
    }
    table NdnPacketFinalTbl {
        key = {
            ig_md.firstDir: exact;      
            ig_md.hasFinger1 : exact;   
            ig_md.hasFinger2 : exact;  
            ig_md.pcctFlag : exact;    
        }
        actions = {
            SetFinalStop;
            SetFinalUnicastToServer;
            SetFinalUnicastToRemote;
            SetFinalMulticastToRemote;
            NoAction;
        }
        default_action = NoAction;
        size = FINAL_JUDGE_TABLE_SIZE;
        const entries = {
            (PACKET_DROP,         LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_NONE)   : SetFinalStop();            
            (PACKET_DROP,         LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_NEW)    : SetFinalStop();
            (PACKET_DROP,         LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_UPDATE) : SetFinalStop();
            (PACKET_DROP,         LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_NONE)   : SetFinalStop();
            (PACKET_DROP,         LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_NEW)    : SetFinalStop();
            (PACKET_DROP,         LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_UPDATE) : SetFinalStop();
            (PACKET_DROP,         LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_NONE)   : SetFinalStop();
            (PACKET_DROP,         LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_NEW)    : SetFinalStop();
            (PACKET_DROP,         LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_UPDATE) : SetFinalStop();
            (PACKET_DROP,         LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_NONE)   : SetFinalStop();
            (PACKET_DROP,         LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_NEW)    : SetFinalStop();
            (PACKET_DROP,         LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_UPDATE) : SetFinalStop();
            (UNICAST_TO_SERVER,   LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_NONE)   : SetFinalUnicastToServer();   // UEI
            (UNICAST_TO_SERVER,   LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_NEW)    : SetFinalUnicastToServer();   // PEI
            (UNICAST_TO_SERVER,   LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_UPDATE) : SetFinalStop();              // Interets already registered
            (UNICAST_TO_SERVER,   LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_NONE)   : SetFinalUnicastToServer();   
            (UNICAST_TO_SERVER,   LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_NEW)    : SetFinalUnicastToServer();   
            (UNICAST_TO_SERVER,   LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_UPDATE) : SetFinalStop();              
            (UNICAST_TO_SERVER,   LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_NONE)   : SetFinalUnicastToServer();   
            (UNICAST_TO_SERVER,   LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_NEW)    : SetFinalUnicastToServer();   
            (UNICAST_TO_SERVER,   LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_UPDATE) : SetFinalStop();             
            (UNICAST_TO_SERVER,   LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_NONE)   : SetFinalUnicastToServer();   
            (UNICAST_TO_SERVER,   LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_NEW)    : SetFinalUnicastToServer();   
            (UNICAST_TO_SERVER,   LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_UPDATE) : SetFinalStop();             
            (UNICAST_TO_REMOTE,   LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_NONE  ) : SetFinalUnicastToRemote();   // InI
            (UNICAST_TO_REMOTE,   LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_NEW   ) : SetFinalUnicastToRemote();
            (UNICAST_TO_REMOTE,   LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_UPDATE) : SetFinalUnicastToRemote();
            (UNICAST_TO_REMOTE,   LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_NONE  ) : SetFinalUnicastToRemote();   
            (UNICAST_TO_REMOTE,   LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_NEW   ) : SetFinalUnicastToRemote();
            (UNICAST_TO_REMOTE,   LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_UPDATE) : SetFinalUnicastToRemote();
            (UNICAST_TO_REMOTE,   LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_NONE  ) : SetFinalUnicastToRemote();   
            (UNICAST_TO_REMOTE,   LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_NEW   ) : SetFinalUnicastToRemote();
            (UNICAST_TO_REMOTE,   LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_UPDATE) : SetFinalUnicastToRemote();
            (UNICAST_TO_REMOTE,   LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_NONE  ) : SetFinalUnicastToRemote();   
            (UNICAST_TO_REMOTE,   LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_NEW   ) : SetFinalUnicastToRemote();
            (UNICAST_TO_REMOTE,   LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_UPDATE) : SetFinalUnicastToRemote();
            (MULTICAST_TO_REMOTE, LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_NONE  ) : SetFinalUnicastToServer();   // UED
            (MULTICAST_TO_REMOTE, LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_NEW   ) : SetFinalUnicastToServer();
            // (MULTICAST_TO_REMOTE, LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_UPDATE) : SetFinalStop();           
            (MULTICAST_TO_REMOTE, LOOKUP_MISS, LOOKUP_MISS, PCCT_OPR_UPDATE) : SetFinalMulticastToRemote(); // NACK
            (MULTICAST_TO_REMOTE, LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_NONE  ) : SetFinalMulticastToRemote(); // PED
            (MULTICAST_TO_REMOTE, LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_NEW   ) : SetFinalMulticastToRemote();
            (MULTICAST_TO_REMOTE, LOOKUP_MISS, LOOKUP_HIT,  PCCT_OPR_UPDATE) : SetFinalMulticastToRemote();
            (MULTICAST_TO_REMOTE, LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_NONE  ) : SetFinalMulticastToRemote(); // PED
            (MULTICAST_TO_REMOTE, LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_NEW   ) : SetFinalMulticastToRemote();
            (MULTICAST_TO_REMOTE, LOOKUP_HIT,  LOOKUP_MISS, PCCT_OPR_UPDATE) : SetFinalMulticastToRemote();
            (MULTICAST_TO_REMOTE, LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_NONE  ) : SetFinalMulticastToRemote(); // PED
            (MULTICAST_TO_REMOTE, LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_NEW   ) : SetFinalMulticastToRemote();
            (MULTICAST_TO_REMOTE, LOOKUP_HIT,  LOOKUP_HIT,  PCCT_OPR_UPDATE) : SetFinalMulticastToRemote();
        }
    }
    action SetToServerPool0() {
        ig_md.serverindex = INVALID_SERVER_INDEX;
    }
    action SetToServerPool1() {
        ig_md.serverindex = 0;
    }
    action SetToServerPool2() {
        ig_md.serverindex[0:0] = serverhash[0:0];
    }
    action SetToServerPool4() {
        ig_md.serverindex[1:0] = serverhash[1:0];
    }
    action SetToServerPool8() {
        ig_md.serverindex[2:0] = serverhash[2:0];
    }
    action SetToServerPool16() {
        ig_md.serverindex[3:0] = serverhash[3:0];
    }
    action SetToServerPool32() {
        ig_md.serverindex[4:0] = serverhash[4:0];
    }
    action SetToServerPool64() {
        ig_md.serverindex[5:0] = serverhash[5:0];
    }
    action SetToServerPool128() {
        ig_md.serverindex[6:0] = serverhash[6:0];
    }
    table NdnServerPoolTbl {
        actions = {
            SetToServerPool0;
            SetToServerPool1;
            SetToServerPool2;
            SetToServerPool4;
            SetToServerPool8;
            SetToServerPool16;
            SetToServerPool32;
            SetToServerPool64;
            SetToServerPool128;
            NoAction;
        }
        key = {
            ig_md.servernum: exact;
        }
        default_action = NoAction;
        size = SERVER_POOL_TBL_SIZE;
        const entries = {
            0   : SetToServerPool0();
            1   : SetToServerPool1();
            2   : SetToServerPool2();
            4   : SetToServerPool4();
            8   : SetToServerPool8();
            16  : SetToServerPool16();
            32  : SetToServerPool32();
            64  : SetToServerPool64();
            128 : SetToServerPool128();
        }
    }

    /* Inner MAC Table */
    action MacTransForFastData() {
        hdr.ethernet.dstAddr = SERVER2_NIC2_1;
        hdr.ethernet.srcAddr = SERVER1_NIC2_1;
    }

    table InnerMacTable {
        key = {
            hdr.ethernet.dstAddr :   exact;
            hdr.ethernet.srcAddr :   exact;
        }
        actions = {
            MacTransForFastData;
            NoAction;
        }

        const default_action = NoAction;
        size = 8;
        const entries = {
            (SERVER1_NIC2_2 ,SERVER2_NIC2_2)    :   MacTransForFastData();
        }
    }

    apply {
        /* Hash for Index */
        NdnNameHashProcess();
        /* Hash for Fingerprint */
        NdnNameSigHashProcess();
        /* Hash for Server MAC */
        NdnToServerMacHash();

        /* server number */
        ig_md.servernum = ServerNumberRead.execute(0);
        /* Packer Category Table */
        NdnNextActionTbl.apply();

        /* Interest */
        if (ig_md.pcctAction == PCCT_ADD_MOD) {
            /* Get the inPort bitmap */
            NdnPortBitmap.apply();
            /* PIT Register Group 1 */
            ig_md.isExpire1 = Time1Check.execute(ig_md.nameIndex);
            ig_md.pcctFlag = Finger1AddAndUpdateEntry.execute(ig_md.nameIndex);
            
            if (ig_md.pcctFlag != PCCT_OPR_NONE) {
                Portmap1AddAndUpdateEntry.execute(ig_md.nameIndex);
                if (ig_md.pcctFlag == PCCT_OPR_NEW) {
                    ig_md.pcctFlag = Finger2OnlyCheckEntry.execute(ig_md.nameIndex);
                }
            } else {
            /* PIT Register Group 2 */
                ig_md.isExpire2 = Time2Check.execute(ig_md.nameIndex);
                ig_md.pcctFlag = Finger2AddAndUpdateEntry.execute(ig_md.nameIndex);
                if (ig_md.pcctFlag != PCCT_OPR_NONE) {
                    Portmap2AddAndUpdateEntry.execute(ig_md.nameIndex);
                }
            }
        /* Data or NACK */
        } else if (ig_md.pcctAction == PCCT_READ_CLEAN) {
            bit<16> portmap1 = 0;
            bit<16> portmap2 = 0;
            ig_md.hasFinger1 = Finger1CheckAndClean.execute(ig_md.nameIndex);
            if (ig_md.hasFinger1 == LOOKUP_HIT) {
                portmap1 = Portmap1CheckAndClean.execute(ig_md.nameIndex);
                // Time1Clean.execute(ig_md.nameIndex);
            }
            ig_md.hasFinger2 = Finger2CheckAndClean.execute(ig_md.nameIndex);
            if (ig_md.hasFinger2 == LOOKUP_HIT) {
                portmap2 = Portmap2CheckAndClean.execute(ig_md.nameIndex);
                // Time2Clean.execute(ig_md.nameIndex);
            }
            ig_md.outGroup = portmap1 | portmap2;
            /* NACK */         
            if (ig_md.isNack == 1) {
                ig_md.hasFinger1 = LOOKUP_MISS;
                ig_md.hasFinger2 = LOOKUP_MISS;
                ig_md.pcctFlag = PCCT_OPR_UPDATE;
            }
        }

        /* Forwarding Action Table */
        NdnPacketFinalTbl.apply();
        
        /* UtoS: Unicast to Internal Server */
        if (ig_md.finalDir == UNICAST_TO_SERVER) {
            NdnServerPoolTbl.apply();
            hdr.linkServer.setValid();
            hdr.linkServer.tlv_type = NDNTYPE_TO_SERVER;
            hdr.linkServer.tlv_length = 6;
            hdr.linkServer.pcctflag = ig_md.pcctFlag;
            hdr.linkServer.sendDir = 0;
            hdr.linkServer.inport = (bit<16>)ig_intr_md.ingress_port;
            hdr.linkServer.outport = 0;
            NdnToServerTbl.apply(); // set outPort based on DstMAC
            ig_tm_md.bypass_egress = 1; 
        } 
        /* UtoE: Unicast to External */
        else if (ig_md.finalDir == UNICAST_TO_REMOTE) {
            ig_tm_md.ucast_egress_port = ig_md.remoteOutPort;
            hdr.linkServer.setInvalid();
            ig_tm_md.bypass_egress = 1;
        } 
        /* MtoE: Multicast to External */
        else if (ig_md.finalDir == MULTICAST_TO_REMOTE) {
            InnerMacTable.apply();
            hdr.linkServer.setInvalid();
            ig_tm_md.mcast_grp_a = ig_md.outGroup;
            ig_tm_md.bypass_egress = 1;
        } 
        /* Drop */
        else {
            drop();
        }
    }
}

/*********************************************************************
    Egress Parser
 * *******************************************************************/
parser SwitchEgressParser(packet_in packet,
    out NdnEgressHeader_t hdr,
    out ndn_egress_metadata_t meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        packet.extract(eg_intr_md);
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

/*********************************************************************
    Egress
 * *******************************************************************/
control SwitchEgress(
    inout NdnEgressHeader_t hdr,
    inout ndn_egress_metadata_t meta,
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
        //hdr.ethernet.dstAddr[17:0] = eg_intr_md.enq_tstamp;
        //hdr.ethernet.srcAddr[17:0] = eg_intr_md.deq_timedelta;
        //hdr.ethernet.srcAddr = eg_prsr_md.global_tstamp;
    }
}

/*********************************************************************
    Egress Deparser
 * *******************************************************************/
control SwitchEgressDeparser(packet_out packet,
    inout NdnEgressHeader_t                         hdr,
    in    ndn_egress_metadata_t                     meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        packet.emit(hdr);
    }
}
/*********************************************************************
    Pipeline
 * *******************************************************************/
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
