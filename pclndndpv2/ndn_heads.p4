/***************************************************************
 * Name:      ndn_heads.p4
 * Purpose:   Definitions of NDN headers
 **************************************************************/
#ifndef _NDN_HEADERS_
#define _NDN_HEADERS_

/* NDN packet type */
#define ETHERTYPE_NDN          0x8624
/* TLV length encoding */
#define ENCODING_1BYTE         0xFC
#define ENCODING_2BYTE         0xFD
#define ENCODING_4BYTE         0xFE
#define ENCODING_8BYTE         0xFF
/* NDN headers */
#define NDNTYPE_INTEREST       0x05
#define NDNTYPE_DATA           0x06
#define NDNTYPE_NAME           0x07
#define NDNTYPE_COMPONENT      0x08
#define NDNTYPE_IS2            0x01
#define NDNTYPE_SEL            0x09
#define NDNTYPE_NON            0x0a
#define NDNTYPE_LIF            0x0c
#define NDNTYPE_MTI            0x14
#define NDNTYPE_MIN            0x0d
#define NDNTYPE_MAX            0x0e
#define NDNTYPE_PKL            0x0f
#define NDNTYPE_EXC            0x10
#define NDNTYPE_CHS            0x11
#define NDNTYPE_MBF            0x12
#define NDNTYPE_DIG            0x1d
#define NDNTYPE_ANY            0x13
#define NDNTYPE_CNT            0x18
#define NDNTYPE_FRP            0x19
#define NDNTYPE_FBI            0x1a
#define NDNTYPE_CON            0x15
#define NDNTYPE_KYL            0x1c
#define NDNTYPE_SIG            0x16
#define NDNTYPE_SGV            0x17
#define NDNTYPE_SEGMENT        0x32
#define NDNTYPE_VERSION        0x36
#define NDNTYPE_TO_SERVER      0x70
#define NDNTYPE_FROM_SERVER    0x71
/* NDNLPv2 headers */
#define TtLpPacket  0x64
#define TtPitToken  0x62
#define TtFragment  0x50

/* PIT Lookup flags */
#define LOOKUP_MISS 0
#define LOOKUP_HIT 1
/* packet source */
#define NOT_FROM_SERVER 0
#define FROM_SERVER 1
/* packet validity */
#define PACKET_VALID 0
#define PACKET_INVALID 1
/* flags indicate whether to send directly to backend servers */
#define NOT_DIRECT_TO_SERVER 0
#define DIRECT_TO_SERVER 1
/* packet sending directions */
#define PACKET_DROP 0
#define UNICAST_TO_SERVER 1
#define UNICAST_TO_REMOTE 2
#define MULTICAST_TO_REMOTE 3
/* flags indicate PCCT operation */
#define PCCT_IDLE 0
#define PCCT_ADD_MOD 1
#define PCCT_READ_CLEAN 2
/* flags indicate PCCT operation result  */
#define PCCT_OPR_NONE 0     // no opration
#define PCCT_OPR_NEW 1      // insert new entry
#define PCCT_OPR_UPDATE 2   // update old entry
/* PIT expiration */
#define PIT_NOT_EXPIRE 0
#define PIT_EXPIRE 1
/* PCCT size */
#if __TARGET_TOFINO__ == 2
#define PCCT_REG_SIZE 131072    // 2^17 for Tofino2
typedef bit<17> PcctIndex;
typedef bit<7> PcctRsvd;
#else
#define PCCT_REG_SIZE 262144    // 2^18 for Tofino1
typedef bit<18> PcctIndex;
typedef bit<6> PcctRsvd;
#endif
/* port bitmap table size */
#define PORT_BITMAP_TBL_SIZE 64
/* backend servers MAC table size */
#define TO_SERVER_TABLE_SIZE 256
/* PCT size */
#define FIRST_JUDGE_TABLE_SIZE 32
/* FAT size */
#define FINAL_JUDGE_TABLE_SIZE 64
/* server pool table size */
#define SERVER_POOL_TBL_SIZE 256
#define INVALID_SERVER_INDEX 255
/* switch port device id */
#define SWITCH_PORT_03 152
#define SWITCH_PORT_04 160
#define SWITCH_PORT_05 168
#define SWITCH_PORT_06 176
/* backend server adapter interface MAC */
#define SERVER1_NIC2_1 0x0c42a13a6768
#define SERVER1_NIC2_2 0x0c42a13a6769
/* external server adapter interface MAC */
#define SERVER2_NIC2_1 0x1070fd31f3bc
#define SERVER2_NIC2_2 0x1070fd31f3bd


/* Ether header */
typedef bit<48> macAddr_t;
header Ethernet_h {
    macAddr_t dstAddr;   /* destination MAC */
    macAddr_t srcAddr;   /* source MAC */
    bit<16>   etherType; /* ether type */
}

/* SwitchInfo header */
header NdnFromToServer {
    bit<8> tlv_type;   /* 0x70 or 0x71 */
    bit<8> tlv_length; /* length of header */
    bit<8> pcctflag;   /* notification flag */
    bit<8> sendDir;    /* send direction */
    bit<16> inport;    /* inport of switch */
    bit<16> outport;   /* outport of switch */
}

/* tlv definitions */
header NdnTLBase {
    bit<8> tlv_type;        /* tlv type */
    bit<8> tlv_len_code;    /* tlv length */
}
header fdNameLength {
    bit<16> tlv_length;    /* The length encoded by FD is represented by 2 bytes. */
}
header NdnFdTLBase {
    bit<8>  fd_encode;        /* FD encode */
    bit<16> fd_type;          /* FD encode type */
    bit<8>  fd_len_code;      /* length */
}

/* Contents */
/* 1-byte content */
header DataOneByte {
    bit<8> name;
}
/* 2-byte content */
header DataTwoByte {
    bit<16> name;
}
/* 4-byte content */
header DataFourByte {
    bit<32> name;
}
/* 8-byte content */
header DataEightByte {
    bit<64> name;
}
/* 16-byte content */
header DataSixteenByte {
    bit<128> name;
}

// header tmp {
//     bit<8> pcctFlag_1;
//     bit<8> pcctFlag_2;
//     bit<8> pcctFlag_3;
//     bit<8> pcctFlag_4;
//     bit<8> pcctFlag_5;
//     bit<8> pcctFlag_6;
//     bit<8> pcctFlag_7;
//     bit<8> pcctFlag_8;
// }

/* NDN header */
struct NdnHeader_t {
    /* Ether header */
    Ethernet_h     ethernet;

    /* SwitchInfo */
    NdnFromToServer linkServer;

    /* LpPacket Header */
    NdnTLBase lpPacket_tl;
    fdNameLength lpPacket_fd_len;
    // /* Sequence */
    // NdnTLBase sequence_tl;
    // DataEightByte sequence;
    // /* FragIndex */
    // NdnTLBase fragIndex_tl;
    // DataOneByte fragIndex;
    // /* FragCount */
    // NdnTLBase fragCount_tl;
    // DataOneByte fragCount;
    /* PitToken */
    NdnTLBase pitToken_tl;
    DataOneByte token_oneByte;
    DataTwoByte token_twoByte;
    DataFourByte token_fourByte;
    DataEightByte token_eightByte;
    /* NACK */
    NdnFdTLBase nack_tl;
    DataFourByte nack;
    DataOneByte nackReason;
    /* Fragment Header */
    NdnTLBase fragment_tl;
    fdNameLength fragment_fd_len;
    /* NDN type: Interest or Data */
    NdnTLBase ndnType_tl;
    fdNameLength ndnType_fd_len;
    /* Name TL header */
    NdnTLBase ndnName_tl;

    // Optimal: 9/4/10/8/16/19
    /* Name component 1 */
    NdnTLBase name1_tl;
    DataOneByte name1_part1;
    DataTwoByte name1_part2;
    DataFourByte name1_part4;
    DataEightByte name1_part8;
    /* Name component 2 */
    NdnTLBase name2_tl;
    DataOneByte name2_part1;
    DataTwoByte name2_part2;
    DataFourByte name2_part4;
    // DataEightByte name2_part8;
    /* Name component 3 */
    NdnTLBase name3_tl;
    DataOneByte name3_part1;
    DataTwoByte name3_part2;
    DataFourByte name3_part4;
    DataEightByte name3_part8;
    /* Name component 4 */
    NdnTLBase name4_tl;
    DataOneByte name4_part1;
    DataTwoByte name4_part2;
    DataFourByte name4_part4;
    DataEightByte name4_part8;
    /* Name component 5 */
    NdnTLBase name5_tl;
    DataOneByte name5_part1;
    DataTwoByte name5_part2;
    DataFourByte name5_part4;
    DataEightByte name5_part8;
    DataSixteenByte name5_part16;
    /* Name component 6 */
    NdnTLBase name6_tl;
    DataOneByte name6_part1;
    DataTwoByte name6_part2;
    DataFourByte name6_part4;
    DataEightByte name6_part8;
    DataSixteenByte name6_part16;

    // /* Guide Info */
    // NdnTLBase canbeprefix_info_tl;
    // NdnTLBase mustbefresh_info_tl;
    // NdnTLBase nonce_tl;
    // DataFourByte nonce;
    // NdnTLBase lifetime_tl;
    // DataOneByte lifetime_oneByte;
    // DataTwoByte lifetime_twoByte;

    // /* Debug Info */
    // tmp pcctFlags;
}

/* NDN header for egress */
struct NdnEgressHeader_t {
    Ethernet_h     ethernet;
}

/* Metadata */
struct metadata_t {
    bit<1> isInvalid;       /* is NDN packet */
    bit<1> fromServer;      /* is from backend server */
    bit<1> toServer;        /* is directly send to backend server */
    bit<1> hasFinger1;      /* is hit on 1st PIT register group */
    bit<1> hasFinger2;      /* is hit on 2nd PIT register group */
    bit<1> isExpire1;       /* is entry on 1st PIT group expire */
    bit<1> isExpire2;       /* is entry on 2nd PIT group expire  */
    bit<1> isNack;          /* is NACK */
    // bit<1> _pad1;           /* Reserve for alignment */
    bit<8> pcctAction;      /* pcct action flags */
    bit<8> pcctFlag;        /* pcct result flags */
    bit<8> firstDir;        /* result of PCT */
    bit<8> finalDir;        /* result of FAT */
    bit<8> servernum;       /* number of backend servers */
    bit<8> serverindex;     /* server index in server pool */
    bit<16> portbitmap;     /* bitmap of inport */
    bit<16> fingerprint;    /* name hash for fingerprint */
    bit<16> outGroup;       /* multicast group id */
    PortId_t inPort;        /* packet inport */
    PortId_t remoteOutPort; /* unicast outport */
    bit<6> _pad2;           /* Reserve for alignment */
    PcctIndex nameIndex;
    PcctRsvd _pad3;
}
/* egress does not use metadata */
struct ndn_egress_metadata_t {

}

#endif