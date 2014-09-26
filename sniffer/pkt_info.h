#ifndef PKT_INFO_H
#define PKT_INFO_H

#include <cstdint>
#include <cstring>
#include <vector>

//layer i - frame
typedef union {
    struct {
        uint32_t size;
    } Frame;
} layer_i_t;

//layer ii - ethernet ii
typedef union {
    struct {
        //data range
        uint32_t    eii_data_offset;
        uint32_t    eii_data_len;
        //protocol format
        char        eii_dst_addr[32];
        char        eii_src_addr[32];
        uint32_t    eii_header_size;
        uint32_t    eii_trailer_size;
        uint16_t    eii_type;
        } EthernetII;
} layer_ii_t;

//layer iii - ARP, IPV4
typedef union {
    struct {
        //data range
        uint32_t    arp_data_offset;
        uint32_t    arp_data_len;
        //protocol format
        uint16_t    arp_hw_type;
        uint16_t    arp_prot_type;
        uint8_t     arp_hw_len;
        uint8_t     arp_prot_len;
        uint16_t    arp_opcode;
        char        arp_sender_hw_addr[32];
        char        arp_sender_ip_addr[16];
        char        arp_target_hw_addr[32];
        char        arp_target_ip_addr[16];
    } ARP;
    struct {
        //data range
        uint32_t    ip_data_offset;
        uint32_t    ip_data_len;
        //protocol format
        uint8_t     ip_version;//4-bits
        uint8_t     ip_header_size;//4-bits
        uint8_t     ip_tos;
        uint16_t    ip_total_len;
        uint16_t    ip_id;
        uint8_t     ip_frag_flags;//3-bits, always 010b
        uint16_t    ip_frag_offset;//13-bits, always 0000000000000b
        uint8_t     ip_ttl;
        uint8_t     ip_protocol;
        uint16_t    ip_header_checksum;
        char        ip_src_addr[16];
        char        ip_dst_addr[16];
        /* options field to be added */
    } IPv4;

} layer_iii_t;

//layer iv - tcp, udp
typedef union {
    struct {
        //data range
        uint32_t    tcp_data_offset;
        uint32_t    tcp_data_len;
        //protocol format
        uint16_t    tcp_sport;
        uint16_t    tcp_dport;
        uint32_t    tcp_seq;
        uint32_t    tcp_ack_seq;
        uint8_t     tcp_header_len;//4-bits, aka data offset
        /*uint8_t     tcp_reserved;*///4-bits
        bool        tcp_flags_cwr;
        bool        tcp_flags_ece;
        bool        tcp_flags_urg;
        bool        tcp_flags_ack;
        bool        tcp_flags_psh;
        bool        tcp_flags_rst;
        bool        tcp_flags_syn;
        bool        tcp_flags_fin;
        uint16_t    tcp_window_size;
        uint16_t    tcp_checksum;
        uint16_t    tcp_urg_ptr;
        /* options field to be added */
    } TCP;
    struct {
        //data range
        uint32_t    udp_data_offset;
        uint32_t    udp_data_len;
        //protocol format
        uint16_t    udp_sport;
        uint16_t    udp_dport;
        uint16_t    udp_len;
        uint16_t    udp_checksum;
    } UDP;
} layer_iv_t;

//layer vii - http, ftp, telnet, dns, ...
typedef union {
    struct {

    } HTTP;
    struct {

    } FTP;
    struct {

    } TELNET;
    struct {

    } DNS;
} layer_vii_t;


struct pkt_info_t {

    enum layer_ii_type {
        EthernetII
    };

    enum layer_iii_type {
        ARP,
        IP
    };
    enum layer_iv_type {
        TCP,
        UDP
    };
    enum layer_vii_type {
        HTTP,
        FTP,
        TELNET,
        DNS
    };
    char                 timestr[64];
    char                 src[32];
    char                 dst[32];
    char                 protocol[16];
    uint32_t             size;
    uint8_t              max_layer;
    //whole packet data
    std::vector<uint8_t> data;
    //Layer I
    layer_i_t            LayerI;
    //LayerII
    enum layer_ii_type   LayerIIType;
    layer_ii_t           LayerII;
    //LayerIII
    enum layer_iii_type  LayerIIIType;
    layer_iii_t          LayerIII;
    //LayerIV
    enum layer_iv_type   LayerIVType;
    layer_iv_t           LayerIV;
    //LayerVII
    enum layer_vii_type  LayerVIIType;
    layer_vii_t          LayerVII;
};

typedef struct pkt_info_t pkt_info_t;

#define PKT_INFO_SET_TIMESTR(_pi, _ts) \
    do { \
        strncpy((_pi)->timestr, (_ts), 63); \
        (_pi)->timestr[63] = '\0'; \
    } while(0)
#define PKT_INFO_SET_SRC(_pi, _src) \
    do { \
        strncpy((_pi)->src, (_src), 31); \
        (_pi)->src[31] = '\0'; \
    } while(0)
#define PKT_INFO_SET_DST(_pi, _dst) \
    do { \
        strncpy((_pi)->dst, (_dst), 31); \
        (_pi)->dst[31] = '\0'; \
    } while(0)

#define PKT_INFO_SET_PROTOCOL(_pi, _prot) \
    do { \
        strncpy((_pi)->protocol, (_prot), 15); \
        (_pi)->protocol[15] = '\0'; \
    } while(0)
#define PKT_INFO_SET_SIZE(_pi, _size) \
    do { \
        (_pi)->size = (_size); \
    } while (0)
#define PKT_INFO_SET_MAX_LAYER(_pi, _max_layer) \
    do { \
        (_pi)->max_layer = (_max_layer); \
    } while (0)
#define PKT_INFO_SET_DATA(_pi, _data) \
    do { \
        (_pi)->data = std::move((_data)); \
    } while (0)


#endif // PKT_INFO_H
