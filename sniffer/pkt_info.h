#ifndef PKT_INFO_H
#define PKT_INFO_H

#include <cstdint>
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

    unsigned long        pkt_num;
    char                 timestr[64];
    char                 src[32];
    char                 dst[32];
    uint32_t             size;
    //whole packet data
    std::vector<uint8_t> data;
    //Layer I
    layer_i_t            LayerI;
    //LayerII
    layer_ii_t           LayerII;
    //LayerIII
    layer_iii_t          LayerIII;
    //layerIV
    layer_iv_t           LayerIV;
    //layerVII
    layer_vii_t          LayerVII;

};

#endif // PKT_INFO_H
