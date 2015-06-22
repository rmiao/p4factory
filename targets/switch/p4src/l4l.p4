xo/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define L4L_CONN_TABLE_SIZE                    65536
#define VIP_TABLE_SIZE                         4096
#define DIP_POOL_TABLE_SIZE                    1024
#define DIP_TABLE_SIZE                         65536
#define L4L_HASH_BIT_WIDTH                         10


#define L4L_CONNECTION_LEARN_TYPE              4
#define L4L_WHITELIST_LEARN_TYPE               5
#define TCP_SEQNUM_WIDTH                       32

/*
 * L4L metadata
 */
 header_type l4l_metadata_t {
     fields {
            trusted : 1;                           /* flag indicating whether src is trusted */
            vip_traffic : 1;                       /* flag indicating VIP traffic */
            dippool_index : 10;                    /* dip-pool index */
            dippool_offset : 16;                   /* offset into the dippool table */
            new_addr : 32;                         /* new dst address, for l4l */
            new_port : 16;                         /* new dst port, for l4l */
            l4l_orig_da : 32;                      /* original dst address, for l4l */
            l4l_orig_dport : 16;                   /* original dst port, for l4l */
	    temp32b : 32;                         /* temporary variable needed because LG does serial processing of actions */
            temp16b : 16;                         /* temporary variable needed to swap port numbers */
     }
 }

metadata l4l_metadata_t l4l_metadata;



action on_whitelist() {
    modify_field(l4l_metadata.trusted, TRUE);  // TODO: change this to Bloomfilter
    
}

table src_whitelist {
    reads {
        ipv4_metadata.lkp_ipv4_sa : exact;
        //ingress_metadata.lkp_l4_sport : exact;
    }
    actions {
        on_miss;  // trusted = false on miss?
        on_whitelist;
    }
    size : 256;
    support_timeout : true;
}


action l4l_tcp_dnat(dip, port) {
    modify_field(ipv4_metadata.lkp_ipv4_da, dip);
    modify_field(ipv4.dstAddr, dip);
    modify_field(ingress_metadata.lkp_l4_dport, port);
    modify_field(tcp.dstPort, port);
}

action l4l_udp_dnat(dip, port) {
    modify_field(ipv4_metadata.lkp_ipv4_da, dip);
    modify_field(ipv4.dstAddr, dip);
    modify_field(ingress_metadata.lkp_l4_dport, port);
    modify_field(udp.dstPort, port);
}

action l4l_tcp_snat(dip, port) {
    modify_field(ipv4_metadata.lkp_ipv4_sa, dip);
    modify_field(ipv4.srcAddr, dip);
    modify_field(ingress_metadata.lkp_l4_sport, port);
    modify_field(tcp.srcPort, port);
}

action l4l_udp_snat(dip, port) {
    modify_field(ipv4_metadata.lkp_ipv4_sa, dip);
    modify_field(ipv4.srcAddr, dip);
    modify_field(ingress_metadata.lkp_l4_sport, port);
    modify_field(udp.srcPort, port);
}

table l4_connections {
    reads {
        l3_metadata.lkp_ip_proto : exact;
        ipv4_metadata.lkp_ipv4_sa : exact;
        ipv4_metadata.lkp_ipv4_da : exact;
        ingress_metadata.lkp_l4_sport : exact;
        ingress_metadata.lkp_l4_dport : exact;
    }
    actions {
        on_miss; // upon miss
        l4l_tcp_dnat;
        l4l_udp_dnat;
        l4l_tcp_snat;
        l4l_udp_snat;
    }
    size : L4L_CONN_TABLE_SIZE;
    support_timeout : true;
}    

action set_dippool_index(dippool_index) {
    modify_field(l4l_metadata.vip_traffic, TRUE);
    modify_field(l4l_metadata.dippool_index, dippool_index);
}

table vip {
    reads {
        ipv4_metadata.lkp_ipv4_da : exact;
        ingress_metadata.lkp_l4_dport : exact;
    }
    actions {
        nop; // upon miss
        set_dippool_index;
    }
    size : VIP_TABLE_SIZE;
}

field_list_calculation l4l_hash {
    input {
        conn_level_hash_fields;
    }
    algorithm : crc16;
    output_width : L4L_HASH_BIT_WIDTH;
}

// TODO: merge dip_pool and l4_rewrite_and_learn using action_profile

action select_dip(dippool_base, dippool_count) {
    // Note: Using the same hash as ECMP is fine
    modify_field_with_hash_based_offset(l4l_metadata.dippool_offset, dippool_base,
                                        l4l_hash, dippool_count); 
}

table dip_pool {
    reads {
        l4l_metadata.dippool_index : exact;
    }
    actions {
        on_miss; // upon miss
        select_dip;
    }
    size : DIP_POOL_TABLE_SIZE;
}

field_list l4l_learn_field {
    l4l_metadata.learn_type;
    l3_metadata.lkp_ip_proto;
    ipv4_metadata.lkp_ipv4_sa;
    l4l_metadata.l4l_orig_da;
    ingress_metadata.lkp_l4_sport;
    l4l_metadata.l4l_orig_dport;
    l4l_metadata.new_addr;
    l4l_metadata.new_port;
}

action l4l_tcp_nat_and_learn(dip, port) {
    // TODO: this action implementation assumes sequential execution semantics
    modify_field(l4l_metadata.learn_type, L4L_CONNECTION_LEARN_TYPE);
    modify_field(l4l_metadata.l4l_orig_da, ipv4_metadata.lkp_ipv4_da);
    modify_field(l4l_metadata.new_addr, dip);
    modify_field(ipv4_metadata.lkp_ipv4_da, dip);
    modify_field(ipv4.dstAddr, dip);
    modify_field(l4l_metadata.l4l_orig_dport,ingress_metadata.lkp_l4_dport);
    modify_field(l4l_metadata.new_port, port);
    modify_field(ingress_metadata.lkp_l4_dport, port);
    modify_field(tcp.dstPort, port);
    generate_digest(LEARN_RECEIVER, l4l_learn_field);
}

action l4l_udp_nat_and_learn(dip, port) {
    // TODO: this action implementation assumes sequential execution semantics
    modify_field(l4l_metadata.learn_type, L4L_CONNECTION_LEARN_TYPE);
    modify_field(l4l_metadata.l4l_orig_da, ipv4_metadata.lkp_ipv4_da);
    modify_field(l4l_metadata.new_addr, dip);
    modify_field(ipv4_metadata.lkp_ipv4_da, dip);
    modify_field(ipv4.dstAddr, dip);
    modify_field(l4l_metadata.l4l_orig_dport, ingress_metadata.lkp_l4_dport);
    modify_field(l4l_metadata.new_port, port);
    modify_field(ingress_metadata.lkp_l4_dport, port);
    modify_field(udp.dstPort, port);
    generate_digest(LEARN_RECEIVER, l4l_learn_field);
}

table l4_rewrite_and_learn {
    reads {
        l3_metadata.lkp_ip_proto : exact;
        l4l_metadata.dippool_offset : exact;
    }
    actions {
        nop;
        l4l_tcp_nat_and_learn;
        l4l_udp_nat_and_learn;
        //l4l_tcp_encap_and_learn;
        //l4l_udp_encap_and_learn;
    }
    size : DIP_TABLE_SIZE;
}

field_list syn_cookie_seed {
    ipv4_metadata.lkp_ipv4_sa;
    ingress_metadata.lkp_l4_sport;
}

field_list_calculation syn_cookie_hash {
    input {
        syn_cookie_seed;
    }
    algorithm : crc32;
    output_width : TCP_SEQNUM_WIDTH;
}

action generate_syn_cookie() {
    // NOTE: sequential exec semantics
    add(tcp.ackNo, tcp.seqNo, 1);
    modify_field_with_hash_based_offset(tcp.seqNo, 0, syn_cookie_hash, 65536);
    modify_field(tcp.ctrl, 18); // SYN-ACK
    
    modify_field(l4l_metadata.temp16b, ingress_metadata.lkp_l4_sport);
    modify_field(ingress_metadata.lkp_l4_sport, ingress_metadata.lkp_l4_dport);
    modify_field(ingress_metadata.lkp_l4_dport, l4l_metadata.temp16b);
    modify_field(tcp.dstPort, ingress_metadata.lkp_l4_dport);
    modify_field(tcp.srcPort, ingress_metadata.lkp_l4_sport);
    
    // TODO: swap IP addresses and change the lkp_ipv4_addrs
    modify_field(l4l_metadata.temp32b, ipv4_metadata.lkp_ipv4_sa);
    modify_field(ipv4_metadata.lkp_ipv4_sa, ipv4_metadata.lkp_ipv4_da);
    modify_field(ipv4_metadata.lkp_ipv4_da, l4l_metadata.temp32b);
    modify_field(ipv4.srcAddr, ipv4_metadata.lkp_ipv4_sa);
    modify_field(ipv4.dstAddr, ipv4_metadata.lkp_ipv4_da);
}


action validate_syn_cookie() {
    // NOTE: sequential exec semantics
    modify_field_with_hash_based_offset(l4l_metadata.temp32b, 0, syn_cookie_hash,65536);    
    subtract_from_field(tcp.ackNo, l4l_metadata.temp32b); // tcp.ackNo must be 1
    //modify_field(tcp.ackNo, tcp.seqNo);
    // TODO: check tcp.ackNo == 1
    //  if yes, you learn src addrs and drop the pkt
    //  if not, simply drop the pkt    
}

table syn_auth {
    reads {
        l3_metadata.lkp_ip_proto : exact;
        tcp.ctrl : exact; // tcp syn or ack
    }
    actions {
        drop_packet;           //other packets
        generate_syn_cookie;  //incoming syn
        validate_syn_cookie;  //incoming ack
    }
    size : 2;
}

field_list l4l_whitelist_learn_field {
    l4l_metadata.learn_type;
    ipv4_metadata.lkp_ipv4_sa;
    //ingress_metadata.lkp_l4_sport;
}

action l4l_syn_cookie_learn() {
    // TODO: this action implementation assumes sequential execution semantics
    modify_field(l4l_metadata.learn_type, L4L_WHITELIST_LEARN_TYPE);
    generate_digest(LEARN_RECEIVER, l4l_whitelist_learn_field);
    drop_packet();
}

table seq_auth {
    reads {
        tcp.ctrl : exact;
        tcp.ackNo : exact;
    }
    actions {
        l4l_syn_cookie_learn;
        //generate_test_cookie;
        drop_packet;
    }
    size : 1;
}

