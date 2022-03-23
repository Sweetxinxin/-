/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//定义相关数据
const bit<16> TYPE_ARP = 0x0806;
const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

//arp头
header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    macAddr_t  sendMac;     //发送端的Mac地址
    ip4Addr_t  sendIP;      //发送端ip地址
    macAddr_t  receiveMac;  //接收端Mac
    ip4Addr_t  receiveIP;   //接收端ip
}

//定义元数据结构体
struct metadata {
 ip4Addr_t dst_ipv4;
}

struct headers {
    ethernet_t   ethernet;
    arp_t		arp;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,  //header类型，out为输出数据
                inout metadata meta,  //inout是同时用作输入、输出值
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;   //转为解析以太网包头
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);  //截取符合以太网长度的包头
        transition select(hdr.ethernet.etherType) {  //根据以太网类型etherType判断下步作何操作
            TYPE_IPV4: parse_ipv4;    //若为IPV4类型，则转为解析ipv4状态
            TYPE_ARP: parse_arp;   //增加此行，若为arp类型，转移到解析arp状态
            default: accept;   //默认为接收
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);   //解析ipv4部分包头
        transition accept;    //转为接收
    }


//解析arp
    state parse_arp {
	/*
	* TODO: parse ARP. If the ARP protocol field is
	* IPV4, transtion to  parse_arp_ipv4
	*/
	packet.extract(hdr.arp);
    meta.dst_ipv4 = hdr.arp.receiveIP;
	transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;  //控制数据包将从哪个输出端口出去
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;   //原来的数据包的原地址修改为目的地址
        hdr.ethernet.dstAddr = dstAddr;   //目标地址修改为控制平面传入的新地址
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;   //TTL自减1
    }

    table ipv4_lpm {  //定义表
        key = {
            hdr.ipv4.dstAddr: lpm;   //匹配类型为最长前缀匹配
        }
        actions = {   //提供行动的列表
            ipv4_forward;   //转发数据
            drop;    //丢弃数据
            NoAction;   //无动作
        }
        size = 1024;   //指定所需的表大小
        default_action = drop();  //默认动作为无动作
    }

//发送及应答
    action send_arp_reply(macAddr_t macadd, ip4Addr_t dst_ipv4) {
        hdr.ethernet.dstAddr = hdr.arp.sendMac;
        hdr.ethernet.srcAddr = macadd;
        hdr.arp.oper = ARP_OPER_REPLY;
        hdr.arp.receiveMac  = hdr.arp.sendMac;
        hdr.arp.receiveIP = hdr.arp.sendIP;
        hdr.arp.sendMac    = macadd;
        hdr.arp.sendIP     = dst_ipv4;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table arp_ternary {
        key = {
            hdr.arp.oper : exact;
            hdr.arp.receiveIP : lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        const default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {    //隐藏参数，判断解析是否成功
            ipv4_lpm.apply();
        }
        else if(hdr.arp.isValid()){  //arp报头有效，调用arp_ternary表
              arp_ternary.apply();
              }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {  //按顺序封装，先以太网后arp最后ipv4
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);   //arp头有效则发出
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
