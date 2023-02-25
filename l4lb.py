# Andreas Hiropedi s2015345 

from re import T
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.tcp import TCP_SYN
from ryu.lib.packet.tcp import TCP_FIN
from ryu.lib.packet.tcp import TCP_RST
from ryu.lib.packet.tcp import TCP_ACK
from ryu.lib.packet.ether_types import ETH_TYPE_IP, ETH_TYPE_ARP

class L4Lb(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4Lb, self).__init__(*args, **kwargs)
        self.ht = {} # {(<sip><vip><sport><dport>): out_port, ...}
        self.vip = '10.0.0.10'
        self.dips = ('10.0.0.2', '10.0.0.3')
        self.dmacs = ('00:00:00:00:00:02', '00:00:00:00:00:03')
        self.cip = '10.0.0.1'
        self.cmac = '00:00:00:00:00:01'

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        return out

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
        mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arph = pkt.get_protocols(arp.arp)
        iph = pkt.get_protocols(ipv4.ipv4)
        tcph = pkt.get_protocols(tcp.tcp)
        key = []
        cip = '10.0.0.1'
        vip = '10.0.0.10'
        dips = ('10.0.0.2', '10.0.0.3')
        acts = [psr.OFPActionOutput(0)]
        try:
            if arph:
                if in_port == 1:
                    ether_proto = ethernet.ethernet(dst=self.cmac, src=self.dmacs[0], ethertype=ETH_TYPE_ARP)
                    arp_proto = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                                src_mac=self.dmacs[0], src_ip=self.vip,
                                dst_mac=self.cmac, dst_ip=self.cip)
                elif in_port == 2:
                    ether_proto = ethernet.ethernet(dst=self.dmacs[0], src=self.cmacs, ethertype=ETH_TYPE_ARP)
                    arp_proto = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                                src_mac=self.cmac, src_ip=self.cip,
                                dst_mac=self.dmacs[0], dst_ip=self.dips[0])
                elif in_port == 3:
                    ether_proto = ethernet.ethernet(dst=self.dmacs[0], src=self.dmacs[1], ethertype=ETH_TYPE_ARP)
                    arp_proto = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                                src_mac=self.cmac, src_ip=self.cip,
                                dst_mac=self.dmacs[1], dst_ip=self.dips[1])
                pkt = packet.Packet()
                pkt.add_protocol(ether_proto)
                pkt.add_protocol(arp_proto)
                out = self._send_packet(dp, in_port, pkt)
                dp.send_msg(out)
                return
            elif tcph and iph:
                acts = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]
                output_port = 1
                ip_pkt = iph[0]
                tcp_pkt = tcph[0]
                if in_port != 1:
                    output_port = 1
                    acts = [psr.OFPActionOutput(output_port), psr.OFPActionSetField(ipv4_src=vip)]
                else:
                    output_port = 0
                    key = (ip_pkt.src, ip_pkt.dst, tcp_pkt.src_port, tcp_pkt.dst_port)
                    if key in self.ht:
                        output_port = self.ht[key]
                    else:
                        output_port = len(self.ht) % 2 + 2
                        self.ht[key] = output_port
                    if output_port != 2:
                        field_1 = psr.OFPActionSetField(ipv4_dst=dips[1])
                        field_2 = psr.OFPActionSetField(eth_dst=self.dmacs[1])
                    else:
                        field_1 = psr.OFPActionSetField(ipv4_dst=dips[0])
                        field_2 = psr.OFPActionSetField(eth_dst=self.dmacs[0])
                    acts = [psr.OFPActionOutput(output_port), field_1, field_2]
                match = psr.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src, ipv4_src=ip_pkt.src, tcp_src=tcp_pkt.src_port, eth_type=eth.ethertype, ip_proto=ip_pkt.proto)
                self.add_flow(dp, output_port, match, acts, msg.buffer_id)
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    return
        except IndexError:
            pass
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
