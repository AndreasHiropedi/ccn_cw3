# Andreas Hiropedi s2015345 

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.ether_types import ETH_TYPE_IP

class L4State14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4State14, self).__init__(*args, **kwargs)
        self.ht = set()

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
        dst, src = (eth.dst, eth.src)
        try:
            # get the head of the list of tcp and ip packets
            tcph = pkt.get_protocols(tcp.tcp)[0]
            iph = pkt.get_protocols(ipv4.ipv4)[0]
            # if either one is null, set the acts according to the input port number
            if not (tcph and iph):
                if in_port == 1:
                    acts = [psr.OFPActionOutput(2)]
                else:
                    acts = [psr.OFPActionOutput(1)]

            else:
                # otherwise, if the input port is 1
                if in_port == 1:
                    # check the TCP flags, and set acts accordingly
                    if tcph.has_flags(tcp.TCP_SYN, tcp.TCP_RST) or tcph.has_flags(tcp.TCP_SYN, tcp.TCP_FIN) or (
                            not tcph.has_flags(tcp.TCP_SYN) and not tcph.has_flags(tcp.TCP_RST) and not tcph.has_flags(
                            tcp.TCP_FIN) and not tcph.has_flags(tcp.TCP_PSH) and not tcph.has_flags(
                            tcp.TCP_ACK) and not tcph.has_flags(tcp.TCP_URG) and not tcph.has_flags(
                            tcp.TCP_ECE) and not tcph.has_flags(tcp.TCP_CWR) and not tcph.has_flags(tcp.TCP_NS)):
                        acts = [psr.OFPActionOutput(0)]
                    else:
                        # get all the necessary info
                        ip_src = iph.src
                        ip_dst = iph.dst
                        sport = tcph.src_port
                        dport = tcph.dst_port
                        match = (ip_src, ip_dst, sport, dport)
                        # and check if the flow key already exists
                        if match not in self.ht:
                            self.ht.add(match)
                        # set acts accordingly
                        acts = [psr.OFPActionOutput(2)]
                        mtc = psr.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src,
                                           ipv4_src=ip_src, ipv4_dst=ip_dst,
                                           ip_proto=iph.proto, tcp_src=sport,
                                           tcp_dst=dport)
                        # add the flow, and link it to port 1
                        self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                        if msg.buffer_id != ofp.OFP_NO_BUFFER:
                            return

                else:
                    # get all the necessary info
                    ip_src = iph.src
                    ip_dst = iph.dst
                    sport = tcph.src_port
                    dport = tcph.dst_port
                    match2 = (ip_dst, ip_src, dport, sport)
                    # and check if the flow key already exists
                    if match2 in self.ht:
                        mtc = psr.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src,
                                           ipv4_src=ip_src, ipv4_dst=ip_dst,
                                           ip_proto=iph.proto, tcp_src=sport,
                                           tcp_dst=dport)
                        # set acts accordingly
                        acts = [psr.OFPActionOutput(1)]
                        # add the flow, and link it to port 1
                        self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                        if msg.buffer_id != ofp.OFP_NO_BUFFER:
                            return
                    else:
                        acts = [psr.OFPActionOutput(0)]

        except IndexError:
            # if there are no TCP over IPV4 packets, just set acts based on input port
            if in_port == 1:
                acts = [psr.OFPActionOutput(2)]
            else:
                acts = [psr.OFPActionOutput(1)]

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
