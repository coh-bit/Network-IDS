from collections import defaultdict, deque

from scapy.all import IP, TCP

class TrafficAnalyzer:
    def __init__(self, sequence_length=10):
        self.sequence_length = sequence_length
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'syn_count': 0,
            'ack_count': 0,
            'fin_count': 0,
            'rst_count': 0
        })
        self.flow_sequences = defaultdict(lambda: deque(maxlen=self.sequence_length))

    def analyze_packet(self, packet):
        if IP not in packet or TCP not in packet:
            return None

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port_src = packet[TCP].sport
        port_dst = packet[TCP].dport
        protocol = "TCP"

        if (ip_src, port_src) <= (ip_dst, port_dst):
            flow_key = (ip_src, port_src, ip_dst, port_dst, protocol)
        else:
            flow_key = (ip_dst, port_dst, ip_src, port_src, protocol)

        stats = self.flow_stats[flow_key]
        current_time = float(packet.time)
        previous_time = stats['last_time']
        tcp_flags = int(packet[TCP].flags)

        stats['packet_count'] += 1
        stats['byte_count'] += len(packet)
        if stats['start_time'] is None:
            stats['start_time'] = current_time
        stats['last_time'] = current_time
        self._update_flag_counts(stats, tcp_flags)

        packet_vector = self._packet_vector(packet, current_time, previous_time)
        self.flow_sequences[flow_key].append(packet_vector)

        return {
            'flow_key': flow_key,
            'flow_features': self.extract_features(packet, stats),
            'sequence': self._get_padded_sequence(flow_key),
            'packet_info': {
                'source_ip': ip_src,
                'destination_ip': ip_dst,
                'source_port': port_src,
                'destination_port': port_dst
            }
        }

    def _update_flag_counts(self, stats, tcp_flags):
        if tcp_flags & 0x02:
            stats['syn_count'] += 1
        if tcp_flags & 0x10:
            stats['ack_count'] += 1
        if tcp_flags & 0x01:
            stats['fin_count'] += 1
        if tcp_flags & 0x04:
            stats['rst_count'] += 1

    def _packet_vector(self, packet, current_time, previous_time):
        inter_arrival_time = 0.0 if previous_time is None else max(current_time - previous_time, 0.0)
        return [
            float(self.flow_stats[self._current_flow_key(packet)]['packet_count']),
            float(self.flow_stats[self._current_flow_key(packet)]['byte_count']),
            float(self.flow_stats[self._current_flow_key(packet)]['last_time'] - self.flow_stats[self._current_flow_key(packet)]['start_time']) if self.flow_stats[self._current_flow_key(packet)]['start_time'] is not None else 0.0,
            float(int(packet[TCP].flags) & 0x02),
            float(int(packet[TCP].flags) & 0x10),
            float(packet[TCP].dport),
        ]

    def _current_flow_key(self, packet):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port_src = packet[TCP].sport
        port_dst = packet[TCP].dport
        protocol = "TCP"

        if (ip_src, port_src) <= (ip_dst, port_dst):
            return (ip_src, port_src, ip_dst, port_dst, protocol)
        return (ip_dst, port_dst, ip_src, port_src, protocol)

    def _get_padded_sequence(self, flow_key):
        sequence = list(self.flow_sequences[flow_key])
        padding_length = self.sequence_length - len(sequence)
        if padding_length > 0:
            sequence = [[0.0, 0.0, 0.0, 0.0, 0.0, 0.0] for _ in range(padding_length)] + sequence
        return sequence[-self.sequence_length:]

    def extract_features(self, packet, stats):
        flow_duration = max(stats['last_time'] - stats['start_time'], 1e-6)
        packet_count = stats['packet_count']
        byte_count = stats['byte_count']
        syn_ratio = stats['syn_count'] / packet_count if packet_count > 0 else 0.0
        ack_ratio = stats['ack_count'] / packet_count if packet_count > 0 else 0.0

        return {
            'packet_size': len(packet),
            'packet_count': packet_count,
            'byte_count': byte_count,
            'flow_duration': flow_duration,
            'packet_rate': packet_count / flow_duration,
            'byte_rate': byte_count / flow_duration,
            'average_packet_size': byte_count / packet_count,
            'event_count': packet_count,
            'syn_ratio': syn_ratio,
            'ack_ratio': ack_ratio,
            'syn_count': stats['syn_count'],
            'ack_count': stats['ack_count'],
            'fin_count': stats['fin_count'],
            'rst_count': stats['rst_count'],
            'tcp_flags': int(packet[TCP].flags),
            'window_size': packet[TCP].window
        }
