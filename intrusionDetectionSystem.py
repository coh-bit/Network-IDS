import queue

from scapy.all import IP, TCP

import alertSystem
import detectionEngine
import packetCapture
import trafficAnalyzer

class IntrusionDetectionSystem:
    def __init__(self, interface=None):
        self.packet_capture = packetCapture.PacketCapture()
        self.traffic_analyzer = trafficAnalyzer.TrafficAnalyzer()
        self.detection_engine = detectionEngine.DetectionEngine()
        self.alert_system = alertSystem.AlertSystem()

        self.interface = interface

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                analysis_result = self.traffic_analyzer.analyze_packet(packet)

                if analysis_result:
                    threats = self.detection_engine.detect_threats(analysis_result)

                    for threat in threats:
                        self.alert_system.generate_alert(threat, analysis_result['packet_info'])
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()
