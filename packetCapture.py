import queue
import threading
from scapy.all import sniff, IP, TCP
from collections import defaultdict

class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()   # use queue instead of list because list is not thread safe (race condition)
        self.stop_capture = threading.Event()   # use threading and not a boolean because it gives a documented API

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:  # checks whether thos protocols layers are present
            self.packet_queue.put(packet)
        
    def start_capture(self, interface=None):
        def capture_thread():
            sniff(iface=interface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: self.stop_capture.is_set())
                
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()
        
    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()
