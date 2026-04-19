"""
local_channel.py
================
A minimal in-memory transport channel for local sender/receiver simulation.

This is NOT real networking.
It simply simulates packet delivery between Alice and Bob.
"""


class LocalChannel:
    def __init__(self):
        self.queue = []

    def send(self, packet: bytes) -> None:
        self.queue.append(packet)

    def receive(self):
        if not self.queue:
            return None
        return self.queue.pop(0)

    def has_data(self) -> bool:
        return len(self.queue) > 0