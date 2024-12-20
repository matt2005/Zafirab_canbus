
'''
LWPM Comfort Module - CAN sniffer

@author: Åukasz Misek
src: https://files.lwpm.eu/LWPMComfortModule/lcm_service/lcm_sniffer.py
'''

import can
import sys
import threading
import platform
from time import sleep, time
from struct import unpack,  pack
from enum import IntEnum


LAN = {
    0: "LSCAN (pin 1)",
    1: "MSCAN (pin 3 + 11)",
    2: "HSCAN (pin 6 + 14)",
    3: "CHCAN (pin 12 + 13)"
}


class SnifferPacketType(IntEnum):
    CANFrame = 0x01


def _create_bus(device, channel, init_commands):

    class BUS():
        def __init__(self):
            from lcm_service import DEBUG
            self.__debug = DEBUG
            self.__device = device
            self.__timeout = 0.001
            self.__thread_terminate = False
            self.__channel = channel
            self.__can = self.__create_can()
            self.__to_send = []
            self.__read_features = True
            self.__set_memory = True
            self.__init_commands = init_commands
            self.__to_recv = []
            self.__lock_recv = threading.Lock()
            self.__lock_send = threading.Lock()
            self.__next_send = None
            self.__exiting = -1
            self.__keep_alive = time() + 2
            self.__thread = threading.Thread(target=self.__thread_fun, name="CAN Sniffer/can (%s)" % channel)
            self.__thread_uart = threading.Thread(target=self.__thread_fun_uart, name="CAN Sniffer/uart (%s)" % channel)
            self.error = False

        def __write(self, data):
            if self.__debug:
                print("WRITE", " ".join(["%02X" % c for c in data]))
            return self.__device.write(data)

        def __read(self, cnt=1):
            res = self.__device.read(cnt)
            if self.__debug and res:
                print("READ", " ".join(["%02X" % c for c in res]))
            return res

        def __create_can(self):
            if platform.system() == "Windows":
                self.__channel, channel_idx = self.__channel.split('/')
                return can.interface.Bus(channel=int(channel_idx), bustype="kvaser")
            else:
                return can.interface.Bus(channel=self.__channel.lower(), bustype="socketcan")

        def __check_timeout(self):
            if self.__keep_alive < time():
                self.__keep_alive = time() + 2
                self.__write(b"\xDD")

        def __thread_fun(self):
            while not self.__thread_terminate:
                msg = self.__can.recv(self.__timeout)

                if msg is not None:
                    with self.__lock_send:
                        self.__to_send.append(msg)

                with self.__lock_recv:
                    for msg in self.__to_recv:
                        if self.__debug:
                            print("<<<", msg)
                        self.__can.send(msg)
                    self.__to_recv = []

        def __thread_fun_uart(self):
            while not self.__thread_terminate:
                self.__device.timeout = self.__timeout
                b = self.__read()
                if b == b'\xEE':
                    if self.__read_features == False:
                        self.__write(b"\x80")
                        self.__device.timeout = 1
                        if self.__read() != b"\xE0":
                            print("--> ERROR: error reading CAN sniffer features, invalid response!")
                            return self.fatal()
                        l = self.__read()
                        if not l or len(l) != 1:
                            print("--> ERROR: error reading CAN sniffer features, no response length!")
                            return self.fatal()
                        features = self.__read(l[0])
                        if not features or len(features) != l[0]:
                            print("--> ERROR: error reading CAN sniffer features, response not received!")
                            return self.fatal()
                        if features[0] == 0x01:
                            self.__version = 1
                            features = unpack(">BBBBBBBB", features)
                            print("--> CAN sniffer features:")
                            print("    version:      %u" % features[0])
                            print("    supported bus:")
                            for i in sorted(LAN.keys()):
                                if features[1] & (1 << i):
                                    print("        %s" % LAN[i])
                            print("    mo range:     %u - %u" % (features[2], features[3]))
                            print("    remote:       %s" % ("yes" if features[4] != 0 else "no"))
                            print("    extended id:  %s" % ("yes" if features[5] != 0 else "no"))
                            print("    error:        %s" % ("yes" if features[6] != 0 else "no"))
                            print("    FD:           %s" % ("yes" if features[7] != 0 else "no"))
                            with self.__lock_send:
                                self.__to_send = self.__init_commands
                                self.__read_features = None
                            continue
                        else:
                            print("--> ERROR: unknown CAN sniffer version!")
                            return self.fatal()

                    assert self.__next_send is not None

                    if isinstance(self.__next_send, can.Message):
                        msg = self.__next_send
                        packet = pack(">IBBBBB", msg.arbitration_id,
                            1 if msg.is_remote_frame else 0,
                            1 if msg.is_extended_id else 0,
                            1 if msg.is_error_frame else 0,
                            1 if msg.is_fd else 0,
                            len(msg.data)) + msg.data
                        self.__device.timeout = 1
                        self.__write(b"\x10" + packet)
                        if self.__debug:
                            print(">>>", msg)
                        if self.__read() != b"\xE0":
                            print("--> ERROR: error sending packet!")
                            return self.fatal()
                    else:
                        self.__write(self.__next_send)
                        self.__device.timeout = 1
                        if self.__read() != b"\xE0":
                            print("--> command %s: FAILED" % " ".join(["%02X" % b for b in self.__next_send]))
                            return self.fatal()
                        else:
                            print("--> command %s: OK" % " ".join(["%02X" % b for b in self.__next_send]))

                    self.__check_timeout()
                    self.__next_send = None

                if b == b'\xBB':
                    # set memory size (maximum available)
                    device.write(pack(">H", 0xFFFF))
                    self.__device.timeout = 1
                    if self.__read() != b"\xE0":
                        print("--> set memory size FAILED")
                        return self.fatal()
                    else:
                        print("--> set memory size: OK")
                if b == b'\xDD':
                    # device timeout
                    print("!!! ERROR: communication timeout!")
                    return self.fatal()
                if b == b'\xFF':
                    # exit
                    self.__device.timeout = 1
                    if self.__read() != b"\xE0":
                        print("--> sniffer exit: FAILED")
                        return self.fatal()
                    else:
                        print("--> sniffer exit: OK")
                    if self.__exiting == 1:
                        self.__exiting = -1
                        return
                if b == b'\xCC':
                    # data received
                    self.__device.timeout = 2
                    device.timeout = 1
                    packet_type = SnifferPacketType(device.read()[0])
                    packet_size = device.read()[0]
                    packet_raw = self.__read(packet_size)
                    if packet_type == SnifferPacketType.CANFrame:
                        packet = unpack(">IBBBB", packet_raw[:8])
                        packet_data = packet_raw[8:]
                        msg = can.Message(
                            timestamp=time(),
                            channel = self.__channel,
                            is_remote_frame=packet[1],
                            is_extended_id=packet[2],
                            is_error_frame=packet[3],
                            arbitration_id=packet[0],
                            data=packet_data)
                        with self.__lock_recv:
                            self.__to_recv.append(msg)
                    else:
                        assert False

                    self.__check_timeout()
                else:
                    if self.__exiting == 0:
                        self.__exiting = 1
                        self.__write(b"\xFF")

                        with self.__lock_send:
                            self.__next_send = None
                            self.__to_send = []
                    elif self.__exiting > 0:
                        continue

                    self.__check_timeout()
                    if self.__next_send:
                        continue
                    with self.__lock_send:
                        if self.__to_send:
                            self.__next_send = self.__to_send[0]
                            self.__to_send = self.__to_send[1:]
                            self.__write(b"\xEE")
                            continue
                    if self.__read_features:
                        self.__read_features = False
                        self.__write(b"\xEE")
                    elif (self.__read_features is None) and self.__set_memory:
                        self.__set_memory = False
                        self.__write(b"\xBB")

        def close(self):
            print("!!! exiting CAN sniffer service...")
            self.__exiting = 0
            while self.__exiting >= 0:
                sleep(0.1)
            print("--> terminating threads...")
            self.__thread_terminate = True
            self.__thread.join()
            self.__thread_uart.join()
            print("--> done!")

        def fatal(self):
            print("FATAL ERROR: unable to continue!")
            self.__thread_terminate = True
            self.error = True
            sys.exit()

        def send(self, frame):
            with self.__lock_send:
                self.__to_send.append(frame)

        def start(self):
            self.__thread.start()
            self.__thread_uart.start()

    return BUS()


def CANSniffer_start(device, bus, init_commands):
    bus = _create_bus(device, bus, init_commands)
    print("!!! press CTRL+C to terminate")
    bus.start()

    while not bus.error:
        try:
            sleep(0.1)
        except KeyboardInterrupt:
            bus.close()
            break