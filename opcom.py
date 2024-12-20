#!/usr/bin/env python3
'''
@author: Łukasz Misek
'''

import sys
import struct
import can
import serial
import threading
from time import sleep
from datetime import datetime, timedelta


def tohex(buff):
    return " ".join(["%02X" % b for b in buff])


class OPCOMCable():
    def __init__(self, isotpfix=False):
        self.need_restart = False
        self.packet_sent = False
        self.packet_sent_time = None
        self.__isotpfix = isotpfix

    def open(self, port, baudrate=500000):
        self.__serial = serial.serial_for_url(port, baudrate=baudrate)
        sleep(0.1)
        self.__serial.reset_input_buffer()
        self.__serial.reset_output_buffer()
        while self.__serial.in_waiting:
            self.__serial.read()

    def close(self):
        self.__serial.close()
        self.__serial = None

    def __fixisotp(self, data):
        if self.__isotpfix and (len(data) >= 1) and (data[0] == len(data) - 1):
            while len(data) < 8:
                data += b'\xAA'
        return data

    def write(self, data=b""):
        buffer = struct.pack("<H", len(data))
        buffer += data
        csum = sum(buffer)
        buffer += bytes([csum & 0xFF])
        print("--> %s" % tohex(data))
        for b in buffer:
            self.__serial.write(bytes([b]))
            while self.__serial.out_waiting:
                pass

    def read(self):
        psize = struct.unpack("<H", self.__serial.read(2))[0]
        data = self.__serial.read(psize)
        csum = self.__serial.read()
        packet = struct.pack("<H", psize) + data + csum
        # print("<-- %s" % tohex(data))
        if sum(struct.pack("<H", psize) + data) & 0xFF != csum[0]:
            print("Invalid received checksum!: %s" % tohex(packet))
        if data == b'\x7F\x7F\x7F':
            self.need_restart = True
        return data

    def execute(self, data=b""):
        self.write(data)
        return self.read()

    def init(self):
        self.execute(b"\xAB")
        self.execute(b"\xAA")
        self.execute(b"\xAC\x01")
        self.execute(b"\x74")
        self.execute(b"\x73\x01\x00\xF6")
        self.execute(b"\x73\x02\x30\xEC")
        self.execute(b"\x73\x03")
        self.execute(b"\x8E\x02")
        self.execute(b"\x84\x02")

    def init_SWCAN(self):
        self.execute(b"\x20\x21")
        self.execute(b"\x84\x03")
        self.execute(b"\x81\x08\x04\x3C\x03\x03\x03")

    def init_MSCAN(self):
        self.execute(b"\x20\x22")
        self.execute(b"\x20\x24")
        self.execute(b"\x8E\x01")
        self.execute(b"\x81\x08\x02\x35\x01\x01\x01")

    def init_HSCAN(self):
        self.execute(b"\x20\x22")
        self.execute(b"\x20\x23")
        self.execute(b"\x8E\x01")
        self.execute(b"\x81\x02")

    def set_CAN_filter(self, pids):
        self.execute(b"\x82\x02")
        for i in range(8):
            self.execute(struct.pack("<BBi", 0x83, i + 1, pids[i]))
        self.execute(b"\x82\x01")

    def CAN_write(self, pid, data=b"", wait=True):
        self.packet_sent = False
        data = self.__fixisotp(data)
        msg = struct.pack("<BIB", 0x90, pid, len(data)) + data
        if wait:
            self.execute(msg)
        else:
            self.write(msg)
        self.packet_sent_time = datetime.now()

    def CAN_multi_read(self, pid, data=b""):
        data = self.__fixisotp(data)
        self.execute(struct.pack("<BIB", 0x71, pid, len(data)) + data)

    def CAN_multi_read_stop(self, pid, data=b""):
        data = self.__fixisotp(data)
        self.execute(struct.pack("<BIB", 0x72, pid, len(data)) + data)

thread_terminate = False
ser = None


def can_thread(can, cable):
    global thread_terminate
    global ser

    while not thread_terminate:
        msg = can.recv()
        cable.CAN_write(msg.arbitration_id, msg.data, wait=False)
        while not ser.packet_sent and not thread_terminate:
            end_time = ser.packet_sent_time + timedelta(milliseconds=500)
            if end_time < datetime.now():
                print("packet send timeout!")
                break
            else:
                sleep(0)


def main():
    global thread_terminate
    global ser

    if len(sys.argv) < 3:
        print("Uwage: %s <device> <can bus> [isotpfix] [filter:-1,-1,0,255,...]")

    isotpfix = False
    canfilter = [0, 0, 0, 0, 0, 0, 0, 0]

    for arg in sys.argv[3:]:
        if arg == 'isotpfix':
            isotpfix = True
        elif arg.startswith('filter:'):
            for idx, val in enumerate(arg.split(':', 1)[1].split(',')):
                if val[0] in ['+', '-']:
                    canfilter[idx] = int(val)
                else:
                    canfilter[idx] = int(val, 16)

    channel = sys.argv[2].lower()
    if channel in ['lscan', 'swcan']:
        channel = 'lscan'
        ch_init = 'SWCAN'
    elif channel in ['mscan']:
        channel = 'mscan'
        ch_init = 'MSCAN'
    elif channel in ['hscan']:
        channel = 'hscan'
        ch_init = 'HSCAN'
    else:
        print("unknown CAN channel! supported: LSCAN/SWCAN, MSCAN, HSCAN")
        return

    while True:
        ser = OPCOMCable(isotpfix=isotpfix)
        ser.open(sys.argv[1])
        ser.init()
        getattr(ser, 'init_' + ch_init)()
        ser.set_CAN_filter(canfilter)

        bus = can.interface.Bus(channel=channel, bustype="socketcan")

        thread_terminate = False
        th = threading.Thread(target=can_thread, args=(bus, ser)).start()

        while True:
            p = ser.read()
            if ser.need_restart:
                ser.close()
                thread_terminate = True
                th.join()
                ser = None
                break
            if p and p[0] == 0x91:
                pid, dlen = struct.unpack(">IB", p[1:6])
                data = p[6:6 + dlen]
                msg = can.Message(arbitration_id=pid, data=[b for b in data], extended_id=False)
                print(msg)
                bus.send(msg)
            elif p and p[0] == 0xD0:
                ser.packet_sent = True


if __name__ == '__main__':
    main()