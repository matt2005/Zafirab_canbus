#!/usr/bin/env python3
'''
LWPM Comfort Module - web server

@author: Åukasz Misek

src: https://files.lwpm.eu/LWPMComfortModule/lcm_service/lcm_service.py
'''

import logging
import serial
import sys
import requests
import platform
import socket
import os
import codecs
import threading
import datetime
from enum import IntEnum
from serial.tools import list_ports
from flask import Flask, jsonify, request, redirect, Response, abort
from functools import wraps
from time import sleep, time
from struct import pack, unpack
from random import getrandbits
from traceback import format_exc
from threading import RLock, Thread
from json import loads, dumps
from base64 import b64decode
from hashlib import sha256
from random import random


VERSION = "v1.0"
V1_VERSION = "v1.0"
V1_REVISION = 29

DEBUG = '--debug' in sys.argv
DEBUG_UART = '--debug-uart' in sys.argv
SSL = '--ssl' in sys.argv
HOST = sys.argv[sys.argv.index('--host') + 1] if ('--host' in sys.argv) else '127.0.0.1'
DUMP = '--dump' in sys.argv
SNIFFER = '--sniffer' in sys.argv
PORT = sys.argv[sys.argv.index('--port') + 1] if ('--port' in sys.argv) else 50099
BAUDRATE = [int(sys.argv[sys.argv.index('--baud') + 1])] if ('--baud' in sys.argv) else [500000, 1000000, 9600, 115200]
FORCE_DEVICE = sys.argv[sys.argv.index('--device') + 1] if ('--device' in sys.argv) else None
HAS_VIRTUAL = '--virtual' in sys.argv
HAS_FAKE = '--fake' in sys.argv
FAKE_SN = sys.argv[sys.argv.index('--sn') + 1] if ('--sn' in sys.argv) else 'LCM/0000FFFF'
GMLAN_SIMULATOR = '--gmlan' in sys.argv
GMLAN_TIMEOUTS = 0.00
if GMLAN_SIMULATOR:
    from lcm_gmlan import VirtualGMLan
    VGMLan = VirtualGMLan()
    x = [p for p in sys.argv if p.startswith("--gmlan-timeout=")]
    if len(x) > 0:
        GMLAN_TIMEOUTS = float(x[0].split("=")[1])
        print("!!! GMLan simulated timeouts: %0.2f" % GMLAN_TIMEOUTS)

UPDATER_VERSION_V01 = "UART Firmware Updater v0.1"
UPDATER_VERSION_V02 = "UART Firmware Updater v0.2"
UPDATER_VERSION_V03 = "LWPM UART Bootloader"

_real_getfqdn = socket.getfqdn
def _my_getfqdn(name=''):
    if not name:
        return 'service.lwpm.eu'
    else:
        try:
            name.decode('utf-8')
        except:
            name = 'service.lwpm.eu'
        return _real_getfqdn(name)
socket.getfqdn = _my_getfqdn

_print = print
def print(s, *args, **kwargs):
    try:
        _print(s, *args, **kwargs)
    except:
        try:
            _print(s.encode('UTF-8').decode('ASCII', errors='ignore'), *args, **kwargs)
        except:
            pass

def add_cors_preflight_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'

    if request.method == 'OPTIONS' or True:
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS, PUSH'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        response.headers['Access-Control-Max-Age'] = '600'
        # Allow chrome to access private network ajax requests
        response.headers['Access-Control-Allow-Private-Network'] = 'true'
    return response


def handle_cors(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        if request.method == 'OPTIONS':
            response = Response()
        else:
            response = func(*args, **kwargs)
        response = add_cors_preflight_headers(response)
        return response

    return decorator

def dumpRequest(rq):
    if DUMP:
        try:
            if request.args:
                for k, v in request.args.items():
                    print('--> argument: %s = %s' % (k, v))
        except:
            pass

        try:
            js = request.get_json(force=True)
            if js:
                print('JSON REQUEST:')
                print(dumps(js, sort_keys=True, indent=4))
        except:
            pass

if '--device' in sys.argv:
    i = sys.argv.index('--device')
    if len(sys.argv) > i + 1:
        FORCE_DEVICE = sys.argv[i + 1]
        print("!!! Forced device: %s" % FORCE_DEVICE)

SESSIONS = {}

SIMULATOR_DEVICE_ID = "/virtual/simulator"
FAKE_DEVICE_ID = "/virtual/fake"

SIMULATOR_CONFIG = {
    11: "16A8",
    17: "0000",
    21: "01",
    60: "8D",
    64: "03",
    66: "96",
    67: "01",
    69: "0A",
    80: "01",
    96: "01",
    97: "01",
    98: "0320",
    99: "0320",
    112: "00",
    128: "01",
    304: "04",
    319: "00C8",
    336: "04",
    343: "454355496E666F",
    344: "496E666F726D61636A65",
    368: "0A",
    384: "8D0F200000",
    385: "0B00210000",
    386: "1314040002",
    387: "1300230000",
    393: "0C14A20000",
    394: "1214A10003",
    395: "1200220000",
    398: "6202010000",
    420: "0000030103002A55040600000055030800005504070000005503010000550302000055030300005503040000550305000030550301FF00550302FF00550303FF00550304FF00550305FF00550406017D0055030801C8550407015DC0550304FF100040550301FF100040550301FF300040550301FF320040550304FF120040550302FF080040550302FF180040550302FF580040550302FFD800405504060000005503080000550407000000550302FF580040550302FF180040550302FF080040550302FF000040550304FF100040550301FF300040550301FF100040550301FF000040550304FF000040010500",
    429: "000005550304020205550304000000",
    430: "0000000C5503040000500502000000000255030410105005020C0C0000",
    431: "0000000C5503050000500502000000000255030510105005020C0C0000",
    512: "01",
    560: "01",
    561: "14",
    562: "0A",
    576: "8F",
    578: "01",
    582: "8E",
    768: "04",
    769: "23",
    770: "0B",
    771: "2F",
    772: "2C",
    773: "1F",
    774: "0C",
    775: "05",
    776: "04",
    777: "0D",
    778: "2D",
    779: "0F",
    780: "1F",
    781: "46",
    782: "33",
    783: "31",
    784: "51",
    785: "1C",
    786: "00",
    787: "20",
    788: "40",
    789: "60",
    790: "80",
    791: "42",
    832: "01",
    833: "02",
    834: "04",
    835: "03",
    836: "05",
    838: "60",
    839: "61",
    840: "62",
    841: "63",
    842: "64",
    844: "62",
    845: "64",
    1023: "FC97F41207713AE586F39D2F4DBA77A7FA06B550C92B5F1B66881D144CB3147AAFA1B22CA22004DA9414335982160CB7B80564C0D0FB7B"
}

FAKE_CONFIG = {
}

API = "/api/v1/"

class Service(IntEnum):
    Configuration = 0x01
    DeviceInfo = 0x02
    GMLan = 0x03,
    CANSniffer = 0x04,
    ResetDevice = 0xFE
    Exit = 0xFF


class ConfigurationServiceCommand(IntEnum):
    Reset = 0x01
    Read = 0x02
    Write = 0x03
    Optimize = 0x04
    RunAction = 0x05
    ATBaudrate = 0x0F
    ATCommand = 0x10
    Exit = 0xFF


class DeviceInfoServiceCommand(IntEnum):
    Product = 0x01
    Version = 0x02
    Firmware = 0x03
    ManufacturingDate = 0x04
    SerialNumber = 0x05
    LicenseOwner = 0x06
    LicenseFeatures = 0x07
    HardwareVersion = 0x08
    DeviceType = 0x09
    FirmwareType = 0x0A
    HardwareFeatures = 0x0B
    Exit = 0xFF


class GMLanServiceCommand(IntEnum):
    GetVersion = 0x01
    SendCommand = 0x02
    SendPacket = 0x03
    SetPacketFilter = 0x04
    SetTesterPresent = 0x05
    AdjustMemory = 0xBB
    DataReceived = 0xCC
    KeepAlive = 0xDD
    ExecuteCommand = 0xEE
    Exit = 0xFF


class CANSnifferCommand(IntEnum):
    InitCAN = 0x01
    SetFilter = 0x02
    SendPacket = 0x10
    Exit = 0xFF


class CommandResult(IntEnum):
    OK = 0xE0
    UnknownCommand = 0xE1
    Failed = 0xE2
    NotImplemented = 0xE3
    NoLicense = 0xE4
    Disconnected = 0xEF


CommandResult.ALL = [CommandResult.OK, CommandResult.UnknownCommand, CommandResult.Failed, CommandResult.NotImplemented, CommandResult.Disconnected]


class ConfigParser():
    @staticmethod
    def decode(data):
        result = {}
        while data:
            length = unpack(">H", data[:2])[0]
            data = data[2:]
            item_type = length & 0x03FF
            length = length >> 10
            if length == 0x3F:
                length = unpack(">H", data[:2])[0]
                data = data[2:]
            value = data[:length]
            data = data[length:]
            result[item_type] = value
        return result

    @staticmethod
    def encode(params):
        result = b""
        for param_type, param_data in params.items():
            if len(param_data) >= 63:
                param_data = pack(">HH", (63 << 10) | param_type, len(param_data)) + param_data
            else:
                param_data = pack(">H", (len(param_data) << 10) | param_type) + param_data
            result += param_data

        return result


class Device():
    SERVICE_START = [0xE0, 0xE1, 0xE2, 0xE3, 0xEF, 0xEE, 0xED, 0xEC]
    SERVICE_READY_MAGIC = 0xFF010203
    SERVICE_NO_LICENSE_MAGIC = 0xFF010204
    SERVICE_READY_MAGIC_NO_ECHO = 0xFF010205
    SERVICE_READY_MAGIC_CONFIRM256 = 0xFF010206

    LastValidBaudrateIndex = None

    @staticmethod
    def EXECUTE(session, fun, init=True, close=True):
        if init:
            dev = Device(session['device'])
            session['current_device'] = dev
        else:
            dev = session['current_device']
        if not dev:
            return {
                "result": False,
                "error": "device is not initialized!"
            }
        result = None
        with dev._lock:
            if not session['current_device']:
                result = result or {
                    "result": False,
                    "error": "device is gone"
                }
            else:
                if (not init) or (dev.init() and dev.service_init()):
                    try:
                        result = fun(dev)
                    except Exception as _e:
                        dev.error("!!! unhandled EXCEPTION !!!")
                        dev.error(format_exc())
                        result = None

                if init and dev._recoveryDetected:
                    result = {
                        "result": False,
                        "recoveryDetected": True
                    }

                if close:
                    dev.close()
                    session['current_device'] =  None

        result = result or {
            "result": False,
            "error": dev.last_error
        }

        return result

    def __init__(self, device):
        self.last_error = None
        self._lock = threading.Lock()
        self.__echo = True
        self.__device_name = device
        self.__device = None
        self._recoveryDetected = False
        if Device.LastValidBaudrateIndex is not None:
            self.__current_baudrate_index = Device.LastValidBaudrateIndex
        else:
            self.__current_baudrate_index = 0
        self.__next_baudrate_index = self.__current_baudrate_index

    def try_next_baudrate(self):
        if self.__device:
            self.__device.close()
            sleep(0.1)

        self.__current_baudrate_index = self.__next_baudrate_index
        br = BAUDRATE[self.__current_baudrate_index]

        self.__next_baudrate_index = self.__current_baudrate_index + 1
        if self.__next_baudrate_index == len(BAUDRATE):
            self.__next_baudrate_index = 0
        try:
            self.info("Connecting to device %s [%u bps]..." % (self.__device_name, br))
            self.__device = serial.serial_for_url(self.__device_name, baudrate=br, timeout=2)
            self._lock = threading.Lock()
            return True
        except Exception as e:
            self.error("ERROR: can not connect to %s\n%s" % (self.__device_name, str(e)))
            return False

    def info(self, msg):
        print("DEV> " + msg)

    def error(self, msg):
        print("DEV ERR> " + msg, file=sys.stderr)
        self.last_error = msg

    def init(self):
        for _i in range(len(BAUDRATE)):
            if self.try_next_baudrate():
                self.info("Device initialization...")
                self.__device.reset_input_buffer()
                self.__device.reset_output_buffer()
                # wake up device
                original_timeout = self.__device.timeout
                self.__device.timeout = 0.10
                self.__device.send_break(0.1)
                self.__echo = True
                self._recoveryDetected = False
                self.__oobMessages = ""
                for _i in range(4):
                    self.send([0xFF])
                for _i in range(2):
                    res = self.send([0x00])
                if res:
                    for _i in range(4):
                        res = self.send([0xAA + _i])

                if UPDATER_VERSION_V01 in self.__oobMessages:
                    self.info("!!! recovery mode detected !!!")
                    self._recoveryDetected = True
                    Device.LastValidBaudrateIndex = self.__current_baudrate_index
                    return False
                if UPDATER_VERSION_V02 in self.__oobMessages:
                    self.info("!!! recovery mode detected !!!")
                    self._recoveryDetected = True
                    Device.LastValidBaudrateIndex = self.__current_baudrate_index
                    return False
                if UPDATER_VERSION_V03 in self.__oobMessages:
                    self.info("!!! recovery mode detected !!!")
                    self._recoveryDetected = True
                    Device.LastValidBaudrateIndex = self.__current_baudrate_index
                    return False
                self.__device.timeout = original_timeout
                self.__device.reset_input_buffer()
                self.__device.reset_output_buffer()
                if res == True:
                    Device.LastValidBaudrateIndex = self.__current_baudrate_index
                    return True
        self.error("ERROR: Connect failed!")
        return False

    def close(self):
        self.info("Disconnecting device...")
        if self.__device:
            self.__device.close()
        self.__device = None
        self.__echo = True

    def get_device(self):
        assert self.__device
        return self.__device

    def send8(self, b, dbg=True):
        if DEBUG_UART and dbg:
            print("::: send8 (0x%02X)" % b)
        self.__device.write(bytes([b]))
        if not self.__echo:
            return True

        timeout = time() + 0.2
        while timeout > time():
            r = self.__device.read()
            if r and len(r) == 1:
                if r[0] == b:
                    return True
                else:
                    self.__oobMessages += ("%c" % r[0])
                    print("%c" % r[0], end='')
            else:
                self.error("ERROR: byte send failed, no echo")
                return False
        self.error("ERROR: byte send timeout, no echo")
        return False

    def send16(self, h, dbg=True):
        if DEBUG_UART and dbg:
            print("::: send16 (0x%04X)" % h)
        return self.send8((h >> 8) & 0xFF, dbg=False) and self.send8(h & 0xFF, dbg=False)

    def send32(self, w, dbg=True):
        if DEBUG_UART and dbg:
            print("::: send32 (0x%08X)" % w)
        return self.send8((w >> 24) & 0xFF, dbg=False) and self.send8((w >> 16) & 0xFF, dbg=False) and self.send8((w >> 8) & 0xFF) and self.send8(w & 0xFF, dbg=False)

    def send(self, data, dbg=True):
        if not isinstance(data, bytes):
            if not isinstance(data, list):
                data = [data]
            data = bytes(data)
        if DEBUG_UART and dbg:
            print("::: send", " ".join(["%02X" % b for b in data]))
        if self.__echo:
            for b in data:
                if not self.send8(b, dbg=True):
                    return False
        else:
            self.__device.write(data)
        return True

    def recv8(self, dbg=True):
        while True:
            r = self.__device.read()
            if r and len(r) == 1:
                if DEBUG_UART and dbg:
                    print("::: recv8: 0x%02X" % r[0])
                return r[0]
            else:
                self.error("ERROR: byte read error")
                return None

    def recv16(self, dbg=True):
        try:
            res = (self.recv8(dbg=False) << 8) | self.recv8(dbg=False)
            if DEBUG_UART and dbg:
                print("::: recv16: 0x%04X" % res)
            return res
        except:
            return None

    def recv32(self, dbg=True):
        try:
            res = (self.recv8(dbg=False) << 24) | (self.recv8(dbg=False) << 16) | (self.recv8(dbg=False) << 8) | self.recv8(dbg=False)
            if DEBUG_UART and dbg:
                print("::: recv32: 0x%08X" % res)
            return res
        except:
            return None

    def recv(self, count, dbg=True):
        result = b''
        idx = 0
        for _i in range(count):
            b = self.recv8(dbg=False)
            if b is None:
                return None
            result += bytes([b])
            idx += 1
            if idx == self.__confirm:
                self.send8(0xAA)
                idx = 0
        if DEBUG_UART and dbg:
            print("::: recv", result)
        return result

    def service_init(self):
        self.__echo = True
        self.__confirm = 0
        if self.send(Device.SERVICE_START):
            response = self.recv32()
            if response == Device.SERVICE_READY_MAGIC:
                self.info("--> connection succeeded")
                self.__echo = True
                self.__confirm = 0
                return True
            if response == Device.SERVICE_READY_MAGIC_NO_ECHO:
                self.info("--> connection succeeded (no echo)")
                self.__confirm = 0
                self.__echo = False
                return True
            if response == Device.SERVICE_READY_MAGIC_CONFIRM256:
                self.info("--> connection succeeded (no echo/confirm 256)")
                self.__confirm = 256
                self.__echo = False
                return True
            if response == Device.SERVICE_NO_LICENSE_MAGIC:
                self.error("--> connection failed (no valid license)")
                return False

        self.error("--> connection failed")
        return False

    def service_start(self, service):
        if self.send8(service):
            response = self.recv32()
            if response == Device.SERVICE_READY_MAGIC:
                self.info("--> connection with service succeeded")
                self.__echo = True
                self.__confirm = 0
                return True
            if response == Device.SERVICE_READY_MAGIC_NO_ECHO:
                self.info("--> connection with service succeeded (no echo)")
                self.__echo = False
                self.__confirm = 0
                return True
            if response == Device.SERVICE_READY_MAGIC_CONFIRM256:
                self.info("--> connection succeeded (no echo/confirm 256)")
                self.__confirm = 256
                self.__echo = False
                return True
            if response == Device.SERVICE_NO_LICENSE_MAGIC:
                self.error("--> connection with service failed (no valid license)")
                return False

        self.error("--> connecting with service failed")
        return False

    def device_restart(self):
        return self.send8(Service.ResetDevice)

    def service_exit(self):
        return self.send8(Service.Exit)

    def service_command_get_result(self):
        msg = b""
        while True:
            b = self.recv8()
            if b is None:
                try:
                    msg = msg.decode('UTF-8')
                except Exception as e:
                    msg = str(e)
                return None, msg
            if b in [int(x) for x in CommandResult.ALL]:
                if msg:
                    for l in msg.decode('UTF-8').strip().split("\n"):
                        self.info("LCM> " + l.strip())
                return CommandResult(b), msg.decode("UTF-8")
            else:
                msg += bytes([b])

    def service_execute(self, command, data=None, response=False):
        if (command is None) or self.send8(command):
            if not data or self.send(data):
                result, message = self.service_command_get_result()
                if res