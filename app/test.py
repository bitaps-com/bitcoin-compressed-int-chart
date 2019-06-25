import argparse
import asyncio
import configparser
import logging
import signal
import sys
import traceback
from setproctitle import setproctitle
import time
import asyncpg
import colorlog
import pybtc
import db_model
from collections import deque
from struct import pack, unpack
from pybtc import int_to_c_int, var_int_to_int, parse_script, int_to_var_int, read_var_int
from pybtc import double_sha256, bytes_from_hex, c_int_to_int
from io import BytesIO
from math import ceil
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

t = "02000000000101dc6f54b6cc74fb9af31668b4b5645660f68a7fa316a267789861add94c8523a31000000017160014629389ff9ecd43c89237c80e1a49a5cc5afee034feffffff02b8161300000000001976a914d09cf298d0220e71014ef1e4491775e4dd4ddb1388ac9f6db6010000000017a914b5589f80cd065c67731cbe7d9e71d218ab279784870247304402204f4273b655ad55d93af5d6da4a27d2a76e204965f63aae6f091ba873c314392202202d02d6dc6b9e70b343d0776a59679257ed93adeb9c5cfb2b8311676d016539dd012103ed461f3ae8d91d3dd9e2897844129caf4bdeb1ffaedc62beb38251f9742ddc2df8e20800"




def read_c_int(stream, base_bytes=1):
    """
    Convert compressed integer bytes to integer

    :param b: compressed integer bytes.
    :param base_bytes: len of bytes base from which start compression.
    :return: integer.
    """
    b = bytearray(stream.read(1))
    byte_length = f = 0
    while True:
        v = b[f]
        if v == 0xff:
            byte_length += 8
            f += 1
            b += stream.read(1)
            continue
        while v & 0b10000000:
            byte_length += 1
            v = v << 1
        break
    b += stream.read(byte_length+base_bytes - f)
    return b


class Transaction(dict):
    """
    The class for Transaction object

    :param raw_tx: (optional) raw transaction in bytes or HEX encoded string, if no raw transaction provided
                well be created new empty transaction template.
    :param tx_format: "raw" or "decoded" format. Raw format is mean that all transaction represented in bytes
                      for best performance.
                      Decoded transaction is represented in human readable format using base68, hex, bech32,
                      asm and opcodes. By default "decoded" format using.
    :param int version: transaction version for new template, by default 1.
    :param int lock_time: transaction lock time for new template, by default 0.
    :param boolean testnet: address type for "decoded" transaction representation.

    """

    def __init__(self, raw_tx=None, format="raw", version=1,
                 lock_time=0, testnet=False, auto_commit=True, keep_raw_tx=False):
        if format not in ("decoded", "raw"):
            raise ValueError("format error, raw or decoded allowed")
        self.auto_commit = auto_commit
        self["format"] = format
        self["testnet"] = testnet
        self["segwit"] = False
        self["txId"] = None
        self["hash"] = None
        self["version"] = version
        self["size"] = 0
        self["vSize"] = 0
        self["bSize"] = 0
        self["lockTime"] = lock_time
        self["vIn"] = dict()
        self["vOut"] = dict()
        self["rawTx"] = None
        self["blockHash"] = None
        self["confirmations"] = None
        self["time"] = None
        self["blockTime"] = None
        self["blockIndex"] = None
        self["coinbase"] = False
        self["fee"] = None
        self["data"] = None
        self["amount"] = None
        if raw_tx is None:
            return

        self["rawTx"] = deque()
        rtx = self["rawTx"].append
        self["amount"] = 0
        sw = sw_len = 0
        stream = self.get_stream(raw_tx)
        start = stream.tell()
        read = stream.read
        tell = stream.tell
        # start deserialization
        t = read(4)
        rtx(t)
        self["version"] = unpack('<L', t)[0]
        n = read_var_int(stream)
        rtx(n)
        if n == b'\x00':
            # segwit format
            sw = 1
            self["flag"] = read(1)
            rtx(self["flag"])
            n = read_var_int(stream)
            rtx(n)
        # inputs
        ic = var_int_to_int(n)

        for k in range(ic):
            self["vIn"][k] = dict()
            self["vIn"][k]["txId"] = read(32)
            rtx(self["vIn"][k]["txId"])
            t = read(4)
            rtx(t)
            self["vIn"][k]["vOut"] = unpack('<L', t)[0]
            t = read_var_int(stream)
            rtx(t)
            self["vIn"][k]["scriptSig"] = read(var_int_to_int(t))
            rtx(self["vIn"][k]["scriptSig"])
            t = read(4)
            rtx(t)
            self["vIn"][k]["sequence"] = unpack('<L', t)[0]
        # outputs
        t = read_var_int(stream)
        rtx(t)
        for k in range(var_int_to_int(t)):
            self["vOut"][k] = dict()
            t = read(8)
            self["vOut"][k]["value"] = unpack('<Q', t)[0]
            rtx(t)
            self["amount"] += self["vOut"][k]["value"]
            t = read_var_int(stream)
            self["vOut"][k]["scriptPubKey"] = read(var_int_to_int(t))
            rtx(t)
            rtx(self["vOut"][k]["scriptPubKey"])
            s = parse_script(self["vOut"][k]["scriptPubKey"])
            self["vOut"][k]["nType"] = s["nType"]
            self["vOut"][k]["type"] = s["type"]
            if self["data"] is None:
                if s["nType"] == 3:
                    self["data"] = s["data"]
            if s["nType"] not in (3, 4, 7, 8):
                self["vOut"][k]["addressHash"] = s["addressHash"]
                self["vOut"][k]["reqSigs"] = s["reqSigs"]

        # witness
        if sw:
            sw = tell() - start
            for k in range(ic):
                self["vIn"][k]["txInWitness"] = []
                t = read_var_int(stream)
                rtx(t)
                for c in range(var_int_to_int(t)):
                    l = read_var_int(stream)
                    rtx(l)
                    d = read(var_int_to_int(l))
                    rtx(d)
                    self["vIn"][k]["txInWitness"].append(d)

            sw_len = (stream.tell() - start) - sw + 2
        t = read(4)
        rtx(t)
        self["lockTime"] = unpack('<L', t)[0]

        end = tell()
        self["rawTx"] = b"".join(self["rawTx"])
        self["size"] = end - start
        self["bSize"] = end - start - sw_len
        self["weight"] = self["bSize"] * 3 + self["size"]
        self["vSize"] = ceil(self["weight"] / 4)
        if ic == 1 and \
                        self["vIn"][0]["txId"] == b'\x00' * 32 and \
                        self["vIn"][0]["vOut"] == 0xffffffff:
            self["coinbase"] = True
        else:
            self["coinbase"] = False
        if sw:
            self["segwit"] = True
            self["hash"] = double_sha256(self["rawTx"])
            self["txId"] = double_sha256(b"".join((self["rawTx"][:4], self["rawTx"][6:sw], self["rawTx"][-4:])))
        else:
            self["segwit"] = False
            self["txId"] = double_sha256(self["rawTx"])
            self["hash"] = self["txId"]
        if not keep_raw_tx:
            self["rawTx"] = None

        if self["format"] == "decoded":
            self.decode()

    def serialize_cint(self, segwit=True):
        chunks = []
        append = chunks.append
        append(int_to_c_int(self["version"]))
        if segwit and self["segwit"]:
            append(b"\x00\x01")
        append(int_to_c_int(len(self["vIn"])))
        for i in self["vIn"]:
            append(self["vIn"][i]['txId'])
            append(int_to_c_int(self["vIn"][i]['vOut']))
            append(int_to_c_int(len(self["vIn"][i]['scriptSig'])))
            append(self["vIn"][i]['scriptSig'])
            append(int_to_c_int(0xffffffff - self["vIn"][i]['sequence']))
        append(int_to_c_int(len(self["vOut"])))
        for i in self["vOut"]:
            append(int_to_c_int(self["vOut"][i]['value']))
            append(int_to_c_int(len(self["vOut"][i]['scriptPubKey'])))
            append(self["vOut"][i]['scriptPubKey'])
        if segwit and self["segwit"]:
            for i in self["vIn"]:
                append(int_to_c_int(len(self["vIn"][i]['txInWitness'])))
                for w in self["vIn"][i]['txInWitness']:
                    append(int_to_c_int(len(w)))
                    append(w)

        append(int_to_c_int(self['lockTime']))
        return b''.join(chunks)

    def serialize(self, segwit=True, hex=True):
        chunks = []
        append = chunks.append
        append(pack('<L', self["version"]))
        if segwit and self["segwit"]:
            append(b"\x00\x01")
        append(int_to_var_int(len(self["vIn"])))
        for i in self["vIn"]:
            append(self["vIn"][i]['txId'])
            append(pack('<L', self["vIn"][i]['vOut']))
            append(int_to_var_int(len(self["vIn"][i]['scriptSig'])))
            append(self["vIn"][i]['scriptSig'])
            append(pack('<L', self["vIn"][i]['sequence']))
        append(int_to_var_int(len(self["vOut"])))
        for i in self["vOut"]:
            append(pack('<Q', self["vOut"][i]['value']))
            append(int_to_var_int(len(self["vOut"][i]['scriptPubKey'])))
            append(self["vOut"][i]['scriptPubKey'])

        if segwit and self["segwit"]:
            for i in self["vIn"]:
                append(int_to_var_int(len(self["vIn"][i]['txInWitness'])))
                for w in self["vIn"][i]['txInWitness']:
                    append(int_to_var_int(len(w)))
                    append(w)
        append(pack('<L', self['lockTime']))
        return b''.join(chunks)

    @staticmethod
    def get_stream(stream):
        if type(stream) != BytesIO:
            if type(stream) == str:
                stream = bytes_from_hex(stream)
            if type(stream) == bytes:
                stream = BytesIO(stream)
            else:
                raise TypeError
        return stream

k = Transaction(t)

from pprint import pprint

pprint(k)

print(k/2,len(k.serialize()), len(k.serialize_cint()))