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
from pybtc import double_sha256
from math import ceil
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())



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

    def __init__(self, raw_tx=None, format="decoded", version=1,
                 lock_time=0, testnet=False, auto_commit=True, keep_raw_tx=False, c_int=False):
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
        if not c_int:
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
        else:
            # start deserialization
            n = read_c_int(stream)
            rtx(n)
            self["version"] = int_to_c_int(n)
            n = read_var_int(stream)
            rtx(n)
            if n == b'\x00':
                # segwit format
                sw = 1
                self["flag"] = read(1)
                rtx(self["flag"])
                n = read_c_int(stream)
                rtx(n)
            # inputs
            ic = int_to_c_int(n)

            for k in range(ic):
                self["vIn"][k] = dict()
                self["vIn"][k]["txId"] = read(32)
                rtx(self["vIn"][k]["txId"])
                n = read_c_int(stream)
                rtx(n)
                self["vIn"][k]["vOut"] = int_to_c_int(n)
                t = read_c_int(stream)
                rtx(t)
                self["vIn"][k]["scriptSig"] = read(int_to_c_int(t))
                rtx(self["vIn"][k]["scriptSig"])

                t = read_c_int(stream)
                rtx(t)
                self["vIn"][k]["sequence"] = 0xffffffff - int_to_c_int(t)
            # outputs
            t = read_c_int(stream)
            rtx(t)
            for k in range(int_to_c_int(t)):
                self["vOut"][k] = dict()
                t = read_c_int(stream)
                rtx(t)
                self["vOut"][k]["value"] = int_to_c_int(t)
                self["amount"] += self["vOut"][k]["value"]
                t = read_c_int(stream)
                self["vOut"][k]["scriptPubKey"] = read(int_to_c_int(t))
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
                t = read_c_int(stream)
                rtx(t)
                for c in range(int_to_c_int(t)):
                    l = read_c_int(stream)
                    rtx(l)
                    d = read(int_to_c_int(l))
                    rtx(d)
                    self["vIn"][k]["txInWitness"].append(d)

            sw_len = (stream.tell() - start) - sw + 2
        t = read_c_int(stream)
        rtx(t)
        self["lockTime"] = int_to_c_int(t)

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


class App:
    def __init__(self, loop, logger, connector_logger, config):
        self.loop = loop
        self.log = logger
        self.config = config
        self.psql_dsn = config["POSTGRESQL"]["dsn"]
        self.psql_threads = int(config["POSTGRESQL"]["pool_threads"])

        self.shutdown = False
        setproctitle('bitcoin chart')

        self.db_pool = None
        self.rpc = None
        self.connector = None
        self.timeline_size_c_int = 0
        self.timeline_size_v_int = 0
        self.block_batch = deque()
        self.start_block = 0
        self.total_tx = 0
        self.processes = []
        self.tasks = []
        self.log.info("starting ...")

        # remap SIGINT and SIGTERM
        signal.signal(signal.SIGINT, self.terminate)
        signal.signal(signal.SIGTERM, self.terminate)

        self.loop.create_task(self.start(config, connector_logger))

    async def start(self, config, connector_logger):
        # init database
        self.log.info("Create/check database model")
        try:
            self.db_pool = await asyncpg.create_pool(dsn=self.psql_dsn, min_size=1, max_size=self.psql_threads)
            async with self.db_pool.acquire() as conn:
                async with conn.transaction():
                    await db_model.create_db_model(self, conn)
            self.log.info("Connecting to bitcoind daemon ...")
            self.tasks.append(self.loop.create_task(self.commit()))

            self.connector = pybtc.Connector(config["CONNECTOR"]["rpc"],
                                             config["CONNECTOR"]["zeromq"],
                                             connector_logger,
                                             db_type="postgresql",
                                             db=self.psql_dsn,
                                             mempool_tx=False,
                                             last_block_height=self.start_block,
                                             block_batch_handler=self.block_batch_handler,
                                             tx_handler=self.new_transaction_handler,
                                             orphan_handler=self.orphan_block_handler,
                                             block_handler=self.new_block_handler,
                                             app_proc_title="bitcoin chart")
            await self.connector.connected
            self.log.info("Bitcoind connected, start app")

        except Exception as err:
            self.log.error("Start failed: %s" % err)
            self.log.error(str(traceback.format_exc()))
            self.terminate(None, None)




    async def block_batch_handler(self, block):
        size = block["size"]
        print(block["height"], size)
        size_c_int = 80 + len(int_to_c_int(len(block["rawTx"])))

        for t in block["rawTx"]:
            size_c_int += len(serialize_cint(block["rawTx"][t], hex=False))

        self.timeline_size_c_int += size_c_int
        self.timeline_size_v_int += size
        self.block_batch.append((block["height"],
                                 int(time.time()),
                                 size,
                                 self.timeline_size_v_int,
                                 size_c_int,
                                 self.timeline_size_c_int))
        if block["height"] % 10000 == 0:
            self.log.info("Blockchain blocks %s size %s cint_size %s " % (block["height"],
                                                                        self.timeline_size_v_int,
                                                                        self.timeline_size_c_int))
            self.log.info("diff  %s -> %s %%  " % (self.timeline_size_v_int - self.timeline_size_c_int,
                                                   round((self.timeline_size_v_int - self.timeline_size_c_int)
                                                         / self.timeline_size_v_int * 100, 2)))
            print(len(self.block_batch))


    async def commit(self):
        batch = None
        while True:
            if batch is None:
                batch = deque(self.block_batch)
                self.block_batch = deque()
            if batch:
                async with self.db_pool.acquire() as conn:
                    async with conn.transaction():

                        await conn.copy_records_to_table('blocks',
                                                         columns=["height", "timestamp",
                                                                  "size_c_int", "timeline_size_c_int",
                                                                  "size_v_int", "timeline_size_v_int"],
                                                         records=batch)
            else:
                await asyncio.sleep(1)
            batch = None



    async def orphan_block_handler(self, orphan_height):
        pass


    async def new_block_handler(self, block, conn):
        pass



    async def new_transaction_handler(self, tx, timestamp, conn):
        pass



    def _exc(self, a, b, c):
        return


    def terminate(self, a, b):
        if not self.shutdown:
            self.shutdown = True
            self.loop.create_task(self.terminate_coroutine())
        else:
            self.log.critical("Shutdown in progress please wait ...")


    async def terminate_coroutine(self):
        sys.excepthook = self._exc
        self.log.error('Stop request received')
        if self.connector:
            self.log.warning("Stop node connector")
            await self.connector.stop()

        self.log.warning('sync worker stop request received')
        [process.terminate() for process in self.processes]
        [task.cancel() for task in self.tasks]
        if self.tasks: await asyncio.wait(self.tasks)

        try: await self.db_pool.close()
        except: pass

        self.log.info("server stopped")
        self.loop.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="bitcoin compressed int chart v 0.0.1")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--config", help = "config file", type=str, nargs=1, metavar=('PATH',))
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="count", default=0)
    parser.add_argument("-w", "--connector", help="increase output verbosity for connector",
                        action="count",
                        default=0)
    args = parser.parse_args()
    config_file = "../config/bitcoin-compressed-int-chart.conf"
    log_level = logging.WARNING
    logger = logging.getLogger("server")
    logger_connector = logging.getLogger("connector")
    if args.config is not None:
        config_file = args.config[0]
    config = configparser.ConfigParser()
    config.read(config_file)
    if args.verbose > 0:
        log_level = logging.INFO
    if args.verbose > 1:
        log_level = logging.DEBUG

    connector_log_level = logging.INFO
    if args.connector > 0:
        connector_log_level = logging.WARNING
    if args.connector > 1:
        connector_log_level = logging.INFO
    if args.connector > 2:
        connector_log_level = logging.DEBUG

    ch = logging.StreamHandler()
    formatter = colorlog.ColoredFormatter('%(log_color) s%(asctime)s: %(message)s')
    formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s %(levelname)s: %(message)s (%(module)s:%(lineno)d)')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logger_connector.addHandler(ch)


    # check config
    try:
        config["CONNECTOR"]["zeromq"]
        config["CONNECTOR"]["rpc"]
        config["POSTGRESQL"]["dsn"]
        config["POSTGRESQL"]["pool_threads"]
        try:
            connector_log_level = log_level_map[config["CONNECTOR"]["log_level"]]
        except:
            pass

        try:
            log_level = log_level_map[config["SERVER"]["log_level"]]
        except:
            pass

    except Exception as err:
        logger.critical("Configuration failed: %s" % err)
        logger.critical("Shutdown")
        logger.critical(str(traceback.format_exc()))
        sys.exit(0)
    connector_log_level = logging.DEBUG
    log_level = logging.DEBUG
    logger.setLevel(log_level)
    logger_connector.setLevel(connector_log_level)
    loop = asyncio.get_event_loop()
    app = App(loop, logger, logger_connector, config)
    loop.run_forever()

    pending = asyncio.Task.all_tasks()
    for task in pending:
        task.cancel()
    if pending:
        loop.run_until_complete(asyncio.wait(pending))
    loop.close()

