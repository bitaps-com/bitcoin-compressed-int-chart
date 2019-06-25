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

import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


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
            self.log.info("Bitcoind connected")

        except Exception as err:
            self.log.error("Start failed: %s" % err)
            self.log.error(str(traceback.format_exc()))
            self.terminate(None, None)




    async def block_batch_handler(self, block):
        pass



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

