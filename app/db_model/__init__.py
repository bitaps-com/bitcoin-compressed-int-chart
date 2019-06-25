async def create_db_model(app, conn):

    level = await conn.fetchval("SHOW TRANSACTION ISOLATION LEVEL;")
    if level != "repeatable read":
        raise Exception("Postgres repeatable read isolation "
                        "level required! current isolation level is %s" % level)
    await conn.execute(open("./db_model/sql/schema.sql", "r", encoding='utf-8').read().replace("\n",""))

    app.start_block = await conn.fetchval("SELECT height FROM blocks ORDER BY height DESC LIMIT 1;")

