async def create_db_model(app, conn):
    await conn.execute(open("./db_model/sql/schema.sql", "r", encoding='utf-8').read().replace("\n",""))
    app.start_block = await conn.fetchval("SELECT height FROM blocks ORDER BY height DESC LIMIT 1;")
    if app.start_block is None:
        app.start_block = 0

