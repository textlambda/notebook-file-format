import sqlite3


def execute(connection, sql, params=()):
    rs = connection.execute(sql, params)
    return (dict(row) for row in rs.fetchall())


def execute_for_one(connection, sql, params=()):
    rows = list(execute(connection, sql, params))
    if len(rows) != 1:
        raise ValueError(f'Expected exactly one record from sql but got {len(rows)}:\n\n{sql}')

    return rows[0]


def connect(path):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection
