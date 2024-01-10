import base64
import getpass
import json
import sys

import db
import cipher


def read_peek(connection) -> dict:
    record = db.execute_for_one(connection, 'SELECT * FROM peek WHERE id=?', [1])
    meta = json.loads(record['meta'])
    meta['salt'] = base64.b64decode(meta['salt'])
    meta['subkey-context'] = meta['subkey-context'].encode()

    record['meta'] = meta
    return record


def get_entry_history(connection, ekey, entry_id):
    sql = """
    SELECT
      id,
      entry_id,
      encrypted_value,
      strftime('%Y-%m-%dT%H:%M:%S', modified) AS modified
    FROM
      entry_history
    WHERE
      entry_id=?
    """

    for x in db.execute(connection, sql, [entry_id]):
        value = cipher.decrypt(ekey, x['encrypted_value']).decode() if x['encrypted_value'] else None

        yield dict(id=x['id'],
                   value=value,
                   modified=x['modified'])


def get_entries(connection, ekey):
    sql = """
    SELECT
      id,
      parent_id,
      encrypted_name,
      encrypted_value,
      deleted,
      strftime('%Y-%m-%dT%H:%M:%S', modified) AS modified
    FROM
      entry
    """

    for x in db.execute(connection, sql):
        name = cipher.decrypt(ekey, x['encrypted_name']).decode()
        value = cipher.decrypt(ekey, x['encrypted_value']).decode() if x['encrypted_value'] else None

        yield dict(id=x['id'],
                   parent_id=x['parent_id'],
                   name=name,
                   value=value,
                   deleted=x['deleted'] == 1,
                   modified=x['modified'])


if __name__ == '__main__':
    if (len(sys.argv) != 2):
        print(f'Syntax: {sys.argv[0]} notebook-file-path')
        sys.exit(1)

    notebook_path = sys.argv[1]
    connection = db.connect(notebook_path)

    peek = read_peek(connection)
    passphrase = getpass.getpass(prompt='Passphrase: ')

    try:
        ekey = cipher.get_ekey(peek, passphrase.encode())
    except cipher.InvalidPassphrase:
        print('Invalid passphrase')
        sys.exit(1)

    entries = list(get_entries(connection, ekey))
    connection.close()

    print(json.dumps(entries, indent=2))
