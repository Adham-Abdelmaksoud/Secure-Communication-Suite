import sqlite3
import io
import numpy as np


class Database:
    conn = None

    @staticmethod
    def getconnection(db_file=r"sqlite/db/database.db") -> sqlite3.Connection:
        """ Create a database connection to a SQLITE database """
        try:
            if Database.conn is None:
                Database.conn = sqlite3.connect(db_file)
                cur = Database.conn.cursor()
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS User(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username VARCHAR(256) NOT NULL,
                    pass VARCHAR(256) NOT NULL
                    )
                    """
                )
            else:
                Database.conn = sqlite3.connect(db_file)
        except sqlite3.Error as e:
            print(e)
        return Database.conn

    
