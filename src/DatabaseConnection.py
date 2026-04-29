import sqlite3


class DatabaseConnection:
    def __init__(self, db_name):
        self.db_name = db_name
        self.conn = None
        self.cursor = None
        self.connect()

    def connect(self) -> None:
        try:
            self.conn = sqlite3.connect(self.db_name)
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.cursor = self.conn.cursor()
            #print(f"Connected to database: {self.db_name}")
            #print(self.conn.execute("SELECT file FROM pragma_database_list WHERE name = 'main';").fetchone()[0])
        except sqlite3.Error as e:
            print(f"Error connecting to database: {e}")

    def disconnect(self) -> None:
        if self.conn:
            self.cursor.close()
            self.conn.close()
            #print("Disconnected from database")

    def execute_query(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error executing query: {e}")
            print(query, end='\n\n')
            return None

    def execute_multi_query(self, query, data_list, params=()):
        try:
            self.execute_query("BEGIN IMMEDIATE")  # ACQUIRE DB LOCK
            self.cursor.executemany(query, data_list)
            self.conn.commit()
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            if str(e).__contains__('BEGIN IMMEDIATE'):
                pass
            else:
                print(f"Error executing query: {e}")
                return None

    def get_table_columns_tuple(self, table_columns: dict) -> tuple:

        if len(table_columns) == 1:
            key, = table_columns.keys()
            columns = '(\'' + key + '\')'
        else:
            columns = tuple([i for i in table_columns.keys() if i != 'id'])

        return columns

    def create_table(self, table_name, columns):
        column_definitions = ", ".join([f"{name} {data_type}" for name, data_type in columns.items()])
        query = f'CREATE TABLE IF NOT EXISTS "{table_name}" ({column_definitions});'
        self.execute_query(query)

    def clear_table(self, table_name):
        if self.table_exists(table_name):
            self.execute_query(f'DELETE FROM "{table_name}";')

            if self.table_exists('SQLITE_SEQUENCE'):
                self.execute_query(f'DELETE FROM SQLITE_SEQUENCE WHERE name="{table_name}";')

    def delete_table(self, table_name):

        if self.table_exists(table_name):
            self.execute_query(f'DROP TABLE IF EXISTS "{table_name}";')

    def insert_data_list(self, table_name, table_columns, data):


            columns = self.get_table_columns_tuple(table_columns)
            mask = '?,' * (len(columns) - 1) + '?'

            query = f'INSERT INTO "{table_name}" {columns} VALUES ({mask})'
            self.execute_multi_query(query, data)


    def insert_binary_data(self, table_name, table_columns, data):
        columns = self.get_table_columns_tuple(table_columns)
        mask = '?,' * (len(columns) - 1) + '?'

        query = f'INSERT INTO "{table_name}" {columns} VALUES ({mask})'
        binary = []
        no_binary = []

        for value in data.values():
            if isinstance(value, bytes):
                binary.append(value)
            else:
                no_binary.append(value)

        self.cursor.execute(query, (*[sqlite3.Binary(value,) for value in binary], *no_binary))
        self.conn.commit()

    def insert_data(self, table_name, table_columns, data, condition=None):

        columns = self.get_table_columns_tuple(table_columns)
        query = f'INSERT INTO "{table_name}" {columns} VALUES (?)'
        if condition:
            query += f" WHERE {condition}"

        return self.execute_query(query, data)

    def select_data(self, table_name, table_columns="*", condition=None):
        query = f"SELECT {table_columns} FROM {table_name}"
        if condition:
            query += f" WHERE {condition}"
        return self.execute_query(query)

    def update_data(self, table_name, data, condition=None):
        set_values = ", ".join([f"{key} = ?" for key in data.keys()])
        query = f"UPDATE {table_name} SET {set_values}"
        if condition:
            query += f"WHERE {condition}"
        self.execute_query(query, tuple(data.values()))

    def delete_data(self, table_name, condition):
        query = f"DELETE FROM {table_name} WHERE {condition}"
        self.execute_query(query)

    def table_exists(self, table_name):
        db_table_exists = self.execute_query(
            f'SELECT * FROM sqlite_master WHERE type="table" and name="{table_name}";')
        if len(db_table_exists) > 0:
            return True
        return False

    def __del__(self):
        self.disconnect()
