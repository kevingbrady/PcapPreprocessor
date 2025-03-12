import sqlite3


class DatabaseAPI:
    def __init__(self, db_name):
        self.db_name = db_name
        self.conn = None
        self.cursor = None

    def connect(self):
        try:
            self.conn = sqlite3.connect(self.db_name)
            self.cursor = self.conn.cursor()
            #print(f"Connected to database: {self.db_name}")
            #print(self.conn.execute("SELECT file FROM pragma_database_list WHERE name = 'main';").fetchone()[0])
        except sqlite3.Error as e:
            print(f"Error connecting to database: {e}")

    def disconnect(self):
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
            self.cursor.executemany(query, data_list)
            self.conn.commit()
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Error executing query: {e}")
            return None

    def create_table(self, table_name, columns):
        column_definitions = ", ".join([f"{name} {data_type}" for name, data_type in columns.items()])
        query = f'CREATE TABLE IF NOT EXISTS "{table_name}" ({column_definitions});'
        self.execute_query(query)

    def insert_data(self, table_name, data):

        query = f'INSERT INTO "{table_name}" (graphs, timestamp) VALUES (?, ?)'
        self.execute_multi_query(query, data)

    def select_data(self, table_name, columns="*", condition=None):
        query = f"SELECT {columns} FROM {table_name}"
        if condition:
            query += f" WHERE {condition}"
        return self.execute_query(query)

    def update_data(self, table_name, data, condition):
        set_values = ", ".join([f"{key} = ?" for key in data.keys()])
        query = f"UPDATE {table_name} SET {set_values} WHERE {condition}"
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
