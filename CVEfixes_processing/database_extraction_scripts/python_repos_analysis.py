import mysql.connector
from mysql.connector import Error
import git
from save_json_and_text import save_repos_text, save_repos_json


def get_fixes_from_database():
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host='localhost',  # Replace with your MySQL host
            user='root',  # Replace with your MySQL username
            password='omar',  # Replace with your MySQL password
            database='CVE_fixes'  # Replace with your database name
        )

        # Check if the connection was successful
        # print(connection)
        if connection.is_connected():
            cursor = connection.cursor()

            # Query to get the content of the fixes table
            cursor.execute("SELECT url, name FROM repository")
            fixes = cursor.fetchall()

            save_repos_json(fixes)
            save_repos_text(fixes)

    except Error as e:
        print(f"An error occurred: {e}")
    finally:
        if connection.is_connected():
            # Close the database connection
            cursor.close()
            connection.close()

if __name__ == "__main__":
    get_fixes_from_database()