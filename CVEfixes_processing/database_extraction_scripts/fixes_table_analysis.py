import mysql.connector
from mysql.connector import Error
import git
from CVEfixes.save_json_and_text import save_fixes_to_json, save_fixes_to_text
# repo_url = "https://github.com/django/django.git"
# repo_path = "/path/to/clone/repo"
# repo = git.Repo.clone_from(repo_url, repo_path)

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
            cursor.execute("SELECT * FROM fixes")
            fixes = cursor.fetchall()

            # get_changes_commit(fixes)
            
            # Print the content of the fixes table
            # for fix in fixes:
            #     print(fix)
            #     break
            save_fixes_to_json(fixes)
            save_fixes_to_text(fixes)

    except Error as e:
        print(f"An error occurred: {e}")
    finally:
        if connection.is_connected():
            # Close the database connection
            cursor.close()
            connection.close()

if __name__ == "__main__":
    get_fixes_from_database()