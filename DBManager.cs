using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

public class DBManager {
    private SqliteConnection? connection = null;

    private string HashPassword(string password) {
        using (var algorithm = SHA256.Create()) {
            var bytes_hash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(bytes_hash);
        }
    }

    public bool ConnectToDB(string path) {
        Console.WriteLine("Connection to db...");

        try
        {
            connection = new SqliteConnection("Data Source=" + path);
            connection.Open();

            if (connection.State != System.Data.ConnectionState.Open) {
                Console.WriteLine("Failed!");
                return false;
            }
            
            string createTableQuery = @"
                CREATE TABLE IF NOT EXISTS users (
                    Login TEXT PRIMARY KEY,
                    Password TEXT NOT NULL
                )";
            using (var command = new SqliteCommand(createTableQuery, connection))
            {
                command.ExecuteNonQuery();
            }
        }
        catch (Exception exp) {
            Console.WriteLine(exp.Message);
            return false;
        }

        Console.WriteLine("Done!");
        return true;
    }

    public void Disconnect() {
        if (null == connection)
            return;

        if (connection.State != System.Data.ConnectionState.Open)
            return;

        connection.Close();

        Console.WriteLine("Disconnect from db");
    }

    public bool AddUser(string login, string password) {
        if (null == connection)
            return false;

        if (connection.State != System.Data.ConnectionState.Open)
            return false;

        string request = "INSERT INTO users (Login, Password) VALUES (@login, @password)";
        using (var command = new SqliteCommand(request, connection))
        {
            command.Parameters.AddWithValue("@login", login);
            command.Parameters.AddWithValue("@password", HashPassword(password));

            try
            {
                int result = command.ExecuteNonQuery();
                return result == 1;
            }
            catch (Exception exp) {
                Console.WriteLine(exp.Message);
                return false;
            }
        }
    }

    public bool CheckUser(string login, string password) {
        if (null == connection)
            return false;

        if (connection.State != System.Data.ConnectionState.Open)
            return false;

        string request = "SELECT Login FROM users WHERE Login = @login AND Password = @password";
        using (var command = new SqliteCommand(request, connection))
        {
            command.Parameters.AddWithValue("@login", login);
            command.Parameters.AddWithValue("@password", HashPassword(password));

            try
            {
                using (var reader = command.ExecuteReader())
                {
                    return reader.HasRows;
                }
            }
            catch (Exception exp) {
                Console.WriteLine(exp.Message);
                return false;
            }
        }
    }
}