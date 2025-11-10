using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

public class DBManager {
    private SqliteConnection? connection = null;

    private string HashPassword(string password) {
        using (var algorithm = SHA256.Create()) {
            var bytes_hash = algorithm.ComputeHash(Encoding.Unicode.GetBytes(password));
            return Encoding.Unicode.GetString(bytes_hash);
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

        string REQUEST = "INSERT INTO users (Login, Password) VALUES ('" + login + "', '" + HashPassword(password) + "')";
        var command = new SqliteCommand(REQUEST, connection);

        int result = 0;
        try
        {
            result = command.ExecuteNonQuery();
        }
        catch (Exception exp) {
            Console.WriteLine(exp.Message);
            return false;
        }

        if (1 == result)
            return true;
        else
            return false;
    }

    public bool CheckUser(string login, string password) {
        if (null == connection)
            return false;

        if (connection.State != System.Data.ConnectionState.Open)
            return false;

        string REQUEST = "SELECT Login,Password FROM users WHERE Login='" + login + "' AND Password = '" + HashPassword(password) + "'";
        var command = new SqliteCommand(REQUEST, connection);

        try
        {
            var reader = command.ExecuteReader();

            if (reader.HasRows)
                return true;
            else
                return false;
        }
        catch (Exception exp) {
            Console.WriteLine(exp.Message);
            return false;
        }
    }
}