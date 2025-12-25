using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/auth";           // Куда редиректить при отсутствии авторизации
        options.AccessDeniedPath = "/auth";     // Куда редиректить при запрете доступа
    });

var app = builder.Build();
app.UseStaticFiles(); 
app.UseAuthentication();
app.UseAuthorization();

RGWebAdapter rg = new RGWebAdapter();

const string DB_PATH = "users.db";

app.MapGet("/", () => "Vigenere Cipher Web API");

app.MapPost("/encrypt", (string text, string key) => rg.Encrypt(text, key))
    .RequireAuthorization();

app.MapPost("/decrypt", (string text, string key) => rg.Decrypt(text, key))
    .RequireAuthorization();

app.MapPost("/login", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    string login = form["login"];
    string password = form["password"];

    if (!rg.db.CheckUser(login, password))
        return Results.Redirect("/auth?error=1");

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, login)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

    ClientLogger.Log("LOGIN_SUCCESS", login);

    return Results.Redirect("/vigenere");
});

app.MapGet("/check_user", [Authorize] (HttpContext context) => {
    if (context.User.Identity == null) 
        return Results.BadRequest("User is unknown");
    return Results.Ok(context.User.Identity.Name);
});

app.MapPost("/signup", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    string login = form["login"];
    string password = form["password"];

    if (!rg.db.AddUser(login, password))
        return Results.Redirect("/auth?reg_error=1");

    ClientLogger.Log("REGISTER", login);

    return Results.Redirect("/auth?reg_ok=1");
});

app.MapGet("/vigenere", async context =>
{
    await context.Response.SendFileAsync("vigenere_client.html");
}).RequireAuthorization();



if (!rg.db.ConnectToDB(DB_PATH))
{
    Console.WriteLine("Failed to connect to db " + DB_PATH);
    Console.WriteLine("Shutdown!");
    return;
}

app.MapGet("/auth", async context =>
{
    await context.Response.SendFileAsync("auth.html");
});

app.Run();
rg.db.Disconnect();


// ======================= ЛОГИКА ШИФРА ВИЖЕНЕРА =============================
public class VigenereCipher
{
    private const string engAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string rusAlphabet = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    private static readonly string fullAlphabet = engAlphabet + rusAlphabet.ToLower() + rusAlphabet + engAlphabet.ToLower();

    private char ProcessChar(char c, char k, bool encrypt)
    {
        char upperC = char.ToUpper(c);
        char upperK = char.ToUpper(k);

        int alphabetIndex = -1;
        char baseAlphabetChar = '\0';

        if (engAlphabet.Contains(upperC))
        {
            alphabetIndex = engAlphabet.IndexOf(upperC);
            baseAlphabetChar = 'A';
        }
        else if (rusAlphabet.Contains(upperC))
        {
            alphabetIndex = rusAlphabet.IndexOf(upperC);
            baseAlphabetChar = 'А';
        }

        if (alphabetIndex == -1)
            return c;

        int keyIndex = fullAlphabet.IndexOf(upperK);
        if (keyIndex == -1)
            return c;

        int keyShift;
        if (keyIndex < engAlphabet.Length)
            keyShift = keyIndex;
        else if (keyIndex < engAlphabet.Length + rusAlphabet.Length * 2)
            keyShift = keyIndex - engAlphabet.Length - rusAlphabet.Length; 
        else
            keyShift = keyIndex - engAlphabet.Length - rusAlphabet.Length * 2;

        if (rusAlphabet.Contains(upperK))
            keyShift = rusAlphabet.IndexOf(upperK);
        else
            keyShift = engAlphabet.IndexOf(upperK);

        int shift = encrypt ? keyShift : -keyShift;
        int newIndex = (alphabetIndex + shift + (rusAlphabet.Contains(upperC) ? rusAlphabet.Length : engAlphabet.Length)) % 
                       (rusAlphabet.Contains(upperC) ? rusAlphabet.Length : engAlphabet.Length);

        char result = (rusAlphabet.Contains(upperC) ? rusAlphabet : engAlphabet)[newIndex];

        return char.IsLower(c) ? char.ToLower(result) : result;
    }

    public string Encrypt(string text, string key)
    {
        if (string.IsNullOrEmpty(text)) return text;
        if (string.IsNullOrEmpty(key)) return text;

        string result = "";
        int keyIndex = 0;

        foreach (char c in text)
        {
            if (char.IsLetter(c))
            {
                char keyChar = key[keyIndex % key.Length];
                result += ProcessChar(c, keyChar, true);
                keyIndex++;
            }
            else
            {
                result += c; 
            }
        }

        return result;
    }

    public string Decrypt(string text, string key)
    {
        if (string.IsNullOrEmpty(text)) return text;
        if (string.IsNullOrEmpty(key)) return text;

        string result = "";
        int keyIndex = 0;

        foreach (char c in text)
        {
            if (char.IsLetter(c))
            {
                char keyChar = key[keyIndex % key.Length];
                result += ProcessChar(c, keyChar, false);
                keyIndex++;
            }
            else
            {
                result += c;
            }
        }

        return result;
    }
}


// ====================== АДАПТЕР К WEB ==========================
public class RGWebAdapter {
    private VigenereCipher cipher = new VigenereCipher();
    public DBManager db = new DBManager();
    public IResult Encrypt(string text, string key) {
        return Results.Ok(cipher.Encrypt(text, key));
    }

    public IResult Decrypt(string text, string key) {
        return Results.Ok(cipher.Decrypt(text, key));
    }
}

public static class ClientLogger
{
    private static readonly string path = "client.log";

    public static void Log(string action, string? user = null)
    {
        string line = $"{DateTime.Now:u} | {action} | {user}";
        File.AppendAllText(path, line + Environment.NewLine);
    }
}