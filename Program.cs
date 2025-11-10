using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseStaticFiles(); 
app.UseAuthentication();
app.UseAuthorization();

RGWebAdapter rg = new RGWebAdapter();

app.MapGet("/", () => "Vigenere Cipher Web API");

app.MapPost("/encrypt", (string text, string key) => rg.Encrypt(text, key));
app.MapPost("/decrypt", (string text, string key) => rg.Decrypt(text, key));

app.MapPost("/login", (string login, string password, HttpContext context) => rg.LogIn(login, password, context));

app.MapGet("/check_user", [Authorize] (HttpContext context) => {
    if (context.User.Identity == null) 
        return Results.BadRequest("User is unknown");
    return Results.Ok(context.User.Identity.Name);
});

app.MapPost("/signup", (string login, string password) =>
{
    if (rg.db.AddUser(login, password))
        return Results.Ok("User " + login + " registered successfully!");
    else
        return Results.Problem("Failed to register user " + login);
});

app.MapGet("/vigenere", async context =>
{
    await context.Response.SendFileAsync("D:/VPN/Курсач ОП/Client/vigenere_client.html");
});

app.MapPost("/picture", (HttpRequest request) => {
    try
    {
        var memoryStream = new MemoryStream();
        request.Body.CopyToAsync(memoryStream).Wait();
        memoryStream.Seek(0, SeekOrigin.Begin);
        Image image = Image.Load<Rgba32>(memoryStream);
        return Results.Ok("Received image " + image.Width + "x" + image.Height);
    }
    catch (Exception exp)
    {
        return Results.BadRequest("Wrong image format: " + exp.Message);
    }
});

app.MapPost("/picture_form", ([FromForm] UploadImageModel model) => {
    if (model.picture == null || model.picture.Length == 0)
        return Results.BadRequest(new { message = "Файл изображения не найден или пуст." });

    try
    {
        var memoryStream = new MemoryStream();
        model.picture.CopyToAsync(memoryStream).Wait();
        memoryStream.Seek(0, SeekOrigin.Begin);
        Image image = Image.Load<Rgba32>(memoryStream);
        return Results.Ok("Received image " + image.Width + "x" + image.Height);
    }
    catch (Exception exp)
    {
        return Results.BadRequest("Wrong image format: " + exp.Message);
    }
}).DisableAntiforgery();

const string DB_PATH = "D:/VPN/Курсач ОП/Client/users.db";
if (!rg.db.ConnectToDB(DB_PATH))
{
    Console.WriteLine("Failed to connect to db " + DB_PATH);
    Console.WriteLine("Shutdown!");
    return;
}

app.MapGet("/auth", async context =>
{
    await context.Response.SendFileAsync("D:/VPN/Курсач ОП/Client/auth.html");
});

app.Run();
rg.db.Disconnect();


// ======================= ЛОГИКА ШИФРА ВИЖЕНЕРА =============================
public class VigenereCipher
{
    private const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private char EncodeChar(char c, char k)
    {
        int pi = alphabet.IndexOf(char.ToUpper(c));
        int ki = alphabet.IndexOf(char.ToUpper(k));
        if (pi == -1) return c;
        return alphabet[(pi + ki) % 26];
    }

    private char DecodeChar(char c, char k)
    {
        int ci = alphabet.IndexOf(char.ToUpper(c));
        int ki = alphabet.IndexOf(char.ToUpper(k));
        if (ci == -1) return c;
        return alphabet[(ci - ki + 26) % 26];
    }

    public string Encrypt(string text, string key)
    {
        string result = "";
        int keyIndex = 0;
        foreach (char c in text)
        {
            result += EncodeChar(c, key[keyIndex]);
            keyIndex = (keyIndex + 1) % key.Length;
        }
        return result;
    }

    public string Decrypt(string text, string key)
    {
        string result = "";
        int keyIndex = 0;
        foreach (char c in text)
        {
            result += DecodeChar(c, key[keyIndex]);
            keyIndex = (keyIndex + 1) % key.Length;
        }
        return result;
    }
}


// ====================== АДАПТЕР К WEB ==========================
public class RGWebAdapter {
    private VigenereCipher cipher = new VigenereCipher();
    public DBManager db = new DBManager();

    public async Task<IResult> LogIn(string login, string password, HttpContext context) {
        if (db.CheckUser(login, password)) {
            var claims = new List<Claim> { new Claim(ClaimTypes.Name, login) };
            var claimsIdentity = new ClaimsIdentity(claims, "Cookies");
            await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
            return Results.Ok();
        }
        return Results.Unauthorized();
    }

    public IResult Encrypt(string text, string key) {
        return Results.Ok(cipher.Encrypt(text, key));
    }

    public IResult Decrypt(string text, string key) {
        return Results.Ok(cipher.Decrypt(text, key));
    }
}


// ===================== МОДЕЛЬ ДЛЯ КАРТИНОК ====================
public class UploadImageModel
{
    public IFormFile picture { get; set; } = default!;
}
