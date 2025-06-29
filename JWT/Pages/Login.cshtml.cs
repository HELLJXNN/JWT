using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using JWT.Services;
using Microsoft.Extensions.Configuration;

namespace JWT.Pages
{
    public class LoginModel : PageModel
    {
        private readonly JwtService _jwtService;
        private readonly IConfiguration _configuration;

        [BindProperty]
        public string Username { get; set; } = string.Empty;

        [BindProperty]
        public string Password { get; set; } = string.Empty;

        public string ErrorMessage { get; set; } = string.Empty;

        public LoginModel(JwtService jwtService, IConfiguration configuration)
        {
            _jwtService = jwtService;
            _configuration = configuration;
        }

        public void OnGet()
        {
            Console.WriteLine("=== LOGIN GET - LIMPIEZA COMPLETA ===");

            // Limpieza exhaustiva del lado del servidor
            ClearAllCookieVariations();

            Console.WriteLine("Limpieza del servidor completada");
        }

        public IActionResult OnPost()
        {
            Console.WriteLine("=== LOGIN POST INICIADO ===");
            Console.WriteLine($"Usuario: {Username}");

            // Limpieza ANTES de crear el nuevo token
            ClearAllCookieVariations();

            // Esperar un poco para asegurar limpieza
            System.Threading.Thread.Sleep(200);

            if (Username == "admin" && Password == "password")
            {
                try
                {
                    var token = _jwtService.GenerateToken(Username);
                    Console.WriteLine($"Nuevo token generado: {token.Substring(0, 50)}...");

                    if (!int.TryParse(_configuration.GetSection("Jwt")["ExpirationMinutes"], out int expirationMinutes))
                    {
                        ErrorMessage = "Error de configuración de la expiración del token.";
                        return Page();
                    }

                    var cookieExpiration = DateTime.UtcNow.AddMinutes(expirationMinutes);

                    // Establecer la nueva cookie con configuración limpia
                    Response.Cookies.Append("jwtToken", token, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = false, // Cambiar a true en producción
                        IsEssential = true,
                        Expires = cookieExpiration,
                        Path = "/",
                        SameSite = SameSiteMode.Lax
                    });

                    Console.WriteLine($"Nueva cookie establecida, expira: {cookieExpiration}");

                    // Esperar un poco antes de redirigir
                    System.Threading.Thread.Sleep(100);

                    return RedirectToPage("/Protected");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error generando token: {ex.Message}");
                    ErrorMessage = "Error interno al generar el token.";
                    return Page();
                }
            }
            else
            {
                Console.WriteLine("Credenciales incorrectas");
                ErrorMessage = "Credenciales incorrectas.";
                return Page();
            }
        }

        private void ClearAllCookieVariations()
        {
            // Lista de todas las posibles configuraciones de cookies a limpiar
            var cookieOptions = new[]
            {
                new CookieOptions { Path = "/", Secure = false, SameSite = SameSiteMode.Lax },
                new CookieOptions { Path = "/", Secure = true, SameSite = SameSiteMode.Lax },
                new CookieOptions { Path = "/", Secure = false, SameSite = SameSiteMode.Strict },
                new CookieOptions { Path = "/", Secure = true, SameSite = SameSiteMode.Strict },
                new CookieOptions { Path = "/", Secure = false, SameSite = SameSiteMode.None },
                new CookieOptions { Path = "/", Secure = true, SameSite = SameSiteMode.None },
                new CookieOptions { Path = "/Login", Secure = false, SameSite = SameSiteMode.Lax },
                new CookieOptions { Path = "/Protected", Secure = false, SameSite = SameSiteMode.Lax }
            };

            var cookieNames = new[] { "jwtToken", "jwt", "token", "auth" };

            foreach (var name in cookieNames)
            {
                foreach (var option in cookieOptions)
                {
                    try
                    {
                        Response.Cookies.Delete(name, option);

                        // También establecer cookie vacía con fecha pasada
                        var expiredOption = new CookieOptions
                        {
                            Path = option.Path,
                            Secure = option.Secure,
                            SameSite = option.SameSite,
                            Expires = DateTime.UtcNow.AddDays(-1)
                        };
                        Response.Cookies.Append(name, "", expiredOption);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error limpiando cookie {name}: {ex.Message}");
                    }
                }
            }
        }
    }
}
