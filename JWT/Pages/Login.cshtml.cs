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
            // IMPORTANTE: Limpiar cualquier cookie existente al cargar la página de login
            Console.WriteLine("=== LOGIN GET - Limpiando cookies existentes ===");

            if (Request.Cookies.ContainsKey("jwtToken"))
            {
                Console.WriteLine("Cookie jwtToken encontrada, eliminándola...");
                Response.Cookies.Delete("jwtToken", new CookieOptions
                {
                    Path = "/",
                    Secure = false, // Cambiar a true en producción
                    SameSite = SameSiteMode.Lax
                });
            }

            // También limpiar cualquier cookie con diferentes configuraciones
            Response.Cookies.Append("jwtToken", "", new CookieOptions
            {
                Path = "/",
                Expires = DateTime.UtcNow.AddDays(-1), // Fecha en el pasado para eliminar
                Secure = false,
                SameSite = SameSiteMode.Lax
            });
        }

        public IActionResult OnPost()
        {
            Console.WriteLine("=== LOGIN POST INICIADO ===");
            Console.WriteLine($"Usuario: {Username}");

            // Limpiar cookies antes de crear nuevas
            Response.Cookies.Delete("jwtToken");

            if (Username == "admin" && Password == "password")
            {
                try
                {
                    var token = _jwtService.GenerateToken(Username);
                    Console.WriteLine($"Token generado: {token.Substring(0, 50)}...");

                    if (!int.TryParse(_configuration.GetSection("Jwt")["ExpirationMinutes"], out int expirationMinutes))
                    {
                        ErrorMessage = "Error de configuración de la expiración del token.";
                        return Page();
                    }

                    var cookieExpiration = DateTime.UtcNow.AddMinutes(expirationMinutes);
                    Console.WriteLine($"Cookie expira en: {cookieExpiration}");

                    Response.Cookies.Append("jwtToken", token, new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = false, // Cambiar a true en producción
                        IsEssential = true,
                        Expires = cookieExpiration,
                        Path = "/",
                        SameSite = SameSiteMode.Lax
                    });

                    Console.WriteLine("Cookie establecida exitosamente");
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
    }
}