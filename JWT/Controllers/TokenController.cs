using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using JWT.Services;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using System;
using System.Linq;

namespace JWT.Controllers
{
    [ApiController]
    [Route("api")]
    public class TokenController : ControllerBase
    {
        private readonly JwtService _jwtService;
        private readonly IConfiguration _configuration;

        public TokenController(JwtService jwtService, IConfiguration configuration)
        {
            _jwtService = jwtService;
            _configuration = configuration;
        }

        [HttpPost("refresh-token")]
        [Authorize]
        public IActionResult RefreshToken()
        {
            try
            {
                Console.WriteLine("=== REFRESH TOKEN ENDPOINT LLAMADO ===");

                var user = HttpContext.User;
                var username = user.FindFirst(ClaimTypes.Name)?.Value;

                Console.WriteLine($"Usuario encontrado: {username}");

                if (string.IsNullOrEmpty(username))
                {
                    Console.WriteLine("ERROR: Usuario no encontrado en el token");
                    return Unauthorized(new { message = "Usuario no encontrado en el token." });
                }

                var newJwtToken = _jwtService.GenerateToken(username);
                var expirationMinutes = int.Parse(_configuration.GetSection("Jwt")["ExpirationMinutes"]);

                Console.WriteLine($"Nuevo token generado, expira en {expirationMinutes} minutos");

                // Limpiar cookie anterior con múltiples configuraciones
                var cookieOptions = new[]
                {
                    new CookieOptions { Path = "/", Secure = false, SameSite = SameSiteMode.Lax },
                    new CookieOptions { Path = "/", Secure = true, SameSite = SameSiteMode.Lax }
                };

                foreach (var option in cookieOptions)
                {
                    Response.Cookies.Delete("jwtToken", option);
                }

                // Establecer nueva cookie
                Response.Cookies.Append("jwtToken", newJwtToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = false, // Cambiar a true en producción
                    IsEssential = true,
                    Expires = DateTime.UtcNow.AddMinutes(expirationMinutes),
                    Path = "/",
                    SameSite = SameSiteMode.Lax
                });

                Console.WriteLine("Cookie actualizada exitosamente");

                return Ok(new
                {
                    message = "Token refrescado exitosamente",
                    expiresIn = expirationMinutes * 60,
                    success = true
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR en RefreshToken: {ex.Message}");
                return BadRequest(new { message = "Error al refrescar token", error = ex.Message });
            }
        }

        [HttpGet("token-info")]
        [Authorize]
        public IActionResult GetTokenInfo()
        {
            try
            {
                Console.WriteLine("=== TOKEN INFO ENDPOINT LLAMADO ===");

                var user = HttpContext.User;
                var username = user.FindFirst(ClaimTypes.Name)?.Value;

                // Buscar el claim de expiración
                var expClaim = user.FindFirst("exp")?.Value;

                Console.WriteLine($"Usuario: {username}");
                Console.WriteLine($"Claim exp: {expClaim}");

                if (string.IsNullOrEmpty(username))
                {
                    return Unauthorized(new { message = "Usuario no encontrado en el token." });
                }

                if (string.IsNullOrEmpty(expClaim))
                {
                    var expirationMinutes = int.Parse(_configuration.GetSection("Jwt")["ExpirationMinutes"]);
                    var estimatedExpiration = DateTime.UtcNow.AddMinutes(expirationMinutes);

                    Console.WriteLine("Usando tiempo estimado");

                    return Ok(new
                    {
                        username = username,
                        expiresAt = estimatedExpiration.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                        secondsUntilExpiration = (int)(estimatedExpiration - DateTime.UtcNow).TotalSeconds,
                        note = "Tiempo estimado basado en configuración"
                    });
                }

                if (long.TryParse(expClaim, out long exp))
                {
                    var expirationTime = DateTimeOffset.FromUnixTimeSeconds(exp);
                    var timeUntilExpiration = expirationTime.Subtract(DateTimeOffset.UtcNow);

                    Console.WriteLine($"Token expira en: {expirationTime}");

                    return Ok(new
                    {
                        username = username,
                        expiresAt = expirationTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                        secondsUntilExpiration = Math.Max(0, (int)timeUntilExpiration.TotalSeconds)
                    });
                }

                return BadRequest(new { message = "No se pudo obtener información del token." });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR en GetTokenInfo: {ex.Message}");
                return BadRequest(new { message = "Error interno del servidor", error = ex.Message });
            }
        }

        [HttpPost("logout")]
        [AllowAnonymous]
        public IActionResult Logout()
        {
            try
            {
                Console.WriteLine("=== LOGOUT ENDPOINT LLAMADO ===");

                // Limpiar cookies con múltiples configuraciones
                var cookieOptions = new[]
                {
                    new CookieOptions { Path = "/", Secure = false, SameSite = SameSiteMode.Lax },
                    new CookieOptions { Path = "/", Secure = true, SameSite = SameSiteMode.Lax },
                    new CookieOptions { Path = "/", Secure = false, SameSite = SameSiteMode.Strict },
                    new CookieOptions { Path = "/", Secure = true, SameSite = SameSiteMode.Strict }
                };

                foreach (var option in cookieOptions)
                {
                    Response.Cookies.Delete("jwtToken", option);

                    // También establecer cookie vacía con fecha pasada
                    option.Expires = DateTime.UtcNow.AddDays(-1);
                    Response.Cookies.Append("jwtToken", "", option);
                }

                Console.WriteLine("Logout completado - cookies limpiadas");
                return Ok(new { message = "Sesión cerrada exitosamente" });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR en Logout: {ex.Message}");
                return BadRequest(new { message = "Error al cerrar sesión", error = ex.Message });
            }
        }

        [HttpGet("test")]
        [AllowAnonymous]
        public IActionResult Test()
        {
            return Ok(new { message = "API funcionando correctamente", timestamp = DateTime.Now });
        }
    }
}
