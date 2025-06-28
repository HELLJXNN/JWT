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
        [Authorize] // Solo usuarios con un token válido pueden solicitar un refresh
        public IActionResult RefreshToken()
        {
            var user = HttpContext.User;
            var username = user.FindFirst(ClaimTypes.Name)?.Value;

            if (string.IsNullOrEmpty(username))
            {
                return Unauthorized(new { message = "Usuario no encontrado en el token." });
            }

            // Opcional: Validar si el token actual está a punto de expirar o si ya expiró (en caso de que se haya excedido el ClockSkew)
            // Esto es más para la lógica del frontend, aquí el [Authorize] ya valida que es un token "válido" hasta cierto punto.

            var newJwtToken = _jwtService.GenerateToken(username);

            // Al refrescar el token, también actualiza la cookie del cliente.
            var expirationMinutes = int.Parse(_configuration.GetSection("Jwt")["ExpirationMinutes"]);
            Response.Cookies.Append("jwtToken", newJwtToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                IsEssential = true,
                Expires = DateTime.UtcNow.AddMinutes(expirationMinutes + 5)
            });

            return Ok(new { token = newJwtToken });
        }
    }
}