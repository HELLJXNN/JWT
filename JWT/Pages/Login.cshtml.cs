using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using JWT.Services; 

namespace JWT.Pages
{
    public class LoginModel : PageModel
    {
        private readonly JwtService _jwtService;

        [BindProperty]
        public string Username { get; set; }

        [BindProperty]
        public string Password { get; set; }

        public string ErrorMessage { get; set; }

        public LoginModel(JwtService jwtService)
        {
            _jwtService = jwtService;
        }

        public void OnGet()
        {
        }

        public IActionResult OnPost()
        {

            if (Username == "admin" && Password == "password")
            {
                var token = _jwtService.GenerateToken(Username);


                Response.Cookies.Append("jwtToken", token, new CookieOptions
                {
                    HttpOnly = true, // Evita que JavaScript acceda directamente a la cookie
                    Secure = true, // Solo enviar sobre HTTPS
                    IsEssential = true, // Para asegurar que se guarde
                    Expires = DateTime.UtcNow.AddMinutes(int.Parse(HttpContext.RequestServices.GetRequiredService<IConfiguration>().GetSection("Jwt")["ExpirationMinutes"]) + 5) // La cookie puede durar un poco más que el token
                });

                return RedirectToPage("/Protected");
            }
            else
            {
                ErrorMessage = "Credenciales incorrectas.";
                return Page();
            }
        }
    }
}