using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration; // Aseg�rate de tener este using

namespace JWT.Pages
{
    [Authorize] // Este atributo protege la p�gina
    public class ProtectedModel : PageModel
    {
        public readonly IConfiguration Configuration;

        public ProtectedModel(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void OnGet()
        {
            // Aqu� puedes acceder a la informaci�n del usuario autenticado si es necesario
            var username = User.Identity.Name;
            // Otros claims pueden ser accedidos con User.Claims
        }
    }
}