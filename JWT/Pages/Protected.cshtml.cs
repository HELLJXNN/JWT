using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration; // Asegúrate de tener este using

namespace JWT.Pages
{
    [Authorize] // Este atributo protege la página
    public class ProtectedModel : PageModel
    {
        public readonly IConfiguration Configuration;

        public ProtectedModel(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void OnGet()
        {
            // Aquí puedes acceder a la información del usuario autenticado si es necesario
            var username = User.Identity.Name;
            // Otros claims pueden ser accedidos con User.Claims
        }
    }
}