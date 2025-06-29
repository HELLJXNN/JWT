using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;

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
            var username = User.Identity.Name;
        }
    }
}