using System.ComponentModel.DataAnnotations;

namespace DemoAppAuthenticationAndAuthorization.Models.ViewModels
{
    public class CheckCredentialLogin
    {

        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
