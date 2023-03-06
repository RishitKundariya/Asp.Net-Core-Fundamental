using DemoAppAuthenticationAndAuthorization.Models;
using DemoAppAuthenticationAndAuthorization.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DemoAppAuthenticationAndAuthorization.Controllers
{
    [ApiController]
    [Route("[controller]/[Action]")]
    public class LoginController : Controller
    {
        private IConfiguration _configuration;
        private PracticeDatabaseContext _practiceDatabaseContext;
        public LoginController(PracticeDatabaseContext practiceDatabaseContext, IConfiguration configuration)
        {
            _configuration = configuration;
            _practiceDatabaseContext= practiceDatabaseContext;
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult ValidateCredential(CheckCredentialLogin checkCredentialLogin)
        {
            if(_practiceDatabaseContext.Users.Any(x=>x.Username == checkCredentialLogin.UserName && x.Password == checkCredentialLogin.Password))
            {
                User u = _practiceDatabaseContext.Users.Where(x => x.Username == checkCredentialLogin.UserName && x.Password == checkCredentialLogin.Password).FirstOrDefault();
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                var Credentials = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);
                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier,u.Username),
                    new Claim(ClaimTypes.Role,u.Authorizations.ToString())
                };
                var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
                    _configuration["Jwt:Audience"],
                    claims,
                    expires:DateTime.Now.AddMinutes(10),
                    signingCredentials:Credentials
                    );
                return Ok( new JwtSecurityTokenHandler().WriteToken(token));
            }
            else
            {
                return Ok("Information provided is invalid");
            }
        }

        [HttpGet]
        [Authorize(Roles = "1")]
        public IActionResult CheckLogin()
        {
            return Ok("Jason Token is valid");
        }

        [HttpGet]
        public IActionResult GetTimestap(string timestamp)
        {
            DateTime currentTime = DateTime.UtcNow;
            long unixTime = ((DateTimeOffset)currentTime).ToUnixTimeSeconds();
            if (unixTime - Convert.ToInt64(timestamp) <= 100)
            {
                return Ok("Link is working");
            }
            else
            {
                return Ok("Link is expried Please try again letter");
            }

        }

        [HttpGet]
        public IActionResult GetUserList(string userId)
        {
            return Ok(_practiceDatabaseContext.Users.FromSqlInterpolated($"exec getuser @usreid={userId}"));
        }
    }
}
