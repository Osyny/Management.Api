using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using User.Management.Api.Models;
using User.Management.Api.Models.Authentification.SignUp;
using User.Management.Core.Entities;
using User.Management.Service.Models;
using User.Management.Service.Services;

namespace User.Management.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;

        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        public AuthenticationController(
            UserManager<ApplicationUser> userManager,
            IConfiguration configuration,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService
            ) 
        {
            _userManager = userManager;
            _configuration = configuration;
            _roleManager = roleManager;
            _emailService = emailService;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody]RegisterUser registerUser, string role)
        {
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User alredy exist!"});
            }

            ApplicationUser user = new ()
            {
                Email = registerUser.Email,
                FirstName = registerUser.FirstName,
                LastName = registerUser.LastName,
                UserName = registerUser.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            if(await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);

                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                            new Response { Status = "Error", Message = "User Faild to Create!" });
                }

                // Add role to the user...
                await _userManager.AddToRoleAsync(user, role);

                return StatusCode(StatusCodes.Status201Created,
                 new Response { Status = "Success", Message = "User create Succcessfull!" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                   new Response { Status = "Error", Message = "Role Doesnot Exist!" });
            }
        }

        [HttpGet]
        public IActionResult TestEmail()
        {

            var message = new Message(new string[] { "oxana1404@gmail.com" }, "Test", "<h1>Subscribe to my chanal!!!</h1>");
            _emailService.SendEmail(message);
            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Email Send Succcessfull!" });
        }
    }
}
