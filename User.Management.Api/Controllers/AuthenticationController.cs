using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web;
using User.Management.Api.Models;
using User.Management.Core.Entities;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentification.Login;
using User.Management.Service.Models.Authentification.SignUp;
using User.Management.Service.Services;

namespace User.Management.Api.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IUserManagement _userManagement;
        public AuthenticationController(
            UserManager<ApplicationUser> userManager,
            IConfiguration configuration,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            SignInManager<ApplicationUser> signInManager,
            IUserManagement userManagement
            ) 
        {
            _userManager = userManager;
            _configuration = configuration;
            _roleManager = roleManager;
            _emailService = emailService;
            _signInManager = signInManager;
            _userManagement = userManagement;
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Register([FromBody]RegisterUser registerUser)
        {
            var tokenResponse = await _userManagement.CreateUserWithTokenAsync(registerUser);
            if (tokenResponse.IsSuccess && tokenResponse.Response != null)
            {
                await _userManagement.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);

                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication",
                    new { tokenResponse.Response.Token, email = registerUser.Email }, Request.Scheme);

                //var confirmationLink = $"http://localhost:4200/confirm-account?Token={HttpUtility.UrlEncode(tokenResponse.Response.Token)}&email={HttpUtility.UrlEncode(registerUser.Email)}";

                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email link", confirmationLink!);
                var responseMsg = _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                        new Response { IsSuccess = true, Message = $"{tokenResponse.Message} {responseMsg}" });
            }

            return StatusCode(StatusCodes.Status500InternalServerError,
                  new Response { Message = tokenResponse.Message, IsSuccess = false });
        }


        [AllowAnonymous]
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            // Clear the existing external cookie to ensure a clean login process
            await _signInManager.SignOutAsync();

            //checking the user...
            var user = await _userManager.FindByNameAsync(loginModel.Username);

            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {             
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                // we add roles to the list
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                // generate the token with the climes...
                var jwtToken = GetToken(authClaims);

                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);

                // returning the token...
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo,
                });
            }
            return Unauthorized();  
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return NoContent();
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    };
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    var jwtToken = GetToken(authClaims);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });
                    //returning the token...

                }
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }

        private async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var userExist = await _userManager.FindByEmailAsync(email);
            if (userExist != null)
            {
                var result = await _userManager.ConfirmEmailAsync(userExist, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                           new Response { Status = "Success", Message = "Email Verified Succcessfully!" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
            new Response { Status = "Error", Message = "This User Doesnot exist!" });
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

            return token;
        }

        // [HttpGet]
        private IActionResult TestEmail()
        {

            var message = new Message(new string[] { "oxana1404@gmail.com" }, "Test", "<h1>Subscribe to my chanal!!!</h1>");
            _emailService.SendEmail(message);
            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Email Send Succcessfull!" });
        }

        //[AllowAnonymous]
        //[HttpPost]
        //[Route("login")]
        //public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        //{
        //    // Clear the existing external cookie to ensure a clean login process
        //    await _signInManager.SignOutAsync();

        //    //checking the user...
        //    var user = await _userManager.FindByNameAsync(loginModel.Username);

        //    // // two-factor authentication
        //    //if (user.TwoFactorEnabled)
        //    //{
        //    //    await _signInManager.SignOutAsync();
        //    //    await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
        //    //    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

        //    //    var message = new Message(new string[] { user.Email! }, "OTP Confrimation", token);
        //    //    _emailService.SendEmail(message);

        //    //    return StatusCode(StatusCodes.Status200OK,
        //    //     new Response { Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}" });
        //    //}

        //    if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
        //    {
        //        var authClaims = new List<Claim>
        //        {
        //            new Claim(ClaimTypes.Name, user.UserName),
        //            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //        };

        //        // we add roles to the list
        //        var userRoles = await _userManager.GetRolesAsync(user);
        //        foreach (var role in userRoles)
        //        {
        //            authClaims.Add(new Claim(ClaimTypes.Role, role));
        //        }

        //        // generate the token with the climes...
        //        var jwtToken = GetToken(authClaims);

        //        await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);

        //        // returning the token...
        //        return Ok(new
        //        {
        //            token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
        //            expiration = jwtToken.ValidTo,
        //        });
        //    }
        //    return Unauthorized();
        //}
    }
}
