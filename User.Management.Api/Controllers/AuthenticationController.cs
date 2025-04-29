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
using User.Management.Api.Models;
using User.Management.Api.Models.Authentification.SignUp;
using User.Management.Core.Entities;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentification.Login;
using User.Management.Service.Models.Authentification.SignUp;
using User.Management.Service.Models.Authentification.User;
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

        private readonly IEmailService _emailService;
        private readonly IUserManagement _userManagement;
        public AuthenticationController(
            UserManager<ApplicationUser> userManager,
            IConfiguration configuration,
            IEmailService emailService,
            SignInManager<ApplicationUser> signInManager,
            IUserManagement userManagement
            ) 
        {
            _userManager = userManager;
            _configuration = configuration;
            _emailService = emailService;
            _signInManager = signInManager;
            _userManagement = userManagement;
        }

        [AllowAnonymous]
        [HttpPost("register")]
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
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var loginOtpResponse = await _userManagement.GetOtpByLoginAsync(loginModel);
            if (loginOtpResponse.Response != null)
            {
                var user = loginOtpResponse.Response.User;
                if (user.TwoFactorEnabled)
                {
                    var token = loginOtpResponse.Response.Token;
                    var message = new Message(new string[] { user.Email! }, "OTP Confrimation", token);
                    _emailService.SendEmail(message);

                    return StatusCode(StatusCodes.Status200OK,
                     new Response { IsSuccess = loginOtpResponse.IsSuccess, Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}" });
                }

                var isValidPass = await _userManager.CheckPasswordAsync(user, loginModel.Password);
                if(user != null && isValidPass)
                {
                    var serviceResponse = await _userManagement.GetJwtTokenAsync(user);
                    return Ok(serviceResponse);
                }
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
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot Password Link", forgotPasswordLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                 new Response { Status = "Success", Message = $"Password changed request is send to {user.Email}. Please open your email and clik the link!" });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                             new Response { Status = "Error", Message = $"Couldnot send link to email, please try again!" });
        }

        [AllowAnonymous]
        [HttpGet("reset-password")]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new
            {
                model
            });
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);

                if (!resetPassResult.Succeeded)
                {
                    foreach (var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password has been changed!" });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Success", Message = $"Couldnot send link to email, please try again!" });
        }

        [AllowAnonymous]
        [HttpGet("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
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


        [AllowAnonymous]
        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(LoginWithOTP loginWithOTP)
        {
            var jwt = await _userManagement.LoginUser2FactorSignInWithJWTokenAsync(loginWithOTP.Code, loginWithOTP.Username);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);

            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }

        [HttpPost]
        [Route("refresh-roken")]
        public async Task<IActionResult> RefreshToken(LoginResponse tokens)
        {
            var jwt = await _userManagement.RenewAccessTokenAsync(tokens);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }

        #region PrivateMethods 

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

        private IActionResult TestEmail()
        {

            var message = new Message(new string[] { "oxana1404@gmail.com" }, "Test", "<h1>Subscribe to my chanal!!!</h1>");
            _emailService.SendEmail(message);
            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Email Send Succcessfull!" });
        }

        #endregion
    }
}
