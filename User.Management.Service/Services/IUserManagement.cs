using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using User.Management.Service.Models.Authentification.Login;
using User.Management.Service.Models.Authentification.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentification.User;
using User.Management.Core.Entities;
using Microsoft.AspNetCore.Mvc;

namespace User.Management.Service.Services
{
    public interface IUserManagement
    {

        /// <summary>
        /// Brief description of what the method does.
        /// </summary>
        /// <param name="registerUser">Description of the parameter.</param>
        /// <returns>Description of the return value.</returns>

        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser);
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user);

        //Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel);
        //Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user);
        //Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(string otp, string userName);
        //Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens);





    }
}
