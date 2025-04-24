using System.ComponentModel.DataAnnotations;

namespace User.Management.Service.Models.Authentification.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "First Name is Required")]
        public required string FirstName { get; set; }
        [Required(ErrorMessage = "Last Name is Required")]
        public required string LastName { get; set; }

        [Required(ErrorMessage = "User Name is Required")]
        public required string UserName { get; set; }
        [Required(ErrorMessage = "Email is Required")]
        [EmailAddress]
        public required string Email { get; set; }
        [Required(ErrorMessage = "Password is Required")]
        public required string Password { get; set; }
        public List<string> Roles { get; set; }


    }
}
