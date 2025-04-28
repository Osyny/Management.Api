using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using User.Management.Core.Entities;

namespace User.Management.Service.Models.Authentification.User
{
    public class CreateUserResponse
    {
        public string Token { get; set; } = null!;
        public ApplicationUser User { get; set; } = null!;

    }
}
