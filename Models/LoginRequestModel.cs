// --- Models/LoginRequestModel.cs

using System.ComponentModel.DataAnnotations;

namespace backEndGamesTito.Api.Models
{
    public class LoginRequestModel
    {
        [Required(ErrorMessage = "O campo email é obrigatório!")]
        [EmailAddress(ErrorMessage = "O email informado não é valido!")]
        public string Email { get; set; } = string.Empty;
        [Required(ErrorMessage = "O campo senha é obrigatório!")]
        public string PassWordHash { get; set; } = string.Empty;
    }
}