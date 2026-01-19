// --- Models/RegisterRequestModel.cs
using System.ComponentModel.DataAnnotations;

namespace backEndGamesTito.API.Models
{
    public class RegisterRequestModel
    {
        [Required(ErrorMessage = "O campo nome é obrigatório!")]
        public string NomeCompleto { get; set; } = string.Empty;

        [Required(ErrorMessage = "O campo email é obrigatório!")]
        [EmailAddress(ErrorMessage = "O email informado não é valido!")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "O campo senha é obrigatório!")]
        public string PassWordHash { get; set; } = string.Empty;
    }
}