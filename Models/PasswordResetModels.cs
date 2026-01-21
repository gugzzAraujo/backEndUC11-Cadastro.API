namespace backEndGamesTito.API.Models
{
    using System.ComponentModel.DataAnnotations;

    namespace backEndGamesTito.API.Models
    {
        // ==========================================
        // MÓDULO DE RECUPERAÇÃO DE SENHA (DTOs)
        // ==========================================

        // 1. DTO para solicitar o envio do código
        public class SolicitarResetModel
        {
            [Required(ErrorMessage = "O e-mail é obrigatório.")]
            [EmailAddress(ErrorMessage = "Formato de e-mail inválido.")]
            public string Email { get; set; } = string.Empty;
        }

        // 2. DTO para validar o código (passo intermediário)
        public class ValidarCodigoModel
        {
            [Required(ErrorMessage = "O e-mail é obrigatório.")]
            [EmailAddress(ErrorMessage = "Formato de e-mail inválido.")]
            public string Email { get; set; } = string.Empty;

            [Required(ErrorMessage = "O código é obrigatório.")]
            public string Codigo { get; set; } = string.Empty;
        }

        // 3. DTO para efetivar a troca de senha
        public class RedefinirSenhaModel
        {
            [Required(ErrorMessage = "O e-mail é obrigatório.")]
            [EmailAddress(ErrorMessage = "Formato de e-mail inválido.")]
            public string Email { get; set; } = string.Empty;

            [Required(ErrorMessage = "O código é obrigatório.")]
            public string Codigo { get; set; } = string.Empty;

            [Required(ErrorMessage = "A nova senha é obrigatória.")]
            [MinLength(6, ErrorMessage = "A senha deve ter no mínimo 6 caracteres.")]
            public string NovaSenha { get; set; } = string.Empty;
        }
    }
}
