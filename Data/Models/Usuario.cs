
// --- Data/Models/Usuario.cs
using System;

namespace backEndGamesTito.API.Data.Models
{
    public class Usuario
    {
        public int UsuarioId { get; set; }
        public string NomeCompleto { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PassWordHash { get; set; } = string.Empty;
        public string HashPass { get; set; }= string.Empty; 
        public DateTime DataCriacao { get; set; }
        public DateTime? DataAtualizacao { get; set; }
        public int StatusId { get; set; }
    }
}