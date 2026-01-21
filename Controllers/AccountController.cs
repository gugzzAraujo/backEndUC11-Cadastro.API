using backEndGamesTito.Api.Models; // Para LoginRequestModel
using backEndGamesTito.API.Data.Models; // Para DbUsuario
// Referências do Projeto
using backEndGamesTito.API.Models;
using backEndGamesTito.API.Models.backEndGamesTito.API.Models;
using backEndGamesTito.API.Repositories;
// Bibliotecas de Terceiros
using BCrypt.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace backEndGamesTito.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly UsuarioRepository _usuarioRepository;

        // Chave de segurança centralizada (Idealmente mover para appsettings.json no futuro)
        private const string ApiKey = "mangaPara_todos_ComLeite_kkk";

        public AccountController(UsuarioRepository usuarioRepository)
        {
            _usuarioRepository = usuarioRepository;
        }

        // =================================================================
        // 1. REGISTRO DE USUÁRIO
        // =================================================================
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequestModel model)
        {
            try
            {
                DateTime agora = DateTime.Now;
                string dataString = agora.ToString();

                // Cria hashes SHA256 dos inputs
                string PassSHA256 = ComputeSha256Hash(model.PassWordHash);
                string EmailSHA256 = ComputeSha256Hash(model.Email);

                // Monta a string para criptografia (Senha + Email + Key)
                string PassCrip = PassSHA256 + EmailSHA256 + ApiKey;
                // Monta a string de controle (Email + Senha + Data + Key)
                string HashCrip = EmailSHA256 + PassSHA256 + dataString + ApiKey;

                // Aplica o BCrypt
                string PassBCrypt = BCrypt.Net.BCrypt.HashPassword(PassCrip);
                string HashBCrypt = BCrypt.Net.BCrypt.HashPassword(HashCrip);

                var novoUsuario = new Usuario
                {
                    NomeCompleto = model.NomeCompleto,
                    Email = model.Email,
                    PassWordHash = PassBCrypt,
                    HashPass = HashBCrypt,
                    DataAtualizacao = agora,
                    StatusId = 2 // Ativo/Pendente
                };

                await _usuarioRepository.CreateUserAsync(novoUsuario);

                return Ok(new
                {
                    erro = false,
                    message = "Usuário cadastrado com sucesso!",
                    usuario = new
                    {
                        model.NomeCompleto,
                        model.Email
                    }
                });
            }
            catch (SqlException ex) when (ex.Number == 2627 || ex.Number == 2601)
            {
                return Conflict(new { erro = true, message = "Este email já está em uso!" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    erro = true,
                    message = "Sistema indisponível no momento.",
                    codErro = $"Erro: {ex.Message}"
                });
            }
        }

        // =================================================================
        // 2. LOGIN (AUTENTICAÇÃO)
        // =================================================================
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestModel model)
        {
            try
            {
                // Busca usuário
                var user = await _usuarioRepository.GetUserByEmailAsync(model.Email);
                bool isPasswordValid = false;

                if (user != null)
                {
                    // Recria a lógica de hash para validar
                    string passSHA256 = ComputeSha256Hash(model.PassWordHash);
                    string emailSHA256 = ComputeSha256Hash(model.Email);

                    // A "Salada" de criptografia deve ser IDÊNTICA ao registro
                    string candidatePassCrip = passSHA256 + emailSHA256 + ApiKey;

                    // Verifica com BCrypt
                    isPasswordValid = BCrypt.Net.BCrypt.Verify(candidatePassCrip, user.PassWordHash);
                }

                if (!isPasswordValid || user == null)
                {
                    return Unauthorized(new { erro = true, message = "E-mail ou senha inválidos." });
                }

                return Ok(new
                {
                    erro = false,
                    message = "Login realizado com sucesso!",
                    usuario = new
                    {
                        user.UsuarioId,
                        user.NomeCompleto,
                        user.Email,
                        user.StatusId
                    }
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { erro = true, message = "Erro ao processar login.", debug = ex.Message });
            }
        }

        // =================================================================
        // 3. RECUPERAÇÃO DE SENHA (FLUXO DE 3 PASSOS)
        // =================================================================

        // Passo A: Solicitar Código
        [HttpPost("solicitar-codigo")]
        public async Task<IActionResult> SolicitarCodigo([FromBody] SolicitarResetModel model)
        {
            var user = await _usuarioRepository.GetUserByEmailAsync(model.Email);

            if (user == null) return NotFound(new { erro = true, message = "E-mail não encontrado." });

            string token = Random.Shared.Next(100000, 999999).ToString();
            await _usuarioRepository.SaveResetTokenAsync(user.UsuarioId, token);

            // Simulação de envio de e-mail
            return Ok(new
            {
                erro = false,
                message = "Código enviado para o e-mail.",
                DEBUG_CODIGO = token // Remover em produção
            });
        }

        // Passo B: Validar Código
        [HttpPost("validar-codigo")]
        public async Task<IActionResult> ValidarCodigo([FromBody] ValidarCodigoModel model)
        {
            var user = await _usuarioRepository.GetUserByEmailAsync(model.Email);

            if (user == null || user.ResetToken != model.Codigo || user.ResetTokenExpiry < DateTime.Now)
            {
                return BadRequest(new { erro = true, message = "Código inválido ou expirado." });
            }

            return Ok(new { erro = false, message = "Código válido." });
        }

        // Passo C: Redefinir Senha
        [HttpPost("redefinir-senha")]
        public async Task<IActionResult> RedefinirSenha([FromBody] RedefinirSenhaModel model)
        {
            try
            {
                var user = await _usuarioRepository.GetUserByEmailAsync(model.Email);

                // Validação de segurança dupla
                if (user == null || user.ResetToken != model.Codigo || user.ResetTokenExpiry < DateTime.Now)
                {
                    return BadRequest(new { erro = true, message = "Sessão expirada ou código inválido." });
                }

                // Verifica se a nova senha é igual a antiga
                string newPassSHA256 = ComputeSha256Hash(model.NovaSenha);
                string emailSHA256 = ComputeSha256Hash(model.Email);
                string candidatePassCrip = newPassSHA256 + emailSHA256 + ApiKey;

                if (BCrypt.Net.BCrypt.Verify(candidatePassCrip, user.PassWordHash))
                {
                    return BadRequest(new { erro = true, message = "A nova senha não pode ser igual à atual." });
                }

                // Gera novos hashes e salva
                string newPassBCrypt = BCrypt.Net.BCrypt.HashPassword(candidatePassCrip);
                string hashCrip = emailSHA256 + newPassSHA256 + DateTime.Now.ToString() + ApiKey;
                string newHashPassBCrypt = BCrypt.Net.BCrypt.HashPassword(hashCrip);

                await _usuarioRepository.UpdatePasswordAsync(user.UsuarioId, newPassBCrypt, newHashPassBCrypt);
                await _usuarioRepository.ClearResetTokenAsync(user.UsuarioId);

                return Ok(new { erro = false, message = "Senha alterada com sucesso!" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { erro = true, message = "Erro interno", debug = ex.Message });
            }
        }

        // =================================================================
        // MÉTODOS AUXILIARES
        // =================================================================
        private string ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}