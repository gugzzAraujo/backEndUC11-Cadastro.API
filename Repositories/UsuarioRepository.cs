// --- Repositories/UsuarioRepository.cs

using System;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using backEndGamesTito.API.Data.Models;

namespace backEndGamesTito.API.Repositories
{
    public class UsuarioRepository
    {
        private readonly string _connectionString = string.Empty;

        public UsuarioRepository(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection")
                    ?? throw new ArgumentNullException("String de conexão 'DefaultConnection' não enconrada!");
        }

        public async Task CreateUserAsync(Usuario user)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                await connection.OpenAsync();

                var commandText = @"
                    INSERT INTO dbo.Usuario
                        (NomeCompleto, Email, PassWordHash, HashPass, DataAtualizacao, StatusId)
                    VALUES
                        (@NomeCompleto, @Email, @PassWordHash, @HashPass, @DataAtualizacao, @StatusId)
                ";

                using (var command = new SqlCommand(commandText, connection)) {
                    command.Parameters.AddWithValue("@NomeCompleto", user.NomeCompleto);
                    command.Parameters.AddWithValue("@Email", user.Email);
                    command.Parameters.AddWithValue("@PassWordHash", user.PassWordHash);
                    command.Parameters.AddWithValue("@HashPass", user.HashPass);
                    // Esta linha da 'DataAtualização entrada como objeto podendo ser um valor 'nulo'
                    command.Parameters.AddWithValue("@DataAtualizacao", (object)user.DataAtualizacao ?? DBNull.Value);
                    command.Parameters.AddWithValue("@StatusId", user.StatusId);

                    await command.ExecuteNonQueryAsync();
                }
            }
        }
        public async Task<Usuario?> GetUserByEmailAsync(string email)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                await connection.OpenAsync();

                var commandText = @"
                    SELECT TOP 1 * FROM dbo.Usuario 
                    WHERE Email = @Email
                ";

                using (var command = new SqlCommand(commandText, connection))
                {
                    command.Parameters.AddWithValue("@Email", email);

                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            // Mapeia os dados do banco para o objeto 'Usuario'
                            return new Usuario
                            {
                                UsuarioId = reader.GetInt32(reader.GetOrdinal("UsuarioId")),
                                NomeCompleto = reader.GetString(reader.GetOrdinal("NomeCompleto")),
                                Email = reader.GetString(reader.GetOrdinal("Email")),
                                PassWordHash = reader.GetString(reader.GetOrdinal("PassWordHash")),
                                HashPass = reader.GetString(reader.GetOrdinal("HashPass")),
                                DataCriacao = reader.GetDateTime(reader.GetOrdinal("DataCriacao")),
                                DataAtualizacao = reader.IsDBNull(reader.GetOrdinal("DataAtualizacao"))
                                                    ? null
                                                    : reader.GetDateTime(reader.GetOrdinal("DataAtualizacao")),
                                StatusId = reader.GetInt32(reader.GetOrdinal("StatusId"))

                            };
                        }
                    }
                }
                // Se não encontrar o usuário, retorna 'nulo'
                return null;
            }
        }
    }
}
