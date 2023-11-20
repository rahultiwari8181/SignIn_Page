using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SignIn_Page.Data;
using SignIn_Page.Model;
using System.IdentityModel.Tokens.Jwt;

using System.Security.Cryptography;
using System.Text;

namespace SignIn_Page.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly userDbContext _userDbContext;

        public UserController(IConfiguration configuration, userDbContext userDbContext)
        {
            _config = configuration;
            _userDbContext = userDbContext;
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] User user)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(user.userName) || string.IsNullOrWhiteSpace(user.Password))
                {
                    return BadRequest("Username and password are required.");
                }

                var existingUser = _userDbContext.Users.FirstOrDefault(u => u.userName == user.userName);
                if (existingUser != null)
                {
                    return BadRequest("User with this username already exists.");
                }
                

                string hashedPassword = HashPassword(user.Password);
                

                User newUser = new User
                {
                    userName = user.userName,
                    Password = hashedPassword,
                    


                };

                _userDbContext.Users.Add(newUser);
                _userDbContext.SaveChanges();
                return Ok();
            }
            catch (Exception ex)
            {
                
                Console.WriteLine(ex.Message);
                return StatusCode(500, "An error occurred while registering the user.");
            }
        }

        private string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
            }
        }

        // Add this method inside UserController

        [HttpPost("login")]
        public IActionResult Login([FromBody] User loginUser)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(loginUser.userName) || string.IsNullOrWhiteSpace(loginUser.Password))
                {
                    return BadRequest("Username and password are required.");
                }

                var existingUser = _userDbContext.Users.FirstOrDefault(u => u.userName == loginUser.userName);

                if (existingUser == null || !VerifyPassword(loginUser.Password, existingUser.Password))
                {
                    return Unauthorized("Invalid username or password.");
                }

                var token = GenerateJwtToken(loginUser.userName);
                return Ok(new { token });
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return StatusCode(500, "An error occurred while authenticating the user.");
            }
        }

        private bool VerifyPassword(string inputPassword, string hashedPassword)
        {
            try
            {

                using (var sha256 = SHA256.Create())
                {

                    byte[] inputHashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(inputPassword));
                    string inputHashedPassword = BitConverter.ToString(inputHashedBytes).Replace("-", "").ToLower();


                    return inputHashedPassword == hashedPassword;
                }
            }
            catch (Exception ex)
            {


                Console.WriteLine($"An error occurred: {ex}");
                return false; 
            }


        }

        private string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(_config["Jwt:Issuer"],_config["Jwt:Audience"], null,

                expires: DateTime.Now.AddMinutes(1),
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
