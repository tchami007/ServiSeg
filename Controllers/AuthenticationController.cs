using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using ServiSeg.Auth;
using ServiSeg.DTOs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ServiSeg.Controllers
{
    // Paso 13

    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private IConfiguration _configuration;

        public AuthenticationController (UserManager<IdentityUser> userManager, 
            RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        // Paso 15
        [HttpPost("Register")]
        public async Task<IActionResult> Register( [FromBody] UserRegistrationRequestDTO model)
        {
            // Verificar valides del modelo

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Verificar la existencia del usuario

            var emailExists = await _userManager.FindByEmailAsync(model.Email);

            if (emailExists != null) 
            { 
                return BadRequest(new AuthResult() 
                { 
                    Result = false,
                    Errors = new List<string> {"Email already exists"}
                });
            }

            // Crear un objeto de tipo Identity user

            var user = new IdentityUser
            {
                UserName = model.Name,
                Email = model.Email
            };

            // Creacion del usuario

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded) 
            {
                // Generar token
                var token = GenerateToken(user);

                // retornar resultados
                return Ok(new AuthResult()
                {
                    Result = true,
                    Token = token
                });
            }
            else 
            {
                var errors = new List<String>();

                foreach (var items in result.Errors)
                {
                    errors.Add(items.Description);
                }
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = errors
                }); 
            }
            
        }

        // Paso 17
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDTO model)
        {
            // Verificar la validez del modelo

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState) ;
            }

            // Verificar si el usuario exists

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                return BadRequest(new AuthResult()
                {
                   Result = false,
                   Errors = new List<string> { "Invalid PayLoad"}
                }) ;
            }

            // Verificar credenciales

            var succeded = await _userManager.CheckPasswordAsync(user, model.Password);

            if (succeded)
            {
                return Ok(new AuthResult()
                {
                    Result = true,
                    // Token = GenerateToken(user) 
                    Token = await GenerateTokenV2(user)
                }); 
            }
            else
            {
                return BadRequest(new AuthResult() 
                    { Result = false, Errors = new List<string> { "Invalid Credentials" } 
                });
            }
        }

        //------- metodos privados ---------//

        // Paso 14
        private string GenerateToken(IdentityUser user)
        {
            var claims = new[]
            {
                new Claim (JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim (JwtRegisteredClaimNames.Jti, Guid.NewGuid ().ToString ())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds
                ); 

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<string> GenerateTokenV2(IdentityUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);                   // Sugerido por IA
            var roles = await _userManager.GetRolesAsync(user);                         // Sugerido por IA
            var roleClaims = roles.Select(r => new Claim(ClaimTypes.Role, r)).ToList(); // Sugerido por IA


            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id) // Sugerido por IA
            }
            .Union(userClaims)  // Sugerido por IA
            .Union(roleClaims); // Sugerido por IA

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
