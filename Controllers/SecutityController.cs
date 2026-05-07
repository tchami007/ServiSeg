using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ServiSeg.Auth;
using ServiSeg.DTOs;
using System.Data;
using System.Security.Claims;

namespace ServiSeg.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public SecurityController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        //------------------------------------------------
        //        A P I S     D E        U S U A R I O 
        //------------------------------------------------
        [Authorize(Roles = "admin")]
        [HttpPost("CreateUser")]
        public async Task<IActionResult> AddUser([FromBody] UserCreationRequestDTO model)
        {
            // Verifica si los datos vienen completos
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Verifica si el email existe
            var email = await _userManager.FindByEmailAsync(model.EmailAddress);

            if (email != null)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>() { "Email already exists" }
                });
            }

            // Verifica si el usuario existe
            var user = await _userManager.FindByNameAsync(model.Name);

            if (user != null)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>() { "User already exists" }
                });
            }

            // Creacion de usuario
            var newUser = new IdentityUser
            {
                UserName = model.Name,
                Email = model.Name
            };

            // Creacion de usuario
            var result = await _userManager.CreateAsync(newUser);
            if (result.Succeeded)
            {
                return Ok(new AuthResult()
                {
                    Result = true,
                    Errors = new List<String>() { "User Created" }
                });
            }
            else
            {
                List<string> errors = new List<string>();
                foreach (var error in result.Errors) { errors.Add(error.Description); }
                return BadRequest(new AuthResult() { Result = false, Errors = errors });
            }
        }
        [Authorize(Roles = "consulta")]
        [HttpGet("Users")]
        public IActionResult GetUsers()
        {
            var users = _userManager.Users;
            return Ok(users);
        }
        [Authorize(Roles = "admin")]
        [HttpDelete("DeleteUser")]
        public async Task<IActionResult> DeleteUser(string userName)
        {
            // Verificar la existencia del usuario
            var user = await _userManager.FindByNameAsync(userName);
            if (user == null)
            {
                return NotFound(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>() { "User not found" }
                });
            }

            // Verificar el rol del usuario
            var roles = await _userManager.GetRolesAsync(user);

            if (roles.Contains("admin"))
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>() { "User is Admin" }
                });
            }

            var result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
            {
                return Ok(new AuthResult()
                {
                    Result = true,
                    Errors = new List<string>() { "User Deleted" }

                });
            }
            else
            {
                List<string> errors = new List<string>();
                foreach (var error in result.Errors)
                {
                    errors.Add(error.Description);
                }
                return BadRequest(new AuthResult() { Result = false, Errors = errors });
            }
        }
        [Authorize(Roles = "admin")]
        [HttpPost("UserAddPassword")]
        public async Task<IActionResult> AddPassword([FromBody] UserAddPasswordRequestDTO model)
        {
            // Verificar la valides del model
            if (!ModelState.IsValid) { return BadRequest(ModelState); }

            // Verificar la existencia del usuario
            var user = await _userManager.FindByEmailAsync(model.EmailAddress);
            if (user == null)
            {
                return BadRequest(new AuthResult() 
                { 
                    Result = false, 
                    Errors = new List<String>() { "User not exists" } });
            }

            // Cambio de password
            var result = await _userManager.AddPasswordAsync(user, model.Password);
            if (result.Succeeded)
            {
                return Ok(new AuthResult() { Result = true, Errors = new List<String>() { "Password Changed" } });
            }
            else
            {
                List<String> errors = new List<String>();
                foreach (var error in result.Errors) { errors.Add(error.Description); }
                return BadRequest(new AuthResult() { Result = true, Errors = errors });
            }
        }
        [HttpPost("UserResetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] UserAddPasswordRequestDTO model)
        {
            // verificar la validez del modelo
            if (!ModelState.IsValid) { return BadRequest(ModelState); }

            // verificar la existencia del usuario
            var user = await _userManager.FindByEmailAsync(model.EmailAddress);
            if (user == null)
            {
                return BadRequest(new AuthResult() { Result = false, Errors = new List<String>() { "User not exists" } });
            }

            // Generacion de token para cambio de password
            var tokenReset = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Cambio de password
            var results = await _userManager.ResetPasswordAsync(user, tokenReset, model.Password);
            if (results.Succeeded)
            {
                return Ok(new AuthResult() { Result = true, Errors = new List<string>() { "Password changed" } });
            }
            else
            {
                List<string> errors = new List<string>();
                foreach (var error in results.Errors)
                { errors.Add(error.Description); }
                return BadRequest(new AuthResult() { Result = false, Errors = errors });
            }
        }
        [Authorize(Roles = "consulta")]
        [HttpGet("UserRolesByUserName")]
        public async Task<IActionResult> GetUserRoles(string userName)
        {
            // Verificar existencia del usuario
            var user = await _userManager.FindByNameAsync(userName);

            if (user == null)
            {
                return NotFound(new AuthResult() { Result = false, Errors = new List<string>() { "User not exists" } });
            }

            // Recuperar roles del usuario
            var roles = await _userManager.GetRolesAsync(user);
            return Ok(roles);
        }
        [Authorize(Roles = "consulta")]
        [HttpGet("UserCheckRoles")]
        public IActionResult CheckRoles()
        {
            var roles = User.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();
            return Ok(new { roles });
        }
        //------------------------------------------------
        //        A P I S     D E        R O L E 
        //------------------------------------------------
        [Authorize(Roles = "admin")]
        [HttpPost("CreateRole")]
        public async Task<IActionResult> AddRol([FromBody] RolRequestDTO model)
        {
            // Verificar la validez del modelo
            if (!ModelState.IsValid)
            { return BadRequest(); }

            // Verificar si el rol existe
            var founded = await _roleManager.RoleExistsAsync(model.RolName);

            if (!founded)
            {
                await _roleManager.CreateAsync(new IdentityRole(model.RolName));
                return Ok(new AuthResult()
                {
                    Result = true,
                    Errors = new List<string>() { "Role Created" }
                });
            }
            else
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>() { "Role Exists" }
                });
            }
        }
        [Authorize(Roles = "consulta")]
        [HttpGet("Roles")]
        public IActionResult GetRoles()
        {
            var roles = _roleManager.Roles;
            return Ok(roles);
        }
        [Authorize(Roles = "admin")]
        [HttpPost("AssignRoleUser")]
        public async Task<IActionResult> AddUserRol(string userName, string userRolName)
        {
            // Verificar la valides de parametros

            if ((userName == null) || (userRolName == null))
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>() { "Invalid Request" }
                });
            }

            // Verificar la existencia del usuario
            var user = await _userManager.FindByNameAsync(userName);

            if (user == null)
            {
                return NotFound(new AuthResult() { Result = false, Errors = new List<string>() { "User not exists" } });
            }

            // Verificar la asignacion del role
            var founded = await _roleManager.FindByNameAsync(userRolName);
            if (founded == null)
            {
                return BadRequest(new AuthResult() { Result = false, Errors = new List<string>() { "User Not Found" } });
            }

            // Asignacion del rol al usuario
            var result = await _userManager.AddToRoleAsync(user, userRolName);
            if (result.Succeeded)
            {
                return Ok(new AuthResult()
                {
                    Result = true,
                    Errors = new List<string>() { "User Role Assigned" }
                });
            }
            else
            {
                return BadRequest(new AuthResult() { Result = false, Errors = new List<string>() { "User Role Not Assigned" } });
            }
        }
    }

}
