using System.ComponentModel.DataAnnotations;

namespace ServiSeg.DTOs
{
    public class UserAddPasswordRequestDTO
    {
        [Required]
        public string EmailAddress { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
