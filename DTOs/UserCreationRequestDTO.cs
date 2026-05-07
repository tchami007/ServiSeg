using System.ComponentModel.DataAnnotations;

namespace ServiSeg.DTOs
{
    public class UserCreationRequestDTO
    {
        [Required]
        public string Name { get; set; }
        [Required]
        public string EmailAddress { get; set; }
    }
}
