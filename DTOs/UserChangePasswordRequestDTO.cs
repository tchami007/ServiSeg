using System.ComponentModel.DataAnnotations;

namespace ServiSeg.DTOs
{
    public class UserChangePasswordRequestDTO
    {
        [Required]
        public string EmailAddress { get; set; }
        [Required] 
        public string OldPassword { get; set; }
        [Required]
        public string NewPassword { get; set; }
        [Required]
        public string RepeatPassword { get; set; }
    }
}
