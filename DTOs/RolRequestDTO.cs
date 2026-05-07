using System.ComponentModel.DataAnnotations;

namespace ServiSeg.DTOs
{
    public class RolRequestDTO
    {
        [Required]
        public string RolName { get; set; }
    }
}
