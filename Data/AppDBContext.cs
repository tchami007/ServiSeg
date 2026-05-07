using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ServiSeg.Data
{
    // Paso 2
    public class AppDBContext : IdentityDbContext // Paso 8
    {
        public AppDBContext(DbContextOptions<AppDBContext> options) : base(options)  { }
    }
}
