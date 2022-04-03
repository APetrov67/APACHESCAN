using Microsoft.EntityFrameworkCore;

namespace ApacheVersionScan
{
 public class ApacheContext : DbContext
    {
        public DbSet<Apache> Apaches { get; set; }

        public ApacheContext()
        {
            Database.EnsureCreated();
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlServer("Server=.\\;Database=apache;Integrated Security=true;");
        }
    }
}
