using Microsoft.EntityFrameworkCore;
using SignIn_Page.Model;

namespace SignIn_Page.Data
{
    public class userDbContext:DbContext
    {
       
            public userDbContext(DbContextOptions<userDbContext> option) : base(option)
            {

            }
            public DbSet<User> Users { get; set; }
        }

    }

