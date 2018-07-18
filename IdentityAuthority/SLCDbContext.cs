using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityAuthority
{
    public class SLCDbContext : IdentityDbContext
    {
        public SLCDbContext(DbContextOptions<SLCDbContext> options) : base(options) { }
    }
}
