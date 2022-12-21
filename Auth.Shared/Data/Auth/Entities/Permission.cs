using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Shared.Data.Auth.Entities
{
    public class Permission
    {
        public Guid PermissionId { get; set; }
        public string Category { get; set; }
        public string Name { get; set; }
        public string ClaimType { get; set; }
        public bool HasReadOnly { get; set; }
        public int SortOrder { get; set; }
        public bool IsSubUser { get; set; }
    }
}
