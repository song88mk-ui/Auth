namespace Auth.Shared.Data.Auth.Entities
{
    public class Permission
    {
        public Guid PermissionId { get; set; }
        public int CategoryId { get; set; }
        public string CategoryName { get; set; }
        public string SubCategoryName { get; set; }
        public string GroupName { get; set; }
        public string Name { get; set; }
        public string ClaimType { get; set; }
        public bool HasReadOnly { get; set; }
        public int SortOrder { get; set; }
        public bool IsSubUser { get; set; }
        public int UserGroupTemplateIdRef { get; set; }
        public int Version { get; set; }
    }
}
