namespace Authly.Models
{
    /// <summary>
    /// Role model for user authorization and permissions
    /// </summary>
    public class RoleModel
    {
        /// <summary>
        /// Gets or sets the unique identifier for the role
        /// </summary>
        public string? Id { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the role code (short identifier)
        /// </summary>
        public string Code { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the detailed description of the role
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether this role is marked for deletion
        /// </summary>
        public bool Delete { get; set; } = false;

        /// <summary>
        /// Gets the formatted title combining code and description, with proper trimming of hyphens
        /// </summary>
        public string Title => $"{Code} - {Description}".Trim().TrimStart('-').TrimEnd('-').Trim();

        /// <summary>
        /// Indicates if this role can be modified
        /// </summary>
        public bool IsEditable { get; set; } = true;
    }
}
