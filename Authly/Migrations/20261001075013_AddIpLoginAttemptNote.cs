using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Authly.Migrations
{
    /// <inheritdoc />
    public partial class AddIpLoginAttemptNote : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Note",
                table: "IpLoginAttempts",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Note",
                table: "IpLoginAttempts");
        }
    }
}
