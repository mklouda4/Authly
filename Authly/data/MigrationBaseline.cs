using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Authly.Data
{
    /// <summary>
    /// Marks migrations as applied when their schema change already exists in the database.
    /// Older installations got some columns outside of migrations; applying the migration again would fail
    /// ("duplicate column name") and block every later migration.
    /// </summary>
    public static class MigrationBaseline
    {
        private static readonly (string MigrationId, string Table, string Column)[] ExistingColumnMigrations =
        [
            ("20261001075013_AddIpLoginAttemptNote", "IpLoginAttempts", "Note")
        ];

        /// <summary>
        /// Records already-satisfied migrations in __EFMigrationsHistory. Returns the migration ids that were baselined.
        /// </summary>
        public static List<string> Apply(AuthlyDbContext context)
        {
            var baselined = new List<string>();
            var applied = context.Database.GetAppliedMigrations().ToHashSet();
            if (applied.Count == 0)
            {
                // Fresh database: let Migrate() create everything
                return baselined;
            }

            var productVersion = typeof(DbContext).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
            var historyRepository = context.GetService<IHistoryRepository>();

            foreach (var (migrationId, table, column) in ExistingColumnMigrations)
            {
                if (applied.Contains(migrationId) || !ColumnExists(context, table, column))
                {
                    continue;
                }

                context.Database.ExecuteSqlRaw(historyRepository.GetInsertScript(new HistoryRow(migrationId, productVersion)));
                baselined.Add(migrationId);
            }

            return baselined;
        }

        private static bool ColumnExists(AuthlyDbContext context, string table, string column)
        {
            // SQLite: pragma_table_info is a table-valued function, parameters cannot be used for the table name
            var count = context.Database
                .SqlQueryRaw<int>($"SELECT COUNT(*) AS \"Value\" FROM pragma_table_info('{table}') WHERE name = {{0}}", column)
                .AsEnumerable()
                .First();
            return count > 0;
        }
    }
}
