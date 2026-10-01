using Authly.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Xunit;

namespace Authly.Tests
{
    public class MigrationBaselineTests : IDisposable
    {
        private const string InitialCreate = "20250727110428_InitialCreate";
        private const string AddNote = "20261001075013_AddIpLoginAttemptNote";

        private readonly SqliteConnection _connection = new("DataSource=:memory:");
        private readonly AuthlyDbContext _context;

        public MigrationBaselineTests()
        {
            _connection.Open();
            _context = new AuthlyDbContext(new DbContextOptionsBuilder<AuthlyDbContext>().UseSqlite(_connection).Options);
        }

        public void Dispose()
        {
            _context.Dispose();
            _connection.Dispose();
        }

        private bool NoteColumnExists() =>
            _context.Database.SqlQueryRaw<int>("SELECT COUNT(*) AS \"Value\" FROM pragma_table_info('IpLoginAttempts') WHERE name = 'Note'")
                .AsEnumerable().First() > 0;

        [Fact]
        public void FreshDatabase_MigrationsCreateNoteColumn()
        {
            Assert.Empty(MigrationBaseline.Apply(_context));
            _context.Database.Migrate();

            Assert.True(NoteColumnExists());
            Assert.Contains(AddNote, _context.Database.GetAppliedMigrations());
        }

        [Fact]
        public void LegacyDatabaseWithNoteColumn_IsBaselinedAndMigrateSucceeds()
        {
            // State of existing installations: InitialCreate applied, Note column added outside of migrations
            _context.GetService<IMigrator>().Migrate(InitialCreate);
            _context.Database.ExecuteSqlRaw("ALTER TABLE IpLoginAttempts ADD COLUMN Note TEXT NULL");

            Assert.Equal([AddNote], MigrationBaseline.Apply(_context));
            _context.Database.Migrate(); // would throw "duplicate column name: Note" without the baseline

            Assert.Contains(AddNote, _context.Database.GetAppliedMigrations());
        }

        [Fact]
        public void LegacyDatabaseWithoutNoteColumn_GetsColumnFromMigration()
        {
            _context.GetService<IMigrator>().Migrate(InitialCreate);

            Assert.Empty(MigrationBaseline.Apply(_context));
            _context.Database.Migrate();

            Assert.True(NoteColumnExists());
        }
    }
}
