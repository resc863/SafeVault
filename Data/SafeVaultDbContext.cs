using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Data;

/// <summary>
/// SafeVault 데이터베이스 컨텍스트
/// </summary>
public class SafeVaultDbContext : DbContext
{
    public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; } = null!;
    public DbSet<InputValidationLog> InputValidationLogs { get; set; } = null!;
    public DbSet<BlockedPattern> BlockedPatterns { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User 엔티티 설정
        modelBuilder.Entity<User>(entity =>
        {
            entity.ToTable("Users");
            entity.HasKey(e => e.UserId);
            entity.HasIndex(e => e.Username).IsUnique();
            entity.HasIndex(e => e.Email).IsUnique();
            entity.Property(e => e.Username).IsRequired().HasMaxLength(50);
            entity.Property(e => e.Email).IsRequired().HasMaxLength(100);
            entity.Property(e => e.PasswordHash).IsRequired();
            entity.Property(e => e.Role).IsRequired().HasMaxLength(20).HasDefaultValue("User");
        });

        // InputValidationLog 엔티티 설정
        modelBuilder.Entity<InputValidationLog>(entity =>
        {
            entity.ToTable("InputValidationLogs");
            entity.HasKey(e => e.LogId);
            entity.HasIndex(e => e.ValidationResult);
            entity.HasIndex(e => e.ThreatType);
            entity.HasIndex(e => e.CreatedAt);
            entity.Property(e => e.ValidationResult)
                .HasConversion<string>();
        });

        // BlockedPattern 엔티티 설정
        modelBuilder.Entity<BlockedPattern>(entity =>
        {
            entity.ToTable("BlockedPatterns");
            entity.HasKey(e => e.PatternId);
            entity.HasIndex(e => e.Pattern);
            entity.Property(e => e.PatternType)
                .HasConversion<string>();
        });

        // 초기 차단 패턴 데이터 시드
        SeedBlockedPatterns(modelBuilder);

        // 기본 관리자 계정 시드
        SeedAdminUser(modelBuilder);
    }

    private static void SeedBlockedPatterns(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<BlockedPattern>().HasData(
            // SQL 인젝션 패턴
            new BlockedPattern { PatternId = 1, Pattern = @"('|""|--)\s*(or|and)\s*('|""|\d|\w+\s*=)", PatternType = PatternType.SQL_INJECTION, Description = "OR/AND 기반 SQL 인젝션" },
            new BlockedPattern { PatternId = 2, Pattern = @"union.*select", PatternType = PatternType.SQL_INJECTION, Description = "UNION SELECT 인젝션" },
            new BlockedPattern { PatternId = 3, Pattern = @"drop\s+table", PatternType = PatternType.SQL_INJECTION, Description = "DROP TABLE 시도" },
            new BlockedPattern { PatternId = 4, Pattern = @"delete\s+from", PatternType = PatternType.SQL_INJECTION, Description = "DELETE 시도" },
            new BlockedPattern { PatternId = 5, Pattern = @"insert\s+into", PatternType = PatternType.SQL_INJECTION, Description = "INSERT 시도" },
            new BlockedPattern { PatternId = 6, Pattern = @"update\s+.*\s+set", PatternType = PatternType.SQL_INJECTION, Description = "UPDATE 시도" },
            new BlockedPattern { PatternId = 7, Pattern = @"--", PatternType = PatternType.SQL_INJECTION, Description = "SQL 주석 시도" },
            new BlockedPattern { PatternId = 8, Pattern = @";\s*drop", PatternType = PatternType.SQL_INJECTION, Description = "세미콜론 DROP 시도" },
            // XSS 패턴
            new BlockedPattern { PatternId = 9, Pattern = @"<script", PatternType = PatternType.XSS, Description = "스크립트 태그 삽입" },
            new BlockedPattern { PatternId = 10, Pattern = @"javascript:", PatternType = PatternType.XSS, Description = "javascript 프로토콜" },
            new BlockedPattern { PatternId = 11, Pattern = @"onerror\s*=", PatternType = PatternType.XSS, Description = "onerror 이벤트 핸들러" },
            new BlockedPattern { PatternId = 12, Pattern = @"onload\s*=", PatternType = PatternType.XSS, Description = "onload 이벤트 핸들러" },
            new BlockedPattern { PatternId = 13, Pattern = @"onclick\s*=", PatternType = PatternType.XSS, Description = "onclick 이벤트 핸들러" },
            new BlockedPattern { PatternId = 14, Pattern = @"<iframe", PatternType = PatternType.XSS, Description = "iframe 삽입" },
            new BlockedPattern { PatternId = 15, Pattern = @"<object", PatternType = PatternType.XSS, Description = "object 태그 삽입" },
            // 경로 탐색 패턴
            new BlockedPattern { PatternId = 16, Pattern = @"\.\./", PatternType = PatternType.PATH_TRAVERSAL, Description = "상위 디렉토리 접근" },
            new BlockedPattern { PatternId = 17, Pattern = @"\.\.\\", PatternType = PatternType.PATH_TRAVERSAL, Description = "상위 디렉토리 접근 (Windows)" },
            // 명령어 인젝션 패턴
            new BlockedPattern { PatternId = 18, Pattern = @";\s*rm\s", PatternType = PatternType.COMMAND_INJECTION, Description = "rm 명령어 연결" },
            new BlockedPattern { PatternId = 19, Pattern = @"\|\s*cat\s", PatternType = PatternType.COMMAND_INJECTION, Description = "파이프 cat 명령어" },
            new BlockedPattern { PatternId = 20, Pattern = @"&&\s*rm\s", PatternType = PatternType.COMMAND_INJECTION, Description = "&& rm 명령어" }
        );
    }

    private static void SeedAdminUser(ModelBuilder modelBuilder)
    {
        // 기본 관리자 계정 (비밀번호: Admin@123!)
        // BCrypt 해시: $2a$11$... (실제로는 애플리케이션 시작 시 생성)
        modelBuilder.Entity<User>().HasData(
            new User
            {
                UserId = 1,
                Username = "admin",
                Email = "admin@safevault.com",
                PasswordHash = "$2a$11$K7oVpFHXxyN1kqwjqYz5QO4xzHjFkxdQq9VoVhFN1G8SvZXYA9IZK", // Admin@123!
                Role = "Admin",
                CreatedAt = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                UpdatedAt = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                IsActive = true
            }
        );
    }
}
