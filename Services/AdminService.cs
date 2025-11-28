using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Models.DTOs;

namespace SafeVault.Services;

/// <summary>
/// 관리자 서비스 인터페이스
/// </summary>
public interface IAdminService
{
    Task<UserListResponse> GetUsersAsync(int page = 1, int pageSize = 20);
    Task<User?> GetUserByIdAsync(int userId);
    Task<bool> ChangeUserRoleAsync(int userId, string newRole);
    Task<bool> DeactivateUserAsync(int userId);
    Task<bool> ActivateUserAsync(int userId);
    Task<bool> DeleteUserAsync(int userId);
    Task<ValidationLogResponse> GetValidationLogsAsync(int page = 1, int pageSize = 50, string? filterByResult = null);
    Task<List<BlockedPattern>> GetBlockedPatternsAsync();
    Task<BlockedPattern?> AddBlockedPatternAsync(AddBlockedPatternRequest request);
    Task<bool> ToggleBlockedPatternAsync(int patternId);
    Task<bool> DeleteBlockedPatternAsync(int patternId);
    Task<DashboardStats> GetDashboardStatsAsync();
}

/// <summary>
/// 대시보드 통계
/// </summary>
public class DashboardStats
{
    public int TotalUsers { get; set; }
    public int ActiveUsers { get; set; }
    public int TotalValidationLogs { get; set; }
    public int BlockedAttempts { get; set; }
    public int TotalBlockedPatterns { get; set; }
    public int ActiveBlockedPatterns { get; set; }
    public List<ThreatTypeStat> ThreatsByType { get; set; } = new();
    public List<RecentLog> RecentLogs { get; set; } = new();
}

public class ThreatTypeStat
{
    public string ThreatType { get; set; } = string.Empty;
    public int Count { get; set; }
}

public class RecentLog
{
    public int LogId { get; set; }
    public string InputType { get; set; } = string.Empty;
    public Models.ValidationResult ValidationResult { get; set; }
    public string? ThreatType { get; set; }
    public string? IpAddress { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// 관리자 서비스 구현
/// </summary>
public class AdminService : IAdminService
{
    private readonly SafeVaultDbContext _context;
    private readonly ILogger<AdminService> _logger;

    public AdminService(SafeVaultDbContext context, ILogger<AdminService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<UserListResponse> GetUsersAsync(int page = 1, int pageSize = 20)
    {
        var totalCount = await _context.Users.CountAsync();
        var users = await _context.Users
            .OrderByDescending(u => u.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(u => new UserInfo
            {
                UserId = u.UserId,
                Username = u.Username,
                Email = u.Email,
                Role = u.Role,
                CreatedAt = u.CreatedAt
            })
            .ToListAsync();

        return new UserListResponse
        {
            Users = users,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize
        };
    }

    public async Task<User?> GetUserByIdAsync(int userId)
    {
        return await _context.Users.FindAsync(userId);
    }

    public async Task<bool> ChangeUserRoleAsync(int userId, string newRole)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return false;

        if (newRole != "Admin" && newRole != "User")
            return false;

        user.Role = newRole;
        user.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        _logger.LogInformation("사용자 역할 변경: UserId={UserId}, NewRole={NewRole}", userId, newRole);
        return true;
    }

    public async Task<bool> DeactivateUserAsync(int userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return false;

        user.IsActive = false;
        user.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        _logger.LogInformation("사용자 비활성화: UserId={UserId}", userId);
        return true;
    }

    public async Task<bool> ActivateUserAsync(int userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return false;

        user.IsActive = true;
        user.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        _logger.LogInformation("사용자 활성화: UserId={UserId}", userId);
        return true;
    }

    public async Task<bool> DeleteUserAsync(int userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return false;

        _context.Users.Remove(user);
        await _context.SaveChangesAsync();

        _logger.LogInformation("사용자 삭제: UserId={UserId}", userId);
        return true;
    }

    public async Task<ValidationLogResponse> GetValidationLogsAsync(int page = 1, int pageSize = 50, string? filterByResult = null)
    {
        var query = _context.InputValidationLogs.AsQueryable();

        if (!string.IsNullOrEmpty(filterByResult) && Enum.TryParse<Models.ValidationResult>(filterByResult, out var result))
        {
            query = query.Where(l => l.ValidationResult == result);
        }

        var totalCount = await query.CountAsync();
        var logs = await query
            .OrderByDescending(l => l.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return new ValidationLogResponse
        {
            Logs = logs,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize
        };
    }

    public async Task<List<BlockedPattern>> GetBlockedPatternsAsync()
    {
        return await _context.BlockedPatterns
            .OrderByDescending(p => p.CreatedAt)
            .ToListAsync();
    }

    public async Task<BlockedPattern?> AddBlockedPatternAsync(AddBlockedPatternRequest request)
    {
        // 중복 검사
        if (await _context.BlockedPatterns.AnyAsync(p => p.Pattern == request.Pattern))
        {
            _logger.LogWarning("중복 패턴 추가 시도: {Pattern}", request.Pattern);
            return null;
        }

        var pattern = new BlockedPattern
        {
            Pattern = request.Pattern,
            PatternType = request.PatternType,
            Description = request.Description,
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        _context.BlockedPatterns.Add(pattern);
        await _context.SaveChangesAsync();

        _logger.LogInformation("새 차단 패턴 추가: PatternId={PatternId}, Type={PatternType}", 
            pattern.PatternId, pattern.PatternType);
        
        return pattern;
    }

    public async Task<bool> ToggleBlockedPatternAsync(int patternId)
    {
        var pattern = await _context.BlockedPatterns.FindAsync(patternId);
        if (pattern == null)
            return false;

        pattern.IsActive = !pattern.IsActive;
        await _context.SaveChangesAsync();

        _logger.LogInformation("차단 패턴 토글: PatternId={PatternId}, IsActive={IsActive}", 
            patternId, pattern.IsActive);
        return true;
    }

    public async Task<bool> DeleteBlockedPatternAsync(int patternId)
    {
        var pattern = await _context.BlockedPatterns.FindAsync(patternId);
        if (pattern == null)
            return false;

        _context.BlockedPatterns.Remove(pattern);
        await _context.SaveChangesAsync();

        _logger.LogInformation("차단 패턴 삭제: PatternId={PatternId}", patternId);
        return true;
    }

    public async Task<DashboardStats> GetDashboardStatsAsync()
    {
        var stats = new DashboardStats
        {
            TotalUsers = await _context.Users.CountAsync(),
            ActiveUsers = await _context.Users.CountAsync(u => u.IsActive),
            TotalValidationLogs = await _context.InputValidationLogs.CountAsync(),
            BlockedAttempts = await _context.InputValidationLogs
                .CountAsync(l => l.ValidationResult == Models.ValidationResult.BLOCKED),
            TotalBlockedPatterns = await _context.BlockedPatterns.CountAsync(),
            ActiveBlockedPatterns = await _context.BlockedPatterns.CountAsync(p => p.IsActive)
        };

        // 위협 유형별 통계
        stats.ThreatsByType = await _context.InputValidationLogs
            .Where(l => l.ThreatType != null)
            .GroupBy(l => l.ThreatType!)
            .Select(g => new ThreatTypeStat
            {
                ThreatType = g.Key,
                Count = g.Count()
            })
            .OrderByDescending(t => t.Count)
            .Take(10)
            .ToListAsync();

        // 최근 로그
        stats.RecentLogs = await _context.InputValidationLogs
            .OrderByDescending(l => l.CreatedAt)
            .Take(10)
            .Select(l => new RecentLog
            {
                LogId = l.LogId,
                InputType = l.InputType,
                ValidationResult = l.ValidationResult,
                ThreatType = l.ThreatType,
                IpAddress = l.IpAddress,
                CreatedAt = l.CreatedAt
            })
            .ToListAsync();

        return stats;
    }
}
