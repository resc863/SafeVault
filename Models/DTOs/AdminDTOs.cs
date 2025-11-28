using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models.DTOs;

/// <summary>
/// 사용자 목록 조회 응답
/// </summary>
public class UserListResponse
{
    public List<UserInfo> Users { get; set; } = new();
    public int TotalCount { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
}

/// <summary>
/// 사용자 역할 변경 요청
/// </summary>
public class ChangeRoleRequest
{
    [Required]
    public int UserId { get; set; }

    [Required]
    [RegularExpression(@"^(Admin|User)$", ErrorMessage = "역할은 'Admin' 또는 'User'만 가능합니다.")]
    public string NewRole { get; set; } = string.Empty;
}

/// <summary>
/// 차단 패턴 추가 요청
/// </summary>
public class AddBlockedPatternRequest
{
    [Required]
    [StringLength(500)]
    public string Pattern { get; set; } = string.Empty;

    [Required]
    public PatternType PatternType { get; set; }

    [StringLength(255)]
    public string? Description { get; set; }
}

/// <summary>
/// 검증 로그 조회 응답
/// </summary>
public class ValidationLogResponse
{
    public List<InputValidationLog> Logs { get; set; } = new();
    public int TotalCount { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
}
