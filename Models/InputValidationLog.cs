using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SafeVault.Models;

/// <summary>
/// 입력 검증 로그 엔티티 - database.sql의 InputValidationLogs 테이블과 매핑
/// </summary>
public class InputValidationLog
{
    [Key]
    [Column("LogID")]
    public int LogId { get; set; }

    [Required]
    [StringLength(50)]
    public string InputType { get; set; } = string.Empty;

    public string? OriginalInput { get; set; }

    public string? SanitizedInput { get; set; }

    [Required]
    public ValidationResult ValidationResult { get; set; }

    [StringLength(100)]
    public string? ThreatType { get; set; }

    [StringLength(45)]
    public string? IpAddress { get; set; }

    public string? UserAgent { get; set; }

    [Column("CreatedAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public enum ValidationResult
{
    VALID,
    INVALID,
    BLOCKED
}
