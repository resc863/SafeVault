using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SafeVault.Models;

/// <summary>
/// 차단 패턴 엔티티 - database.sql의 BlockedPatterns 테이블과 매핑
/// </summary>
public class BlockedPattern
{
    [Key]
    [Column("PatternID")]
    public int PatternId { get; set; }

    [Required]
    [StringLength(500)]
    public string Pattern { get; set; } = string.Empty;

    [Required]
    public PatternType PatternType { get; set; }

    [StringLength(255)]
    public string? Description { get; set; }

    public bool IsActive { get; set; } = true;

    [Column("CreatedAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public enum PatternType
{
    SQL_INJECTION,
    XSS,
    PATH_TRAVERSAL,
    COMMAND_INJECTION,
    OTHER
}
