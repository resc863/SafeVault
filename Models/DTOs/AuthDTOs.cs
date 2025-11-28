using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models.DTOs;

/// <summary>
/// 사용자 등록 요청 DTO
/// </summary>
public class RegisterRequest
{
    [Required(ErrorMessage = "사용자명은 필수입니다.")]
    [StringLength(50, MinimumLength = 3, ErrorMessage = "사용자명은 3-50자여야 합니다.")]
    [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "사용자명은 영문, 숫자, 언더스코어만 허용됩니다.")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "이메일은 필수입니다.")]
    [StringLength(100, ErrorMessage = "이메일은 100자 이하여야 합니다.")]
    [EmailAddress(ErrorMessage = "유효한 이메일 형식이 아닙니다.")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "비밀번호는 필수입니다.")]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "비밀번호는 8-100자여야 합니다.")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "비밀번호 확인은 필수입니다.")]
    [Compare("Password", ErrorMessage = "비밀번호가 일치하지 않습니다.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

/// <summary>
/// 로그인 요청 DTO
/// </summary>
public class LoginRequest
{
    [Required(ErrorMessage = "사용자명은 필수입니다.")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "비밀번호는 필수입니다.")]
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// 인증 응답 DTO
/// </summary>
public class AuthResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? Token { get; set; }
    public UserInfo? User { get; set; }
}

/// <summary>
/// 사용자 정보 DTO (비밀번호 제외)
/// </summary>
public class UserInfo
{
    public int UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}
