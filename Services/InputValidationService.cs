using System.Text.RegularExpressions;
using System.Web;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Services;

/// <summary>
/// 입력 검증 결과
/// </summary>
public class InputValidationResult
{
    public bool IsValid { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? ThreatType { get; set; }
    public string? SanitizedInput { get; set; }
}

/// <summary>
/// 입력 검증 서비스 인터페이스
/// </summary>
public interface IInputValidationService
{
    Task<InputValidationResult> ValidateInputAsync(string input, string inputType, string? ipAddress = null, string? userAgent = null);
    Task<InputValidationResult> ValidateUsernameAsync(string username);
    Task<InputValidationResult> ValidateEmailAsync(string email);
    string SanitizeInput(string input);
    string EscapeHtml(string input);
    Task LogValidationAsync(string inputType, string? originalInput, string? sanitizedInput, 
        Models.ValidationResult result, string? threatType, string? ipAddress, string? userAgent);
    Task<bool> ContainsDangerousPatternAsync(string input);
}

/// <summary>
/// 입력 검증 서비스 구현 - SQL 인젝션, XSS 등 보안 위협 탐지
/// </summary>
public class InputValidationService : IInputValidationService
{
    private readonly SafeVaultDbContext _context;
    private readonly ILogger<InputValidationService> _logger;
    
    // 정적 패턴 (데이터베이스 패턴과 함께 사용)
    private static readonly Regex[] DangerousPatterns = new[]
    {
        new Regex(@"('|""|--)\s*(or|and)\s*('|""|\d|\w+\s*=)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"["";<>{}|\\&]", RegexOptions.Compiled),
        new Regex(@"(union|select|insert|update|delete|drop|truncate|exec|execute)\s", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"<script[^>]*>|</script>|javascript:|on\w+\s*=", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"(%27)|(%22)|(%3C)|(%3E)|(%00)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"(/\*|\*/|@@|char\s*\(|nchar\s*\()", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    };

    private static readonly Regex UsernameRegex = new(@"^[a-zA-Z0-9_]+$", RegexOptions.Compiled);
    private static readonly Regex EmailRegex = new(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", RegexOptions.Compiled);

    public InputValidationService(SafeVaultDbContext context, ILogger<InputValidationService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<InputValidationResult> ValidateInputAsync(string input, string inputType, string? ipAddress = null, string? userAgent = null)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return new InputValidationResult
            {
                IsValid = false,
                Message = "입력값이 비어있습니다."
            };
        }

        // 위험 패턴 검사
        var hasDangerousPattern = await ContainsDangerousPatternAsync(input);
        if (hasDangerousPattern)
        {
            var threatType = await DetectThreatTypeAsync(input);
            
            await LogValidationAsync(inputType, input, null, Models.ValidationResult.BLOCKED, 
                threatType, ipAddress, userAgent);

            _logger.LogWarning("위험 입력 차단 - Type: {InputType}, Threat: {ThreatType}, IP: {IpAddress}", 
                inputType, threatType, ipAddress);

            return new InputValidationResult
            {
                IsValid = false,
                Message = "유해한 입력이 감지되었습니다.",
                ThreatType = threatType
            };
        }

        var sanitizedInput = SanitizeInput(input);

        await LogValidationAsync(inputType, input, sanitizedInput, Models.ValidationResult.VALID, 
            null, ipAddress, userAgent);

        return new InputValidationResult
        {
            IsValid = true,
            Message = "검증 통과",
            SanitizedInput = sanitizedInput
        };
    }

    public async Task<InputValidationResult> ValidateUsernameAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return new InputValidationResult
            {
                IsValid = false,
                Message = "사용자명은 필수입니다."
            };
        }

        if (username.Length < 3 || username.Length > 50)
        {
            return new InputValidationResult
            {
                IsValid = false,
                Message = "사용자명은 3-50자여야 합니다."
            };
        }

        if (!UsernameRegex.IsMatch(username))
        {
            return new InputValidationResult
            {
                IsValid = false,
                Message = "사용자명은 영문, 숫자, 언더스코어만 허용됩니다."
            };
        }

        if (await ContainsDangerousPatternAsync(username))
        {
            return new InputValidationResult
            {
                IsValid = false,
                Message = "유해한 입력이 감지되었습니다.",
                ThreatType = await DetectThreatTypeAsync(username)
            };
        }

        return new InputValidationResult
        {
            IsValid = true,
            Message = "유효한 사용자명입니다.",
            SanitizedInput = username
        };
    }

    public async Task<InputValidationResult> ValidateEmailAsync(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return new InputValidationResult
            {
                IsValid = false,
                Message = "이메일은 필수입니다."
            };
        }

        if (email.Length > 100)
        {
            return new InputValidationResult
            {
                IsValid = false,
                Message = "이메일은 100자 이하여야 합니다."
            };
        }

        if (!EmailRegex.IsMatch(email))
        {
            return new InputValidationResult
            {
                IsValid = false,
                Message = "유효한 이메일 형식이 아닙니다."
            };
        }

        if (await ContainsDangerousPatternAsync(email))
        {
            return new InputValidationResult
            {
                IsValid = false,
                Message = "유해한 입력이 감지되었습니다.",
                ThreatType = await DetectThreatTypeAsync(email)
            };
        }

        return new InputValidationResult
        {
            IsValid = true,
            Message = "유효한 이메일입니다.",
            SanitizedInput = email.ToLowerInvariant()
        };
    }

    public string SanitizeInput(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        // HTML 인코딩
        var sanitized = HttpUtility.HtmlEncode(input);
        
        // 제어 문자 제거
        sanitized = Regex.Replace(sanitized, @"[\x00-\x1F\x7F]", string.Empty);
        
        // 앞뒤 공백 제거
        sanitized = sanitized.Trim();

        return sanitized;
    }

    public string EscapeHtml(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        return input
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#x27;")
            .Replace("/", "&#x2F;")
            .Replace("`", "&#x60;")
            .Replace("=", "&#x3D;");
    }

    public async Task LogValidationAsync(string inputType, string? originalInput, string? sanitizedInput,
        Models.ValidationResult result, string? threatType, string? ipAddress, string? userAgent)
    {
        try
        {
            var log = new InputValidationLog
            {
                InputType = inputType,
                OriginalInput = originalInput?.Substring(0, Math.Min(originalInput.Length, 1000)), // 최대 1000자
                SanitizedInput = sanitizedInput?.Substring(0, Math.Min(sanitizedInput?.Length ?? 0, 1000)),
                ValidationResult = result,
                ThreatType = threatType,
                IpAddress = ipAddress,
                UserAgent = userAgent?.Substring(0, Math.Min(userAgent?.Length ?? 0, 500)),
                CreatedAt = DateTime.UtcNow
            };

            _context.InputValidationLogs.Add(log);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "검증 로그 저장 중 오류");
        }
    }

    public async Task<bool> ContainsDangerousPatternAsync(string input)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        // 정적 패턴 검사
        foreach (var pattern in DangerousPatterns)
        {
            if (pattern.IsMatch(input))
                return true;
        }

        // 데이터베이스의 활성 패턴 검사
        var activePatterns = await _context.BlockedPatterns
            .Where(p => p.IsActive)
            .ToListAsync();

        foreach (var blockedPattern in activePatterns)
        {
            try
            {
                var regex = new Regex(blockedPattern.Pattern, RegexOptions.IgnoreCase);
                if (regex.IsMatch(input))
                    return true;
            }
            catch (RegexParseException)
            {
                // 잘못된 정규식 패턴 무시
                _logger.LogWarning("잘못된 정규식 패턴: {Pattern}", blockedPattern.Pattern);
            }
        }

        return false;
    }

    private async Task<string?> DetectThreatTypeAsync(string input)
    {
        // SQL 인젝션 패턴
        if (Regex.IsMatch(input, @"(union|select|insert|update|delete|drop|truncate)", RegexOptions.IgnoreCase))
            return "SQL_INJECTION";

        if (Regex.IsMatch(input, @"('|""|--)\s*(or|and)", RegexOptions.IgnoreCase))
            return "SQL_INJECTION";

        // XSS 패턴
        if (Regex.IsMatch(input, @"<script|javascript:|on\w+\s*=", RegexOptions.IgnoreCase))
            return "XSS";

        // 경로 탐색 패턴
        if (Regex.IsMatch(input, @"\.\./|\.\.\\"))
            return "PATH_TRAVERSAL";

        // 명령어 인젝션 패턴
        if (Regex.IsMatch(input, @"[;&|]\s*(rm|cat|wget|curl)", RegexOptions.IgnoreCase))
            return "COMMAND_INJECTION";

        // 데이터베이스 패턴에서 탐지
        var matchedPattern = await _context.BlockedPatterns
            .Where(p => p.IsActive)
            .ToListAsync();

        foreach (var pattern in matchedPattern)
        {
            try
            {
                var regex = new Regex(pattern.Pattern, RegexOptions.IgnoreCase);
                if (regex.IsMatch(input))
                    return pattern.PatternType.ToString();
            }
            catch { }
        }

        return "UNKNOWN";
    }
}
