using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Services;

namespace SafeVault.Controllers;

/// <summary>
/// 폼 제출 API 컨트롤러
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class FormController : ControllerBase
{
    private readonly IInputValidationService _validationService;
    private readonly IAntiforgery _antiforgery;
    private readonly ILogger<FormController> _logger;

    public FormController(
        IInputValidationService validationService, 
        IAntiforgery antiforgery,
        ILogger<FormController> logger)
    {
        _validationService = validationService;
        _antiforgery = antiforgery;
        _logger = logger;
    }

    /// <summary>
    /// CSRF 토큰 발급
    /// </summary>
    [HttpGet("csrf-token")]
    public IActionResult GetCsrfToken()
    {
        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
        return Ok(new { token = tokens.RequestToken });
    }

    /// <summary>
    /// 폼 제출 처리 (webform.html에서 호출)
    /// </summary>
    [HttpPost("submit")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Submit([FromForm] FormSubmitRequest request)
    {
        var ipAddress = GetClientIpAddress();
        var userAgent = Request.Headers.UserAgent.ToString();

        // 사용자명 검증
        var usernameResult = await _validationService.ValidateUsernameAsync(request.Username);
        if (!usernameResult.IsValid)
        {
            _logger.LogWarning("폼 제출 실패 - 사용자명 검증 오류: {Message}, IP: {IpAddress}", 
                usernameResult.Message, ipAddress);
            return BadRequest(new { success = false, message = usernameResult.Message });
        }

        // 이메일 검증
        var emailResult = await _validationService.ValidateEmailAsync(request.Email);
        if (!emailResult.IsValid)
        {
            _logger.LogWarning("폼 제출 실패 - 이메일 검증 오류: {Message}, IP: {IpAddress}", 
                emailResult.Message, ipAddress);
            return BadRequest(new { success = false, message = emailResult.Message });
        }

        // 검증 통과 로그
        await _validationService.LogValidationAsync(
            "FORM_SUBMIT",
            $"username:{request.Username}|email:{request.Email}",
            $"username:{usernameResult.SanitizedInput}|email:{emailResult.SanitizedInput}",
            Models.ValidationResult.VALID,
            null,
            ipAddress,
            userAgent);

        _logger.LogInformation("폼 제출 성공: Username={Username}, IP={IpAddress}", 
            usernameResult.SanitizedInput, ipAddress);

        return Ok(new 
        { 
            success = true, 
            message = "제출되었습니다.",
            data = new 
            {
                username = usernameResult.SanitizedInput,
                email = emailResult.SanitizedInput
            }
        });
    }

    /// <summary>
    /// 입력값 검증 (실시간 검증용)
    /// </summary>
    [HttpPost("validate")]
    public async Task<IActionResult> ValidateInput([FromBody] ValidateInputRequest request)
    {
        var ipAddress = GetClientIpAddress();
        var userAgent = Request.Headers.UserAgent.ToString();

        var result = await _validationService.ValidateInputAsync(
            request.Value, 
            request.FieldType, 
            ipAddress, 
            userAgent);

        return Ok(new
        {
            valid = result.IsValid,
            message = result.Message,
            sanitizedValue = result.SanitizedInput
        });
    }

    private string GetClientIpAddress()
    {
        var forwardedFor = Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',').First().Trim();
        }

        var realIp = Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp))
        {
            return realIp;
        }

        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}

public class FormSubmitRequest
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}

public class ValidateInputRequest
{
    public string Value { get; set; } = string.Empty;
    public string FieldType { get; set; } = string.Empty;
}
