using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

// ===== 서비스 등록 =====

// 컨트롤러 추가
builder.Services.AddControllers();

// OpenAPI/Swagger 설정
builder.Services.AddOpenApi();

// Entity Framework - InMemory 데이터베이스 사용 (개발/테스트용)
builder.Services.AddDbContext<SafeVaultDbContext>(options =>
    options.UseInMemoryDatabase("SafeVaultDb"));

// JWT 인증 설정
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey가 설정되지 않았습니다.");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
        ClockSkew = TimeSpan.Zero // 토큰 만료 시간 정확히 적용
    };

    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
            {
                context.Response.Headers["Token-Expired"] = "true";
            }
            return Task.CompletedTask;
        }
    };
});

// 권한 부여 정책 설정
builder.Services.AddAuthorization(options =>
{
    // 관리자 전용 정책
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin"));

    // 일반 사용자 이상 정책
    options.AddPolicy("UserOrAbove", policy =>
        policy.RequireRole("User", "Admin"));
});

// CSRF 보호 (Antiforgery)
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "SafeVault.Antiforgery";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// CORS 설정
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigins", policy =>
    {
        var allowedOrigins = builder.Configuration.GetSection("Security:AllowedOrigins").Get<string[]>() 
            ?? new[] { "http://localhost:5000" };
        
        policy.WithOrigins(allowedOrigins)
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// 커스텀 서비스 등록
builder.Services.AddScoped<IInputValidationService, InputValidationService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IAdminService, AdminService>();

// 로깅 설정
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

var app = builder.Build();

// ===== 데이터베이스 초기화 (시드 데이터 적용) =====
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<SafeVaultDbContext>();
    context.Database.EnsureCreated();
}

// ===== 미들웨어 파이프라인 구성 =====

// 개발 환경에서 Swagger 활성화
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// 보안 헤더 추가 미들웨어
app.Use(async (context, next) =>
{
    // XSS 방지
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    // MIME 스니핑 방지
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    // 클릭재킹 방지
    context.Response.Headers["X-Frame-Options"] = "DENY";
    // HSTS (HTTPS 강제)
    if (context.Request.IsHttps)
    {
        context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
    }
    // CSP (콘텐츠 보안 정책)
    context.Response.Headers["Content-Security-Policy"] = 
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;";
    // Referrer 정책
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    
    await next();
});

// HTTPS 리다이렉션
app.UseHttpsRedirection();

// 정적 파일 서비스 (webform.html 등)
app.UseStaticFiles();

// CORS
app.UseCors("AllowSpecificOrigins");

// 인증 및 권한 부여
app.UseAuthentication();
app.UseAuthorization();

// 컨트롤러 라우팅
app.MapControllers();

// 루트 경로에서 webform.html 서비스
app.MapGet("/", async context =>
{
    context.Response.ContentType = "text/html";
    var filePath = Path.Combine(app.Environment.ContentRootPath, "webform.html");
    if (File.Exists(filePath))
    {
        await context.Response.SendFileAsync(filePath);
    }
    else
    {
        context.Response.StatusCode = 404;
        await context.Response.WriteAsync("webform.html not found");
    }
});

// 폼 제출 엔드포인트 (webform.html에서 사용)
app.MapPost("/submit", async (HttpContext context, IInputValidationService validationService) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = form["username"].ToString();
    var email = form["email"].ToString();
    
    var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var userAgent = context.Request.Headers.UserAgent.ToString();

    var usernameResult = await validationService.ValidateUsernameAsync(username);
    var emailResult = await validationService.ValidateEmailAsync(email);

    if (!usernameResult.IsValid || !emailResult.IsValid)
    {
        context.Response.StatusCode = 400;
        return Results.Json(new { success = false, message = usernameResult.Message ?? emailResult.Message });
    }

    return Results.Json(new { success = true, message = "제출되었습니다." });
});

// 헬스 체크 엔드포인트
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

app.Run();
