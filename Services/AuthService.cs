using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Models.DTOs;

namespace SafeVault.Services;

/// <summary>
/// 인증 서비스 인터페이스
/// </summary>
public interface IAuthService
{
    Task<AuthResponse> RegisterAsync(RegisterRequest request, string ipAddress, string userAgent);
    Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent);
    Task<User?> GetUserByIdAsync(int userId);
    Task<User?> GetUserByUsernameAsync(string username);
    string GenerateJwtToken(User user);
    Task<bool> ValidateUserCredentialsAsync(string username, string password);
}

/// <summary>
/// 인증 서비스 구현
/// </summary>
public class AuthService : IAuthService
{
    private readonly SafeVaultDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly IInputValidationService _validationService;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        SafeVaultDbContext context,
        IConfiguration configuration,
        IInputValidationService validationService,
        ILogger<AuthService> logger)
    {
        _context = context;
        _configuration = configuration;
        _validationService = validationService;
        _logger = logger;
    }

    public async Task<AuthResponse> RegisterAsync(RegisterRequest request, string ipAddress, string userAgent)
    {
        try
        {
            // 입력 검증
            var usernameValidation = await _validationService.ValidateInputAsync(
                request.Username, "USERNAME", ipAddress, userAgent);
            
            if (!usernameValidation.IsValid)
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = usernameValidation.Message
                };
            }

            var emailValidation = await _validationService.ValidateInputAsync(
                request.Email, "EMAIL", ipAddress, userAgent);
            
            if (!emailValidation.IsValid)
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = emailValidation.Message
                };
            }

            // 중복 검사
            if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = "이미 사용 중인 사용자명입니다."
                };
            }

            if (await _context.Users.AnyAsync(u => u.Email == request.Email))
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = "이미 사용 중인 이메일입니다."
                };
            }

            // 비밀번호 해시
            var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            // 사용자 생성
            var user = new User
            {
                Username = request.Username,
                Email = request.Email,
                PasswordHash = passwordHash,
                Role = "User",
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsActive = true
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            _logger.LogInformation("새 사용자 등록: {Username} from {IpAddress}", user.Username, ipAddress);

            var token = GenerateJwtToken(user);

            return new AuthResponse
            {
                Success = true,
                Message = "회원가입이 완료되었습니다.",
                Token = token,
                User = new UserInfo
                {
                    UserId = user.UserId,
                    Username = user.Username,
                    Email = user.Email,
                    Role = user.Role,
                    CreatedAt = user.CreatedAt
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "회원가입 중 오류 발생");
            return new AuthResponse
            {
                Success = false,
                Message = "회원가입 처리 중 오류가 발생했습니다."
            };
        }
    }

    public async Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress, string userAgent)
    {
        try
        {
            // 입력 검증
            var usernameValidation = await _validationService.ValidateInputAsync(
                request.Username, "LOGIN_USERNAME", ipAddress, userAgent);
            
            if (!usernameValidation.IsValid)
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = "유효하지 않은 입력입니다."
                };
            }

            // 사용자 조회
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Username == request.Username && u.IsActive);

            if (user == null)
            {
                _logger.LogWarning("로그인 실패 - 사용자 없음: {Username} from {IpAddress}", request.Username, ipAddress);
                
                // 로그 기록
                await _validationService.LogValidationAsync(
                    "LOGIN_ATTEMPT", request.Username, null, 
                    Models.ValidationResult.INVALID, "USER_NOT_FOUND", ipAddress, userAgent);

                return new AuthResponse
                {
                    Success = false,
                    Message = "사용자명 또는 비밀번호가 올바르지 않습니다."
                };
            }

            // 비밀번호 확인
            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                _logger.LogWarning("로그인 실패 - 비밀번호 불일치: {Username} from {IpAddress}", request.Username, ipAddress);
                
                await _validationService.LogValidationAsync(
                    "LOGIN_ATTEMPT", request.Username, null,
                    Models.ValidationResult.INVALID, "WRONG_PASSWORD", ipAddress, userAgent);

                return new AuthResponse
                {
                    Success = false,
                    Message = "사용자명 또는 비밀번호가 올바르지 않습니다."
                };
            }

            // 마지막 로그인 시간 업데이트
            user.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            _logger.LogInformation("로그인 성공: {Username} ({Role}) from {IpAddress}", 
                user.Username, user.Role, ipAddress);

            var token = GenerateJwtToken(user);

            return new AuthResponse
            {
                Success = true,
                Message = "로그인되었습니다.",
                Token = token,
                User = new UserInfo
                {
                    UserId = user.UserId,
                    Username = user.Username,
                    Email = user.Email,
                    Role = user.Role,
                    CreatedAt = user.CreatedAt
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "로그인 중 오류 발생");
            return new AuthResponse
            {
                Success = false,
                Message = "로그인 처리 중 오류가 발생했습니다."
            };
        }
    }

    public string GenerateJwtToken(User user)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey가 설정되지 않았습니다.");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var expirationMinutes = int.Parse(jwtSettings["ExpirationMinutes"] ?? "60");
        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: jwtSettings["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<User?> GetUserByIdAsync(int userId)
    {
        return await _context.Users.FindAsync(userId);
    }

    public async Task<User?> GetUserByUsernameAsync(string username)
    {
        return await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
    }

    public async Task<bool> ValidateUserCredentialsAsync(string username, string password)
    {
        var user = await GetUserByUsernameAsync(username);
        if (user == null || !user.IsActive)
            return false;

        return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
    }
}
