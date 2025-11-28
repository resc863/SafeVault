using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Models.DTOs;
using SafeVault.Services;

namespace SafeVault.Controllers;

/// <summary>
/// 관리자 전용 API 컨트롤러
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = "AdminOnly")]
public class AdminController : ControllerBase
{
    private readonly IAdminService _adminService;
    private readonly ILogger<AdminController> _logger;

    public AdminController(IAdminService adminService, ILogger<AdminController> logger)
    {
        _adminService = adminService;
        _logger = logger;
    }

    /// <summary>
    /// 대시보드 통계 조회
    /// </summary>
    [HttpGet("dashboard")]
    [ProducesResponseType(typeof(DashboardStats), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetDashboardStats()
    {
        var stats = await _adminService.GetDashboardStatsAsync();
        return Ok(stats);
    }

    /// <summary>
    /// 사용자 목록 조회
    /// </summary>
    [HttpGet("users")]
    [ProducesResponseType(typeof(UserListResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        var users = await _adminService.GetUsersAsync(page, pageSize);
        return Ok(users);
    }

    /// <summary>
    /// 특정 사용자 조회
    /// </summary>
    [HttpGet("users/{id}")]
    [ProducesResponseType(typeof(UserInfo), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetUser(int id)
    {
        var user = await _adminService.GetUserByIdAsync(id);
        if (user == null)
        {
            return NotFound(new { message = "사용자를 찾을 수 없습니다." });
        }

        return Ok(new UserInfo
        {
            UserId = user.UserId,
            Username = user.Username,
            Email = user.Email,
            Role = user.Role,
            CreatedAt = user.CreatedAt
        });
    }

    /// <summary>
    /// 사용자 역할 변경
    /// </summary>
    [HttpPut("users/{id}/role")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ChangeUserRole(int id, [FromBody] ChangeRoleRequest request)
    {
        if (id != request.UserId)
        {
            return BadRequest(new { message = "사용자 ID가 일치하지 않습니다." });
        }

        var result = await _adminService.ChangeUserRoleAsync(id, request.NewRole);
        if (!result)
        {
            return NotFound(new { message = "사용자를 찾을 수 없거나 역할 변경에 실패했습니다." });
        }

        _logger.LogInformation("관리자가 사용자 역할 변경: UserId={UserId}, NewRole={NewRole}", id, request.NewRole);
        return Ok(new { message = "역할이 변경되었습니다." });
    }

    /// <summary>
    /// 사용자 비활성화
    /// </summary>
    [HttpPut("users/{id}/deactivate")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeactivateUser(int id)
    {
        var result = await _adminService.DeactivateUserAsync(id);
        if (!result)
        {
            return NotFound(new { message = "사용자를 찾을 수 없습니다." });
        }

        _logger.LogInformation("관리자가 사용자 비활성화: UserId={UserId}", id);
        return Ok(new { message = "사용자가 비활성화되었습니다." });
    }

    /// <summary>
    /// 사용자 활성화
    /// </summary>
    [HttpPut("users/{id}/activate")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ActivateUser(int id)
    {
        var result = await _adminService.ActivateUserAsync(id);
        if (!result)
        {
            return NotFound(new { message = "사용자를 찾을 수 없습니다." });
        }

        _logger.LogInformation("관리자가 사용자 활성화: UserId={UserId}", id);
        return Ok(new { message = "사용자가 활성화되었습니다." });
    }

    /// <summary>
    /// 사용자 삭제
    /// </summary>
    [HttpDelete("users/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var result = await _adminService.DeleteUserAsync(id);
        if (!result)
        {
            return NotFound(new { message = "사용자를 찾을 수 없습니다." });
        }

        _logger.LogWarning("관리자가 사용자 삭제: UserId={UserId}", id);
        return Ok(new { message = "사용자가 삭제되었습니다." });
    }

    /// <summary>
    /// 검증 로그 조회
    /// </summary>
    [HttpGet("logs")]
    [ProducesResponseType(typeof(ValidationLogResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetValidationLogs(
        [FromQuery] int page = 1, 
        [FromQuery] int pageSize = 50,
        [FromQuery] string? filter = null)
    {
        var logs = await _adminService.GetValidationLogsAsync(page, pageSize, filter);
        return Ok(logs);
    }

    /// <summary>
    /// 차단 패턴 목록 조회
    /// </summary>
    [HttpGet("patterns")]
    [ProducesResponseType(typeof(List<BlockedPattern>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetBlockedPatterns()
    {
        var patterns = await _adminService.GetBlockedPatternsAsync();
        return Ok(patterns);
    }

    /// <summary>
    /// 차단 패턴 추가
    /// </summary>
    [HttpPost("patterns")]
    [ProducesResponseType(typeof(BlockedPattern), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> AddBlockedPattern([FromBody] AddBlockedPatternRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var pattern = await _adminService.AddBlockedPatternAsync(request);
        if (pattern == null)
        {
            return BadRequest(new { message = "패턴 추가에 실패했습니다. 이미 존재하는 패턴일 수 있습니다." });
        }

        _logger.LogInformation("관리자가 차단 패턴 추가: PatternId={PatternId}", pattern.PatternId);
        return CreatedAtAction(nameof(GetBlockedPatterns), new { id = pattern.PatternId }, pattern);
    }

    /// <summary>
    /// 차단 패턴 활성화/비활성화 토글
    /// </summary>
    [HttpPut("patterns/{id}/toggle")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ToggleBlockedPattern(int id)
    {
        var result = await _adminService.ToggleBlockedPatternAsync(id);
        if (!result)
        {
            return NotFound(new { message = "패턴을 찾을 수 없습니다." });
        }

        _logger.LogInformation("관리자가 차단 패턴 토글: PatternId={PatternId}", id);
        return Ok(new { message = "패턴 상태가 변경되었습니다." });
    }

    /// <summary>
    /// 차단 패턴 삭제
    /// </summary>
    [HttpDelete("patterns/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteBlockedPattern(int id)
    {
        var result = await _adminService.DeleteBlockedPatternAsync(id);
        if (!result)
        {
            return NotFound(new { message = "패턴을 찾을 수 없습니다." });
        }

        _logger.LogWarning("관리자가 차단 패턴 삭제: PatternId={PatternId}", id);
        return Ok(new { message = "패턴이 삭제되었습니다." });
    }
}
