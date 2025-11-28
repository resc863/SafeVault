-- database.sql
-- 사용자 테이블 (보안 강화)
CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(50) NOT NULL,
    Email VARCHAR(100) NOT NULL,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT chk_username CHECK (Username REGEXP '^[a-zA-Z0-9_]{3,50}$'),
    CONSTRAINT chk_email CHECK (Email REGEXP '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'),
    UNIQUE INDEX idx_username (Username),
    UNIQUE INDEX idx_email (Email)
);

-- 입력 검증 로그 테이블 (보안 감사용)
CREATE TABLE InputValidationLogs (
    LogID INT PRIMARY KEY AUTO_INCREMENT,
    InputType VARCHAR(50) NOT NULL,
    OriginalInput TEXT,
    SanitizedInput TEXT,
    ValidationResult ENUM('VALID', 'INVALID', 'BLOCKED') NOT NULL,
    ThreatType VARCHAR(100),
    IPAddress VARCHAR(45),
    UserAgent TEXT,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_validation_result (ValidationResult),
    INDEX idx_threat_type (ThreatType),
    INDEX idx_created_at (CreatedAt)
);

-- 차단된 패턴 테이블 (SQL 인젝션, XSS 패턴 등)
CREATE TABLE BlockedPatterns (
    PatternID INT PRIMARY KEY AUTO_INCREMENT,
    Pattern VARCHAR(500) NOT NULL,
    PatternType ENUM('SQL_INJECTION', 'XSS', 'PATH_TRAVERSAL', 'COMMAND_INJECTION', 'OTHER') NOT NULL,
    Description VARCHAR(255),
    IsActive BOOLEAN DEFAULT TRUE,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_pattern (Pattern(255))
);

-- 기본 차단 패턴 삽입
INSERT INTO BlockedPatterns (Pattern, PatternType, Description) VALUES
-- SQL 인젝션 패턴
('''.*OR.*=', 'SQL_INJECTION', 'OR 기반 SQL 인젝션'),
('UNION.*SELECT', 'SQL_INJECTION', 'UNION SELECT 인젝션'),
('DROP.*TABLE', 'SQL_INJECTION', 'DROP TABLE 시도'),
('DELETE.*FROM', 'SQL_INJECTION', 'DELETE 시도'),
('INSERT.*INTO', 'SQL_INJECTION', 'INSERT 시도'),
('UPDATE.*SET', 'SQL_INJECTION', 'UPDATE 시도'),
('--', 'SQL_INJECTION', 'SQL 주석 시도'),
-- XSS 패턴
('<script', 'XSS', '스크립트 태그 삽입'),
('javascript:', 'XSS', 'javascript 프로토콜'),
('onerror=', 'XSS', '이벤트 핸들러 삽입'),
('onload=', 'XSS', '이벤트 핸들러 삽입'),
('<iframe', 'XSS', 'iframe 삽입'),
-- 경로 탐색 패턴
('../', 'PATH_TRAVERSAL', '상위 디렉토리 접근'),
('..\\', 'PATH_TRAVERSAL', '상위 디렉토리 접근 (Windows)'),
-- 명령어 인젝션 패턴
('; rm', 'COMMAND_INJECTION', '명령어 연결'),
('| cat', 'COMMAND_INJECTION', '파이프 명령어');

-- 입력 검증 저장 프로시저 (서버 측에서 호출)
DELIMITER //

CREATE PROCEDURE ValidateAndInsertUser(
    IN p_username VARCHAR(50),
    IN p_email VARCHAR(100),
    IN p_ip_address VARCHAR(45),
    IN p_user_agent TEXT,
    OUT p_result VARCHAR(20),
    OUT p_message VARCHAR(255)
)
BEGIN
    DECLARE v_blocked_count INT DEFAULT 0;
    DECLARE v_threat_type VARCHAR(100) DEFAULT NULL;
    
    -- SQL 인젝션 및 XSS 패턴 검사
    SELECT COUNT(*), MAX(PatternType) INTO v_blocked_count, v_threat_type
    FROM BlockedPatterns 
    WHERE IsActive = TRUE 
    AND (p_username REGEXP Pattern OR p_email REGEXP Pattern);
    
    IF v_blocked_count > 0 THEN
        -- 위협 탐지 시 로그 기록
        INSERT INTO InputValidationLogs (InputType, OriginalInput, ValidationResult, ThreatType, IPAddress, UserAgent)
        VALUES ('USER_REGISTRATION', CONCAT('username:', p_username, '|email:', p_email), 'BLOCKED', v_threat_type, p_ip_address, p_user_agent);
        
        SET p_result = 'BLOCKED';
        SET p_message = '유해한 입력이 감지되었습니다.';
    ELSE
        -- 정상 입력 처리
        BEGIN
            DECLARE EXIT HANDLER FOR SQLEXCEPTION
            BEGIN
                SET p_result = 'ERROR';
                SET p_message = '데이터 저장 중 오류가 발생했습니다.';
            END;
            
            INSERT INTO Users (Username, Email) VALUES (p_username, p_email);
            
            INSERT INTO InputValidationLogs (InputType, OriginalInput, SanitizedInput, ValidationResult, IPAddress, UserAgent)
            VALUES ('USER_REGISTRATION', CONCAT('username:', p_username, '|email:', p_email), 
                    CONCAT('username:', p_username, '|email:', p_email), 'VALID', p_ip_address, p_user_agent);
            
            SET p_result = 'SUCCESS';
            SET p_message = '사용자가 성공적으로 등록되었습니다.';
        END;
    END IF;
END //

DELIMITER ;
