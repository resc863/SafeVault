# SafeVault

SafeVault is a **security-focused ASP.NET Core Web API** application. It protects user input from various security threats such as SQL injection, XSS, and command injection, while providing JWT-based authentication and role-based access control.

## 🛡️ Key Features

### Security Features
- **Input Validation & Sanitization**: Detection and blocking of SQL injection, XSS, path traversal, command injection, etc.
- **JWT Authentication**: Secure token-based user authentication
- **Role-Based Access Control (RBAC)**: Permission management based on Admin and User roles
- **CSRF Protection**: Defense against CSRF attacks using Antiforgery tokens
- **CORS Configuration**: API access restricted to allowed origins only
- **Security Audit Logging**: All input validation events are logged

### API Endpoints

#### Authentication (`/api/auth`)
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user information

#### Form Processing (`/api/form`)
- `GET /api/form/csrf-token` - Issue CSRF token
- `POST /api/form/submit` - Form submission (with input validation)
- `POST /api/form/validate` - Real-time input validation

#### Admin (`/api/admin`) - Requires Admin role
- `GET /api/admin/dashboard` - Dashboard statistics
- `GET /api/admin/users` - Get user list
- `GET /api/admin/users/{id}` - Get specific user
- `PUT /api/admin/users/{id}/role` - Change user role
- `PUT /api/admin/users/{id}/deactivate` - Deactivate user

## 🛠️ Tech Stack

- **.NET 10.0**
- **ASP.NET Core Web API**
- **Entity Framework Core** (InMemory Database)
- **JWT Bearer Authentication**
- **BCrypt.Net** (Password Hashing)

## 🚀 Getting Started

### Prerequisites

- [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) or later

### Installation & Running

#### 1. Clone the Repository

```bash
git clone https://github.com/resc863/SafeVault.git
cd SafeVault
```

#### 2. Create `appsettings.json` File

> ⚠️ **Important**: The `appsettings.json` file is not included in the GitHub repository for security reasons. You must create it manually in the project root directory using the template below.

Create an `appsettings.json` file in the project root with the following content:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "SafeVault": "Debug"
    }
  },
  "AllowedHosts": "*",
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=SafeVaultDb;Trusted_Connection=True;MultipleActiveResultSets=true"
  },
  "JwtSettings": {
    "SecretKey": "YourSuperSecretKeyThatIsAtLeast32CharactersLong!",
    "Issuer": "SafeVault",
    "Audience": "SafeVaultUsers",
    "ExpirationMinutes": 60
  },
  "Security": {
    "EnableRateLimiting": true,
    "MaxRequestsPerMinute": 100,
    "EnableCors": true,
    "AllowedOrigins": [ "http://localhost:5000", "https://localhost:5001" ]
  }
}
```

##### Configuration Options

| Section | Key | Description |
|---------|-----|-------------|
| `Logging` | `LogLevel` | Log level configuration |
| `ConnectionStrings` | `DefaultConnection` | Database connection string (currently using InMemory DB) |
| `JwtSettings` | `SecretKey` | **🔐 Must Change** - Secret key for JWT signing (minimum 32 characters) |
| `JwtSettings` | `Issuer` | JWT issuer |
| `JwtSettings` | `Audience` | JWT audience |
| `JwtSettings` | `ExpirationMinutes` | Token expiration time (in minutes) |
| `Security` | `EnableRateLimiting` | Enable/disable rate limiting |
| `Security` | `MaxRequestsPerMinute` | Maximum requests per minute |
| `Security` | `AllowedOrigins` | List of allowed CORS origins |

##### Tips for Generating SecretKey

Use the following methods to generate a secure secret key:

**PowerShell:**
```powershell
[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(64))
```

**Linux/macOS:**
```bash
openssl rand -base64 64
```

#### 3. Development Configuration File (Optional)

If you need additional settings for the development environment, you can also create an `appsettings.Development.json` file:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "Microsoft.AspNetCore": "Information",
      "SafeVault": "Debug"
    }
  }
}
```

#### 4. Build and Run the Application

```bash
# Restore dependencies
dotnet restore

# Build
dotnet build

# Run
dotnet run
```

Once the application starts, you can access it at:
- **HTTP**: `http://localhost:5000`
- **HTTPS**: `https://localhost:5001`

#### 5. Test the API

You can test the API through OpenAPI (Swagger) UI:
```
https://localhost:5001/openapi/v1.json
```

Alternatively, use the provided `SafeVault.http` file with the REST Client extension for testing.

## 📁 Project Structure

```
SafeVault/
├── Controllers/
│   ├── AdminController.cs      # Admin API
│   ├── AuthController.cs       # Authentication API
│   └── FormController.cs       # Form Processing API
├── Data/
│   └── SafeVaultDbContext.cs   # Entity Framework Context
├── Models/
│   ├── BlockedPattern.cs       # Blocked Pattern Model
│   ├── InputValidationLog.cs   # Validation Log Model
│   ├── User.cs                 # User Model
│   └── DTOs/                   # Data Transfer Objects
├── Services/
│   ├── AdminService.cs         # Admin Service
│   ├── AuthService.cs          # Authentication Service
│   └── InputValidationService.cs # Input Validation Service
├── Tests/
│   └── TestInputValidation.cs  # Input Validation Tests
├── admin.html                  # Admin Page
├── webform.html                # Web Form Page
├── Program.cs                  # Application Entry Point
├── database.sql                # Database Schema
└── appsettings.json            # Configuration File (must be created manually)
```

## 🔒 Security Considerations

1. **Always use a strong SecretKey in production environments.**
2. **Always enable HTTPS.**
3. **Restrict AllowedOrigins to your actual domains.**
4. **Regularly update security patterns.**

## 📝 License

This project is licensed under the MIT License.
