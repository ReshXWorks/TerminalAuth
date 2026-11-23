# TerminalAuth
TerminalAuth is a Python-based command-line authentication system built as a learning project to explore password security and Two-Factor Authentication (2FA). It combines password hashing using PBKDF2-HMAC-SHA256 with Time-Based One-Time Password (TOTP) verification using Google Authenticator.

## What I Learned?
- **Password Hashing:** Used PBKDF2-HMAC-SHA256 with 600,000 iterations and randomly generated salts to securely store passwords instead of storing them as plain text.
- **Two-Factor Authentication (2FA):** Implemented an additional authentication layer that requires a six-digit OTP after password verification.
- **TOTP (Time-Based One-Time Password):** Explored how OTPs are generated using a shared secret key and the current Unix timestamp.
- **HMAC-SHA1:** Used HMAC-SHA1 as the underlying hashing algorithm for generating TOTP codes.
- **OTP Synchronization:** Understood how Python and Google Authenticator independently generate the same six-digit OTP without directly communicating with each other.
- **Time-Based Verification:** Learned that the 30-second OTP interval is based on the global Unix clock, not on when the user registers or adds the secret to an authenticator app.
- **OTP Replay Prevention:** Implemented a mechanism to prevent an already accepted OTP time step from being reused.
- **Secure Input Handling:** Used Python's `getpass` module instead of `input()` to prevent passwords and OTPs from being visibly displayed while typing in the terminal.

## How Does It Work?
### 1. User Registration
The user creates an account by providing a username and password. A random salt is generated, and the password is processed using PBKDF2-HMAC-SHA256 before being stored in the local JSON database.
A unique TOTP secret is also generated for the user.

### 2. Google Authenticator Setup
During registration, the application displays the generated TOTP secret and an `otpauth://` provisioning URI.
The user manually adds this secret to Google Authenticator.
- Python does not directly connect to Google Authenticator. Both applications simply store the same secret key and independently calculate OTPs using the same TOTP algorithm.

### 3. How Both Applications Generate the Same OTP
Both Python and Google Authenticator use three main inputs:
- The same shared secret key.
- The current Unix timestamp.
- The same TOTP configuration (30-second interval and six-digit output).
The timestamp is divided into 30-second intervals to determine the current time step. Both applications use this time step and the shared secret to calculate the OTP.
Since both perform the same mathematical calculation independently, they generate the same six-digit code without requiring an internet connection or direct communication between the applications.
The 30-second countdown does not begin when registration is completed or when the secret is added to Google Authenticator. It follows the actual system time. Therefore, both applications remain synchronized even if their setup happens at different times.

### 4. User Login
During login, the user provides their username and password. The application verifies the password against its stored hash.
If the password is correct, the user is prompted to enter the six-digit OTP displayed in their authenticator application.
The entered OTP is independently verified using the stored secret and the current time step. Access is granted only when both authentication factors are successfully verified.

## Security Features
- Password hashing with PBKDF2-HMAC-SHA256.
- Randomly generated password salts.
- Constant-time comparison using `hmac.compare_digest()`.
- Six-digit TOTP verification.
- 30-second OTP time intervals.
- Previous, current, and next time-step tolerance for OTP verification.
- OTP replay prevention using the last accepted time step.
- Account lockout after five failed authentication attempts.
- Temporary account lockout for 60 seconds.
- Restricted database file permissions on supported operating systems.

## Python Modules Used?
This project uses Python's built-in libraries without requiring additional third-party packages.
| Module | Purpose |
|---|---|
| `os` | File operations and permissions |
| `json` | Local user database management |
| `time` | Unix timestamp and OTP intervals |
| `hmac` | HMAC generation and secure comparison |
| `hashlib` | PBKDF2 password hashing and HMAC-SHA1 |
| `secrets` | Cryptographically secure random generation |
| `base64` | Encoding and decoding salts and TOTP secrets |
| `struct` | Binary encoding of the TOTP counter |
| `getpass` | Hidden password and OTP input |
| `tempfile` | Temporary file creation during database updates |
| `urllib.parse` | TOTP provisioning URI generation |
| `pathlib` | File path management |

## Project Structure

```
TerminalAuth/
│
├── secure_login.py
├── users.json
└── README.md
```

`users.json` is automatically created when the first user registers. It stores the password hash, salt, TOTP secret, failed login attempts, lockout information, and last accepted OTP time step.

## Requirements
- Python 3.10 or later. 
  No additional Python package installations are required.
- Google Authenticator or another compatible TOTP authenticator application.

## How to Run
1. Clone or download the repository.
2. Open a terminal in the project directory.
3. Run the application:

```bash
python secure_login.py
```

Choose an option from the main menu:
1. Register – Create a new user account and configure TOTP.
2. Login – Authenticate using a password and six-digit OTP.
3. Exit – Close the application.

## Limitations and Learning Notes
This is a learning project intended to explore authentication concepts and Python security-related modules. It is not intended to be a production-ready authentication service.
Currently, TOTP secrets are stored in plain text in the local JSON database. The application also does not include password recovery, authenticator recovery, or an administrator interface.
