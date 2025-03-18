import { IsEmail, IsEnum, IsInt, IsNotEmpty, Max, Min } from 'class-validator';
import { UserRole } from 'src/entities/user.entity';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  firstName: string;

  @IsNotEmpty()
  lastName: string;

  @IsNotEmpty()
  password: string;

  @IsEnum(UserRole, { message: 'Role must be one of: admin, hr, user, guest' })
  role: UserRole;
}

export class LoginDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;

  @IsEnum(UserRole, { message: 'Role must be one of: admin, hr, user, guest' })
  role: UserRole;
}

export class ResetPasswordDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;

  @IsNotEmpty()
  confirmPassword: string;
}

export class VerifyOtpDto {
  @IsEmail()
  email: string;

  @IsInt()
  @Min(100000, { message: 'OTP must be a 6-digit number' })
  @Max(999999, { message: 'OTP must be a 6-digit number' })
  otp: number;
}

export class ForgotPasswordDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
