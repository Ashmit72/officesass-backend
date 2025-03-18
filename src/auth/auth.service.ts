import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import * as nodemailer from 'nodemailer';
import { User, UserRole } from 'src/entities/user.entity';
import { Repository } from 'typeorm';
import {
  ForgotPasswordDto,
  LoginDto,
  RegisterDto,
  ResetPasswordDto,
  VerifyOtpDto,
} from './dto/auth.dto';
import { configDotenv } from 'dotenv';

configDotenv();

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private readonly jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto) {
    const { firstName, lastName, email, password, role } = registerDto;
    const userExists = await this.userRepository.findOne({
      where: { email },
    });
    if (userExists) {
      throw new HttpException('User already exists', HttpStatus.BAD_REQUEST);
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = this.userRepository.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role: role as UserRole,
    });
    await this.userRepository.save(newUser);
    return {
      message: 'User registered Successfully',
    };
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.userRepository.findOne({
      where: { email },
    });
    if (!user) {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new HttpException('Invalid Password', HttpStatus.UNAUTHORIZED);
    }
    const token = this.jwtService.sign({ id: user.id, role: user.role });
    return {
      token,
    };
  }

  async forgotPassword(forgotPassword: ForgotPasswordDto) {
    const { email } = forgotPassword;
    if (!email) {
      throw new HttpException('Email is missing', HttpStatus.BAD_REQUEST);
    }
    const user = await this.userRepository.findOne({
      where: { email },
    });
    const otp = Math.floor(100000 + Math.random() * 900000);
    const expirationTime = new Date(Date.now() + 10 * 60 * 1000);
    user.otp = otp;
    user.otpExpiresAt = expirationTime;
    await this.userRepository.save(user);
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.email!,
        pass: process.env.password!,
      },
    });
    const mailOptions = {
      from: process.env.email!, // Sender address
      to: email, // Receiver's email
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is ${otp}. This OTP is valid for 10 minutes.`,
    };
    try {
      await transporter.sendMail(mailOptions);
      return {
        message: 'Email Verified OTP Sent',
      };
    } catch (error) {
      console.error('Error sending email:', error);
      return {
        error,
      };
    }
  }

  async verifyOtp(verifyOtpDto: VerifyOtpDto) {
    const { email, otp } = verifyOtpDto;
    if (!email || !otp) {
      throw new HttpException(
        'Email Or OTP is required',
        HttpStatus.BAD_REQUEST,
      );
    }
    const user = await this.userRepository.findOne({
      where: { email },
    });
    const { otp: storedOtp, otpExpiresAt } = user;
    if (new Date() > otpExpiresAt) {
      return {
        message: 'OTP has expired',
      };
    }
    if (storedOtp !== otp) {
      throw new HttpException('OTP is invalid', HttpStatus.BAD_REQUEST);
    }
    return {
      message: 'Otp Verified Successfully!',
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { email, password, confirmPassword } = resetPasswordDto;
    if (password !== confirmPassword) {
      throw new HttpException('Passwords donot match', HttpStatus.BAD_REQUEST);
    }

    const user = await this.userRepository.findOne({
      where: { email },
    });
    if (!user) {
      throw new HttpException('User does not exist', HttpStatus.BAD_REQUEST);
    }
    const hashedNewPassword = await bcrypt.hash(password, 10);
    await this.userRepository.update(
      { email },
      { password: hashedNewPassword },
    );

    return {
      message: 'Password Reset Successful!',
    };
  }
}
