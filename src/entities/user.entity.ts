import { IsEmail, IsNotEmpty } from 'class-validator';
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

export enum UserRole {
  ADMIN = 'admin',
  HR = 'hr',
  USER = 'user',
  GUEST = 'guest',
}

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @IsNotEmpty({ message: 'First name is required' })
  @Column()
  firstName: string;

  @IsNotEmpty({ message: 'Last name is required' })
  @Column({ unique: true })
  lastName: string;

  @IsEmail()
  @Column()
  email: string;

  @Column({
    type: 'enum',
    enum: UserRole,
  })
  role: UserRole;

  @IsNotEmpty({ message: 'Password is required' })
  @Column()
  password: string;

  @Column({ nullable: true })
  otp: number;

  @Column({ type: 'timestamp', nullable: true })
  otpExpiresAt: Date;
}
