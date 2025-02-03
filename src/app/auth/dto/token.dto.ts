import { IsString, IsNotEmpty, MinLength, MaxLength, Matches } from 'class-validator';
import { IsMongoId } from 'class-validator';
import { IsPasswordStrong } from '../../../common/decorators/password-strength.decorator';
import { IsEqualTo } from '../../../common/decorators/is-equal-to.decorator';

export class TokenDto implements Readonly<any> {
  @Matches(/^\d{6}$/, { message: 'one-time passcode must be exactly 6 digits' })
  otp: string;
}

export class VerifyPasswordResetTokenDto implements Readonly<any> {
  @IsString({ message: 'token is required' })
  token: string;
}

export class ResetPasswordDto {
  password(password: any, salt: string) {
    throw new Error('Method not implemented.');
  }
  @IsMongoId({ message: 'Invalid user identifier' })
  @IsNotEmpty({ message: 'User ID is required' })
  userId: string;

  @IsString({ message: 'Reset token must be a string' })
  @IsNotEmpty({ message: 'Reset token is required' })
  token: string;

  @IsPasswordStrong({
    message: 'Password must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character',
  })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(64, { message: 'Password cannot exceed 64 characters' })
  newPassword: string;

  @IsString({ message: 'Confirmation password must be a string' })
  @IsEqualTo('newPassword', { 
    message: 'Confirmation password does not match new password' 
  })
  confirmPassword: string;
}