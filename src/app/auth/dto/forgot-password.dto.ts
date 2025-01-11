import { IsEmail, IsEnum, IsString, IsUrl } from 'class-validator';
import { ProfileType } from '../../../enums/enum';

export class ForgotPasswordDto implements Readonly<any> {
  @IsEmail({}, { message: 'email is required and must be valid' })
  email: string;

  @IsEnum(Object.values(ProfileType), { message: `profileType must be one of the following: ${Object.values(ProfileType).join(', ')}` })
  profileType: ProfileType;

  @IsUrl({}, { message: 'redirectUrl is required and must be a valid URL' })
  redirectUrl: string;
}