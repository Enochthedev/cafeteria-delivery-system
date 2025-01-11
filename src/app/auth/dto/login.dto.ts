import { ProfileType } from '../../../enums/enum';
import { IsEmail, IsEnum, IsString } from 'class-validator';
import { CreateUserDto } from '../../users/dto/user.dto';

export class LoginDto implements Pick<CreateUserDto, 'email' | 'password'> {
  @IsEmail({}, { message: 'email is required and must be valid' })
  email: string;

  @IsString({ message: 'password is required' })
  password: string;
}