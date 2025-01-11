import { IsEmail, IsString } from 'class-validator';

export class CreateUserDto {
  @IsString({ message: 'firstName is required' })
  readonly firstName?: string;

  @IsString({ message: 'lastName is required' })
  readonly lastName?: string;

  @IsEmail({}, { message: 'email is required' })
  readonly email: string;

  @IsString({ message: 'password is required' })
  readonly password: string;

  @IsString({ message: 'callingCode is required' })
  readonly callingCode: number;

  @IsString({ message: 'nationalNumber is required' })
  readonly nationalNumber: string;
}

export class UpdatePhoneNumberDto implements Readonly<any> {
  @IsString({ message: 'callingCode is required' })
  readonly callingCode: number;

  @IsString({ message: 'nationalNumber is required' })
  readonly nationalNumber: string;
}

export class UpdatePasswordDto implements Readonly<any> {
  @IsString({ message: 'oldPassword is required' })
  readonly oldPassword: string;

  @IsString({ message: 'newPassword is required' })
  readonly newPassword: string;
}