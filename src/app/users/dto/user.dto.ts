import { IsString, IsEmail, IsOptional, IsNumber, IsObject, IsArray, IsBoolean } from 'class-validator';

export class CreateUserDto {
  @IsString({ message: 'username is required' })
  readonly username: string;

  @IsString({ message: 'matricNumber is required' })
  readonly matricNumber: string;

  @IsEmail({}, { message: 'email is required' })
  readonly email: string;

  @IsString({ message: 'password is required' })
  readonly password: string;

  @IsNumber ({}, { message: 'callingCode must be a number' })
  readonly callingCode?: number;

  @IsNumber ({}, { message: 'Phone Number is required' })
  readonly phoneNumber?: number;

  @IsString({ message: 'firstName is required' })
  readonly firstName: string;

  @IsString({ message: 'lastName is required' })
  readonly lastName: string;


  @IsString({ message: 'campus is required' })
  readonly campus: string;

  @IsString({ message: 'department is required' })
  readonly department: string;

  @IsNumber({}, { message: 'level must be a number' })
  readonly level: number;

  @IsString({ message: 'hostel is required' })
  readonly hostel: string;

  @IsString({ message: 'referralCode must be a string' })
  @IsOptional()
  readonly referralCode?: string;

  @IsString({ message: 'referredBy must be a string' })
  @IsOptional()
  readonly referredBy?: string;

  @IsString({ message: 'profileImage must be a string' })
  @IsOptional()
  readonly profileImage?: string;

  // let's work on the location 
  @IsObject({ message: 'location must be an object' })
  readonly location: {
    readonly longitude: string;
    readonly latitude: string;
  };

  // let's work on the idCardData
  @IsObject({ message: 'idCardData must be an object' })
  readonly idCardData: {
    readonly front: string;
    readonly back: string;
  };
}