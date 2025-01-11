import { IsNumber, IsOptional, IsString, validateSync } from 'class-validator';
import { BasicConfig, loadEnv } from '../internal/env';

export class ApplicationEnv extends BasicConfig {
  @IsNumber({}, { message: 'bcrypt rounds must be a number' })
  @IsOptional()
  readonly bcrypt_rounds: number;

  @IsString({ message: 'mongo uri is required' })
  @IsOptional()
  readonly mongo_uri: string;

  @IsString({ message: 'redis host is required' })
  @IsOptional()
  readonly redis_host: string;

  @IsNumber({}, { message: 'redis port must be a number' })
  @IsOptional()
  readonly redis_port: number;

  @IsString({ message: 'jwt access secret is required' })
  @IsOptional()
  readonly jwt_access_secret: string;

  @IsString({ message: 'jwt refresh secret is required' })
  @IsOptional()
  readonly jwt_refresh_secret: string;

  @IsString({ message: 'jwt password reset secret is required' })
  @IsOptional()
  readonly jwt_password_reset_secret: string;

  @IsString({ message: 'mail host is required' })
  @IsOptional()
  readonly mail_host: string;

  @IsNumber({}, { message: 'mail port must be a number' })
  @IsOptional()
  readonly mail_port: number;

  @IsString({ message: 'mail username is required' })
  @IsOptional()
  readonly mail_username: string;

  @IsString({ message: 'mail password is required' })
  @IsOptional()
  readonly mail_password: string;

  @IsString({ message: 'mail tls is required' })
  @IsOptional()
  readonly mail_tls: string;

  @IsString({ message: 'aws access key id is required' })
  @IsOptional()
  readonly aws_access_key_id: string;

  @IsString({ message: 'aws secret access key is required' })
  @IsOptional()
  readonly aws_secret_access_key: string;

  @IsString({ message: 'aws region is required' })
  @IsOptional()
  readonly aws_region: string;

  @IsString({ message: 'aws public bucket is required' })
  @IsOptional()
  readonly aws_s3_public_bucket: string;

  @IsString({ message: 'aws private bucket is required' })
  @IsOptional()
  readonly aws_s3_private_bucket: string;


  constructor(config?: Partial<ApplicationEnv>) {
    super(config);

    if (config) {
      Object.assign(this, {
        bcrypt_rounds: config.bcrypt_rounds ?? this.bcrypt_rounds,
        // mongo
        mongo_uri: config.mongo_uri ?? this.mongo_uri,
        // redis
        redis_host: config.redis_host ?? this.redis_host,
        redis_port: config.redis_port ?? this.redis_port,
        // jwt
        jwt_access_secret: config.jwt_access_secret ?? this.jwt_access_secret,
        jwt_refresh_secret: config.jwt_refresh_secret ?? this.jwt_refresh_secret,
        jwt_password_reset_secret: config.jwt_password_reset_secret ?? this.jwt_password_reset_secret,
        //   smtp
        mail_host: config.mail_host ?? this.mail_host,
        mail_port: config.mail_port ?? this.mail_port,
        mail_username: config.mail_username ?? this.mail_username,
        mail_password: config.mail_password ?? this.mail_password,
        mail_tls: config.mail_tls ?? this.mail_tls,
        //   aws
        aws_access_key_id: config.aws_access_key_id ?? this.aws_access_key_id,
        aws_secret_access_key: config.aws_secret_access_key ?? this.aws_secret_access_key,
        aws_region: config.aws_region ?? this.aws_region,
        aws_s3_public_bucket: config.aws_s3_public_bucket ?? this.aws_s3_public_bucket,
        aws_s3_private_bucket: config.aws_s3_private_bucket ?? this.aws_s3_private_bucket,
      });
    }

    this.validate();
  }

  validate(): void {
    super.validate();

    const errors = validateSync(this, {
      validationError: {
        target: false,
        value: false,
      },
    });

    if (errors.length > 0) {
      const errorMessages = errors.map(
        error => Object.values(error.constraints || {}).join(', '),
      ).join('; ');

      throw new Error(`Environment Configuration Validation Failed: ${errorMessages}`);
    }
  }
}

const env: ApplicationEnv = loadEnv(ApplicationEnv);

export default env;