import { inject, injectable } from 'inversify';
import { DeleteObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { LIB_TYPES } from '../di/types';
import { Logger } from './logger';
import env from './env';
import { IFileUpload } from '../interfaces/interfaces';

@injectable()
export class StorageProvider {
  private readonly s3Client: S3Client;

  constructor(@inject(LIB_TYPES.Logger) private readonly _logger: Logger) {
    const awsConfig = {
      region: env.aws_region,
      credentials: {
        accessKeyId: env.aws_access_key_id,
        secretAccessKey: env.aws_secret_access_key,
      },
    };
    // this.s3Client = new S3Client(awsConfig);
    this._logger.info('s3 storage provider initialized');
  }

  public async uploadFileToBucket(
    bucketName: string,
    key: string,
    data: IFileUpload,
  ) {
    await this.s3Client.send(
      new PutObjectCommand({
        Bucket: bucketName,
        Key: key,
        Body: data.buffer,
        ContentType: data.mimetype,
        ContentLength: data.sizeInBytes,
      }),
    );

    this._logger.debug(`file uploaded to s3 bucket: ${key}`);
  }

  public async deleteFileFromBucket(bucketName: string, key: string) {
    await this.s3Client.send(
      new DeleteObjectCommand({
        Bucket: bucketName,
        Key: key,
      }),
    );

    this._logger.debug(`file deleted from s3 bucket: ${key}`);
  }
}