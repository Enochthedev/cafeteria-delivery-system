import { Job } from 'bullmq';
import { Logger } from './logger';
import { LogStatus, ProfileType, RedisJob } from '../enums/enum';
import { promisify } from 'util';
import { readFile } from 'node:fs';
import { join } from 'node:path';
import Handlebars from 'handlebars';
import * as process from 'node:process';
import { IFileUpload, ILog } from '../interfaces/interfaces';
import { MailClient } from './mail';
import { StorageProvider } from './cloud.storage';

export interface JobData {
  data: any;
  ip: string,
  userAgent: string,
  timestamp: string,
  requestId: string,
}

export async function processJobs(job: Job<JobData>, mailClient: MailClient, storageProvider: StorageProvider, logger: Logger): Promise<void> {
  try {
    logger.debug(`processing job ${job.id} with data`);
    const { ip, requestId, timestamp, userAgent } = job.data;
    const readFileAsync = promisify(readFile);

    switch (job.name as RedisJob) {
      case RedisJob.SEND_VERIFICATION_OTP: {
        const { name, email, otp, expiresIn } = job.data.data;
        const htmlPath = join(process.cwd(), './emails/verify-email.html');
        const html = await readFileAsync(htmlPath, 'utf8');
        const template = Handlebars.compile(html);
        const subject = 'Welcome to Collabo.ng🥳 - Verify your Account';
        const mail = template({
          name: name,
          otp: otp,
          expiresIn: expiresIn,
          year: new Date().getFullYear(),
        });

        await mailClient.sendEmail(email, subject, mail);

        const payload: ILog = {
          action: job.name,
          data: undefined,
          description: 'verification otp sent successfully',
          ipAddress: ip,
          userAgent: userAgent,
          requestId: requestId,
          timestamp: timestamp,
          status: LogStatus.SUCCESS,
          details: {},
        };
        logger.debug(`job ${job.id} processed successfully`, payload);

        break;
      }
      case RedisJob.SEND_WELCOME_EMAIL: {
        const { name, email, } = job.data.data;
        const htmlPath = join(process.cwd(), './emails/welcome-email.html');
        const html = await readFileAsync(htmlPath, 'utf8');
        const template = Handlebars.compile(html);
        const subject = 'Welcome to Collabo.ng🥳 - Your thriving career begins here...';
        const mail = template({
          // name: name,
          year: new Date().getFullYear(),
        });

        await mailClient.sendEmail(email, subject, mail);
        break;
      }
      case RedisJob.SEND_PASSWORD_RESET_LINK: {
        const { name, email, link, expiresIn } = job.data.data;
        const htmlPath = join(process.cwd(), './emails/forgot-password.html');
        const html = await readFileAsync(htmlPath, 'utf8');
        const template = Handlebars.compile(html);
        const subject = 'Reset your password🔐';
        const mail = template({
          name: name,
          link: link,
          year: new Date().getFullYear(),
          // expiresIn: expiresIn
        });

        await mailClient.sendEmail(email, subject, mail);

        const payload: ILog = {
          action: job.name,
          data: undefined,
          description: 'password reset link sent successfully',
          ipAddress: ip,
          userAgent: userAgent,
          requestId: requestId,
          timestamp: timestamp,
          status: LogStatus.SUCCESS,
          details: {},
        };
        logger.debug(`job ${job.id} processed successfully`, payload);

        break;
      }
      case RedisJob.SEND_PASSWORD_RESET_SUCCESS_EMAIL: {
        const { name, email } = job.data.data;
        const htmlPath = join(process.cwd(), './emails/password-reset-success.html');
        const html = await readFileAsync(htmlPath, 'utf8');
        const template = Handlebars.compile(html);
        const subject = 'Your Password has been Successfully Reset👍';
        const mail = template({
          name: name,
          loginUrl: 'https://collabo.ng/login',
          year: new Date().getFullYear(),
        });

        await mailClient.sendEmail(email, subject, mail);

        const payload: ILog = {
          action: job.name,
          data: undefined,
          description: 'password reset success email sent successfully',
          ipAddress: ip,
          userAgent: userAgent,
          requestId: requestId,
          timestamp: timestamp,
          status: LogStatus.SUCCESS,
          details: {},
        };
        logger.debug(`job ${job.id} processed successfully`, payload);

        break;
      }
      case RedisJob.UPLOAD_FILE: {
        const { upload, key, bucketName } = job.data.data;

        await storageProvider.uploadFileToBucket(bucketName, key, upload as IFileUpload);

        const payload: ILog = {
          action: job.name,
          data: undefined,
          description: 'file uploaded successfully',
          ipAddress: ip,
          userAgent: userAgent,
          requestId: requestId,
          timestamp: timestamp,
          status: LogStatus.SUCCESS,
          details: {},
        };
        logger.debug(`job ${job.id} processed successfully`, payload);
        break;
      }
      default:
        throw new Error(`unknown job name: ${job.name}`);
    }
  } catch (error) {
    const payload: ILog = {
      action: job.name,
      data: undefined,
      description: `failed to process job ${job.id}`,
      ipAddress: job.data.ip,
      userAgent: job.data.userAgent,
      requestId: job.data.requestId,
      timestamp: job.data.timestamp,
      status: LogStatus.FAILED,
      details: { error: error },
    };
    logger.error(`job ${job.id} failed`, payload);
  }
}