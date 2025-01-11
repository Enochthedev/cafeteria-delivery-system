import nodemailer from 'nodemailer';
import { inject, injectable } from 'inversify';
import { LIB_TYPES } from '../di/types';
import env from './env';
import { Logger } from './logger';

@injectable()
export class MailClient {
  private readonly transporter: nodemailer.Transporter;

  constructor(@inject(LIB_TYPES.Logger) private readonly _logger: Logger) {
    this.transporter = nodemailer.createTransport({
      host: env.mail_host,
      port: env.mail_port,
      auth: {
        user: env.mail_username,
        pass: env.mail_password,
      },
    });

    this._logger.info('mail client initialized');
  }

  async sendEmail(to: string, subject: string, html: string): Promise<void> {
    try {
      const info = await this.transporter.sendMail({
        from: {
          name: 'Collabo',
          address: 'no-reply@collabo.ng',
        },
        to,
        subject,
        html: html,
        replyTo: 'no-reply@collabo.ng',
      });

      this._logger.info(`sent using nodemailer: ${info.messageId}`);
    } catch (err) {
      this._logger.error('error sending email', { error: err });
      throw new Error('error sending email');
    }
  }

  // Send an email with attachments
  /*async sendEmailWithAttachments(
    to: string,
    subject: string,
    body: string,
    attachments: { filename: string; path: string | Buffer }[],
  ): Promise<void> {
    if (env.NODE_ENV === 'dev') {
      // Sending email with attachments using Nodemailer in development
      try {
        const info = await this.transporter.sendMail({
          from: env.SMTP_FROM, // e.g., 'no-reply@example.com'
          to,
          subject,
          text: body,
          attachments, // Adding attachments
        });

        this._logger.info(`Email with attachments sent using Nodemailer: ${info.messageId}`);
      } catch (err) {
        this._logger.error('Error sending email with attachments via Nodemailer', { error: err });
        throw new Error('Error sending email with attachments via Nodemailer');
      }
    } else {
      // Sending email with attachments using AWS SES in other environments
      try {
        const base64Attachments = attachments.map((attachment) => ({
          Filename: attachment.filename,
          Data: attachment.path instanceof Buffer ? attachment.path.toString('base64') : Buffer.from(attachment.path).toString('base64'),
        }));

        const params = {
          Destination: {
            ToAddresses: [to],
          },
          Message: {
            Body: {
              Text: { Data: body },
            },
            Subject: { Data: subject },
          },
          Source: env.SES_FROM, // e.g., 'no-reply@example.com'
          Attachments: base64Attachments, // AWS SES accepts attachments in base64
        };

        const command = new SendEmailCommand(params);
        const data = await this.transporter.send(command);

        this._logger.info(`Email with attachments sent using AWS SES: ${data.MessageId}`);
      } catch (err) {
        this._logger.error('Error sending email with attachments via AWS SES', { error: err });
        throw new Error('Error sending email with attachments via AWS SES');
      }
    }
  }*/
}
