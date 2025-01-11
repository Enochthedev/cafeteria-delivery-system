import { parsePhoneNumberWithError } from 'libphonenumber-js';
import jwt from 'jsonwebtoken';
import { ProfileType } from '../../enums/enum';
import env from '../../config/env';

export default class Default {
  constructor() {
  };

  public static GENERATE_ACCESS_TOKEN = (userId: string, email: string, sessionId: number) => {
    return jwt.sign({
      email: email,
      type: 'access',
      lastLogin: sessionId,
    }, env.jwt_access_secret, { expiresIn: '20m', subject: userId });
  };

  public static GENERATE_REFRESH_TOKEN = (userId: string, email: string, profileType: ProfileType, rememberMe: boolean = false) => {
    return jwt.sign({
      email: email,
      profileType: profileType,
      type: 'refresh',
    }, env.jwt_refresh_secret, { expiresIn: rememberMe ? '30d' : '5d', subject: userId });
  };

  public static GENERATE_PASSWORD_RESET_TOKEN = (userId: string, email: string, profileType: ProfileType, expiresIn: number) => {
    return jwt.sign({
      email: email,
      profileType: profileType,
      type: 'password-reset',
    }, env.jwt_password_reset_secret, { expiresIn: `${expiresIn}m`, subject: userId });
  };

  public static PREFIX_AWS_KEY = (key: string) => {
    return `v2/${env.node_env}/${key}`;
  };

  public static FORMAT_AWS_S3_URL = (bucket: string, key: string) => `https://${bucket}.s3.amazonaws.com/${key}`;

  public static FORMAT_DEFAULT_AVATAR_URL = (name: string) => {
    return `https://ui-avatars.com/api/?name=${name}&background=random&color=fff`;
  };

  public static FORMAT_TO_TITLE_CASE = (text: string) => {
    return text.replace(/\w\S*/g, (word) => (word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()));
  };

  public static GENERATE_SLUG = (name: string, includeRandomChars: boolean = true) => {
    const slug = name.toLowerCase().replace(/ /g, '-');
    const randomSuffix = Math.random().toString(36).substring(2, 6);
    return includeRandomChars ? `${slug}-${randomSuffix}` : slug;
  };

  public static FORMAT_NAIRA = (amount: number) => {
    const numericAmount = parseFloat(String(amount));

    if (!isNaN(numericAmount)) {
      return `NGN ${numericAmount.toLocaleString()}`;
    } else {
      return 'NGN 0.00';
    }
  };

  public static FORMAT_PHONE_AS_INTERNATIONAL = (code: number, number: string) => {
    const phoneNumber = parsePhoneNumberWithError(number, { defaultCallingCode: code.toString() });
    return phoneNumber.format('E.164');
  };

  public static FORMAT_DATE(value: string | Date) {
    const date = typeof value === 'string' ? new Date(value) : value;

    if (isNaN(date.getTime())) {
      return 'Invalid Date';
    }
    ;

    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[date.getMonth()];
    const day = date.getDate();
    const year = date.getFullYear();

    let hours = date.getHours();
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const ampm = hours >= 12 ? 'pm' : 'am';

    hours = hours % 12;
    hours = hours ? hours : 12;

    return `${month} ${day}, ${year} ${hours}:${minutes}${ampm}`;
  };

  public static GENERATE_REQUEST_ID(): string {
    const prefix: string = 'REQ_';
    const length: number = 18;
    const randomNumber: number = Math.floor(Math.random() * Math.pow(10, length - prefix.length));
    return prefix + randomNumber.toString().padStart(length - prefix.length, '0');
  };

  public static GENERATE_RANDOM_ID(prefix: string = 'REX_', length: number = 18): string {
    const randomNumber: number = Math.floor(Math.random() * Math.pow(10, length - prefix.length));
    return prefix + randomNumber.toString().padStart(length - prefix.length, '0');
  };

  public static GENERATE_OTP(length: number = 6): string {
    let OTP = '';
    for (let i = 0; i < length; i++) {
      OTP += Math.floor(Math.random() * 10).toString();
    }
    return OTP;
  };

  public static GENERATE_PASSWORD = (length: number = 12): string => {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let PASSWORD = '';
    for (let i = 0; i < length; i++) {
      PASSWORD += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return PASSWORD;
  };
}
