
export enum RedisJob {
  SEND_VERIFICATION_OTP = 'send-verification-otp',
  SEND_PASSWORD_RESET_LINK = 'send-password-reset-link',
  SEND_PASSWORD_RESET_SUCCESS_EMAIL = 'send-password-reset-success-email',
  SEND_WELCOME_EMAIL = 'send-welcome-email',
  UPLOAD_FILE = 'upload-avatar',
}

export enum LogStatus {
  SUCCESS = 'success',
  FAILED = 'failed',
}

export enum ProfileType {
  Teacher = 'teacher',
  School = 'school',
  Creator = 'creator'
}

export enum Gender {
  Male = 'male',
  Female = 'female',
  Other = 'other'
}

export enum TokenType {
  OTP = 'otp',
  RESET = 'reset'
}

export enum LessonType {
  Video = 'video',
  Text = 'text',
  Pdf = 'pdf',
  Reflection = 'reflection'
}