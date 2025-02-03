// security.utils.ts
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import zxcvbn from 'zxcvbn';

export class SecurityUtils {
  static generateSecureToken(bytes = 32): string {
    return crypto.randomBytes(bytes).toString('hex');
  }

  static validatePasswordComplexity(password: string): boolean {
    // NIST SP 800-63B guidelines
    const minLength = 8;
    const maxLength = 64;
    const strength = zxcvbn(password).score;
    
    return password.length >= minLength && 
           password.length <= maxLength &&
           strength >= 3;
  }

  static async checkPasswordBreach(password: string): Promise<boolean> {
    const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = hash.slice(0, 5);
    
    try {
      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      const results = await response.text();
      return results.includes(hash.slice(5));
    } catch (error) {
      return false;
    }
  }
}