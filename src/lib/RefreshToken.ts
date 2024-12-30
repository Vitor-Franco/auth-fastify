import { JwtPayload, sign, verify } from 'jsonwebtoken';
import { env } from '../config/env';

export class RefreshToken {
  static readonly secret = env.REFRESH_TOKEN_SECRET;

  static readonly generate = (accountId: string)=> {
    return sign({
      sub: accountId,
    }, this.secret, {
      expiresIn: '10d'
    });
  };

  static readonly validate = (token: string) => {
    try {
      const payload = verify(token, this.secret) as JwtPayload;
      return payload.sub;
    } catch (error) {
      return;
    }
  };
}
