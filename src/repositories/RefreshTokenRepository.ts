import { prismaClient } from '../lib/prisma';

interface CreateDTO {
  accountId: string;
  token: string;
}

export class RefreshTokenRepository {
  static findByToken(token: string) {
    return prismaClient.refreshToken.findFirst({
      where: {
        token,
      }
    });
  }

  static create({accountId,token}: CreateDTO) {
    return prismaClient.refreshToken.create({
      data: {
        token,
        accountId,
      }
    });
  }

  static delete(token: string) {
    return prismaClient.refreshToken.deleteMany({
      where: {
        token,
      }
    });
  }

  static deleteAllByAccountId(accountId: string) {
    return prismaClient.refreshToken.deleteMany({
      where: {
        accountId
      }
    });
  }
}
