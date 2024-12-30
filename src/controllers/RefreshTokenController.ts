import { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { RefreshToken } from '../lib/RefreshToken';

export class RefreshTokenController {
  static schema = z.object({
    refreshToken: z.string(),
  });

  static handle = async (request: FastifyRequest, reply: FastifyReply) => {
    const result = this.schema.safeParse(request.body);

    if (!result.success) {
      return reply.code(400).send({ errors: result.error.issues });
    }

    const { refreshToken } = result.data;

    const accountId = RefreshToken.validate(refreshToken);

    if (!accountId) {
      return reply.code(401).send({ message: 'Invalid refresh token' });
    }

    const accessToken = await reply.jwtSign({ sub: accountId });
    const newRefreshToken = RefreshToken.generate(accountId);

    return reply.code(200).send({
      accessToken,
      refreshToken: newRefreshToken,
    });
  };
}
