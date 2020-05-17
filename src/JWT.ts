import { sign, verify } from "jsonwebtoken";
import { Response } from "express";

class JWT {
  accessSecret: string;
  refreshSecret: string;

  constructor() {
    this.accessSecret = "secret1";
    this.refreshSecret = "secret2";
  }

  createAccessToken = (id: number): string =>
    sign({ id }, this.accessSecret, { expiresIn: "15m" });

  verifyAccessToken = (token: string) => verify(token, this.accessSecret);

  verifyRefreshToken = (token: string) => verify(token, this.refreshSecret);

  createRefreshToken(id: number, tokenVersion: number): string {
    return sign({ id, tokenVersion }, this.refreshSecret, { expiresIn: "7d" });
  }

  sendRefreshToken = (
    res: Response,
    id: number,
    tokenVersion: number
  ): Response<void> => {
    return res.cookie(
      "refreshtoken",
      this.createRefreshToken(id, tokenVersion),
      {
        httpOnly: true,
        path: "/refresh-token",
      }
    );
  };

  revokeRefreshToken = (res: Response, user) => {
    //   revoke user's token by incrementing the tokenVersion by 1
    //   example using knex:
    //   knex('users')
    //     .where({id: user.id})
    //     .update({token_version: user.token_version + 1})

    // clear cookies
    res.clearCookie("refreshtoken");
    return true;
  };
}

export default new JWT();
