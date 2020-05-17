import express from "express";
import JWT from "../JWT";

export const isAuth = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  if (!req.headers.authorization) {
    res.send({ message: "Not authorized" });
  } else {
    try {
      let token = req.headers.authorization.split("Bearer ")[1];
      let payload = JWT.verifyAccessToken(token);

      // todo: check if payload.id is in the user's table

      if (payload) {
        next();
      }

      res.send({ message: "Not authorized" });
    } catch (error) {
      console.error(error);
      res.send({ message: "Not authorized" });
    }
  }
};
