import express, { Application, Request } from "express";
import bodyparser from "body-parser";
import cookieparser from "cookie-parser";

import JWT from "./JWT";
import { isAuth } from "./middleware/isAuth";

const app: Application = express();

app.use(bodyparser.json());
app.use(cookieparser());

app.get("/", (req: express.Request, res: express.Response) => {
  console.log(
    "Refresh token should be undefined for every path except /refresh-token =",
    req.cookies.refreshtoken === undefined
  );
  res.send({ message: "Hello" });
});

app.get("/users", isAuth, (_, res: express.Response) => {
  res.send({
    message: "Users fetched successfully",
    users: [
      { id: 1, name: "Adithya", email: "a@a.com" },
      { id: 2, name: "Siddarth", email: "s@s.com" },
    ],
  });
});

app.post("/login", (req: express.Request, res: express.Response) => {
  try {
    let { email, password } = req.body;
    // lets ignore email and password validations for now.
    if (!email.trim() || !password.trim()) {
      res.status(400).send({ sucess: false, message: "Invalid creds..." });
    } else {
      // check whether user exists in the db.
      // and sign the access and refresh token using their id and token version.
      // Token version can be incremented every time the user's access is revoked (logged out from all devices,
      // , user lost their account details to a hacker to make the tokens invalid.)

      res.setHeader("authorization", JWT.createAccessToken(1)); // consider the user id is 1

      // set refresh token inside the cookies.
      JWT.sendRefreshToken(res, 1, 1); // id and token version will be fetched from the db.

      res.send({ success: true, message: "Signed in" });
    }
  } catch (error) {
    console.error("Auth error", error);
    res.send({ success: false, message: "Something went wrong..." });
  }
});

app.post(
  "/refresh-token",
  async (req: express.Request, res: express.Response) => {
    try {
      let token = req.cookies.refreshtoken;
      if (!token) res.status(401).send({ message: "Invalid token" });
      else {
        const payload = JWT.verifyRefreshToken(token);

        // find a user with user.id === payload.id
        // then compare user.token_version and payload.tokenVersion.

        // replace 1 with user.token_version
        if ((payload as any).tokenVersion! === 1) {
          res.setHeader("authorization", JWT.createAccessToken(1));
          JWT.sendRefreshToken(res, 1, 1);

          res.send({ message: "Token refreshed..." });
        }
      }
    } catch (error) {
      console.error(error);
      res.end({ message: "Something went wrong" });
    }
  }
);

app.listen(8080, () => console.log("Listening on port 8080"));
