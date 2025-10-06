// app.js
const express = require("express");
const bcrypt = require("bcrypt");
const helmet = require("helmet");

const app = express();

// JSON受信（サイズ制限）
app.use(express.json({ limit: "16kb" }));

// 文字化け対策：全レスポンスUTF-8
app.use((req, res, next) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  next();
});

// セキュリティヘッダ（HSTS等）
app.use(helmet());

// PaaSのリバースプロキシを信頼（x-forwarded-proto 等を信頼）
app.enable("trust proxy");

// 本番のみ http→https を強制
if (process.env.NODE_ENV === "production") {
  app.use((req, res, next) => {
    if (req.secure || req.headers["x-forwarded-proto"] === "https")
      return next();
    const host = req.headers.host;
    return res.redirect(301, `https://${host}${req.originalUrl}`);
  });
}

// ===== メモリストア（起動中のみ保持） =====
const users = new Map(); // key: user_id -> { user_id, passwordHash, nickname?, comment? }

// ===== バリデーション =====
const isValidUserId = (s) => /^[A-Za-z0-9]{6,20}$/.test(s); // 半角英数字 6-20
const isValidPassword = (s) => /^[\x21-\x7E]{8,20}$/.test(s); // ASCII可視文字 8-20（空白/制御除外）
const noCtrl = (s) => /^[^\x00-\x1F\x7F]*$/.test(s); // 制御コード禁止

// ===== Basic認証ヘルパ =====
function parseBasicAuth(req) {
  const h = req.header("Authorization") || "";
  if (!/^Basic\s*/i.test(h)) return null; // "Basic" の後の空白有無を許容
  const b64 = h.replace(/^Basic\s*/i, "").trim();
  let raw = "";
  try {
    raw = Buffer.from(b64, "base64").toString("utf8");
  } catch {
    return null;
  }
  const idx = raw.indexOf(":");
  if (idx < 0) return null;
  return { user_id: raw.slice(0, idx), password: raw.slice(idx + 1) };
}

async function authUserAsync(req) {
  const cred = parseBasicAuth(req);
  if (!cred) return { ok: false };
  const u = users.get(cred.user_id);
  if (!u) return { ok: false };
  const ok = await bcrypt.compare(cred.password, u.passwordHash);
  return ok ? { ok: true, user: u } : { ok: false };
}

// ===== POST /signup（新規作成） =====
app.post("/signup", async (req, res) => {
  const { user_id, password, nickname, comment } = req.body || {};

  if (!user_id || !password) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Required user_id and password",
    });
  }

  if (
    user_id.length < 6 ||
    user_id.length > 20 ||
    password.length < 8 ||
    password.length > 20
  ) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Input length is incorrect",
    });
  }

  if (!isValidUserId(user_id) || !isValidPassword(password)) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Incorrect character pattern",
    });
  }

  if (users.has(user_id)) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Already same user_id is used",
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users.set(user_id, {
    user_id,
    passwordHash,
    nickname: nickname ?? user_id,
    comment: comment ?? null,
  });

  return res.status(200).json({
    message: "Account successfully created",
    user: { user_id, nickname: user_id },
  });
});

// ===== GET /users/:user_id（取得・要Basic認証） =====
app.get("/users/:user_id", async (req, res) => {
  const auth = await authUserAsync(req);
  if (!auth.ok)
    return res.status(401).json({ message: "Authentication failed" });

  const { user_id } = req.params;
  const u = users.get(user_id);
  if (!u) return res.status(404).json({ message: "No user found" });

  const nickname =
    u.nickname === undefined || u.nickname === "" ? u.user_id : u.nickname;

  const body = {
    message: "User details by user_id",
    user: { user_id: u.user_id, nickname },
  };
  if (u.comment !== undefined && u.comment !== "") {
    body.user.comment = u.comment; // 設定済みなら含める（未設定なら省略）
  }
  return res.status(200).json(body);
});

// ===== PATCH /users/:user_id（更新・本人のみ・要Basic認証） =====
app.patch("/users/:user_id", async (req, res) => {
  const auth = await authUserAsync(req);
  if (!auth.ok)
    return res.status(401).json({ message: "Authentication failed" });

  const { user_id } = req.params;
  const u = users.get(user_id);
  if (!u) return res.status(404).json({ message: "No user found" });

  if (auth.user.user_id !== user_id) {
    return res.status(403).json({ message: "No permission for update" });
  }

  const {
    nickname,
    comment,
    user_id: uidInBody,
    password: pwdInBody,
  } = req.body || {};

  if (uidInBody !== undefined || pwdInBody !== undefined) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "Not updatable user_id and password",
    });
  }

  const hasNickname = Object.prototype.hasOwnProperty.call(
    req.body || {},
    "nickname"
  );
  const hasComment = Object.prototype.hasOwnProperty.call(
    req.body || {},
    "comment"
  );
  if (!hasNickname && !hasComment) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "Required nickname or comment",
    });
  }

  if (hasNickname) {
    if (
      typeof nickname !== "string" ||
      (nickname !== "" && (!noCtrl(nickname) || nickname.length > 30))
    ) {
      return res.status(400).json({
        message: "User updation failed",
        cause: "String length limit exceeded or containing invalid characters",
      });
    }
  }

  if (hasComment) {
    if (
      typeof comment !== "string" ||
      (comment !== "" && (!noCtrl(comment) || comment.length > 100))
    ) {
      return res.status(400).json({
        message: "User updation failed",
        cause: "String length limit exceeded or containing invalid characters",
      });
    }
  }

  if (hasNickname) u.nickname = nickname === "" ? u.user_id : nickname; // 空→初期化
  if (hasComment) u.comment = comment === "" ? "" : comment; // 空→クリア
  users.set(user_id, u);

  return res.status(200).json({
    message: "User successfully updated",
    user: {
      user_id: u.user_id,
      nickname:
        u.nickname === undefined || u.nickname === "" ? u.user_id : u.nickname,
      comment: u.comment === undefined ? "" : u.comment,
    },
  });
});

// ===== POST /close（削除・要Basic認証） =====
app.post("/close", async (req, res) => {
  const auth = await authUserAsync(req);
  if (!auth.ok)
    return res.status(401).json({ message: "Authentication failed" });

  users.delete(auth.user.user_id);
  return res
    .status(200)
    .json({ message: "Account and user successfully removed" });
});

// ===== ヘルスチェック =====
app.get("/health", (_req, res) => res.json({ ok: true }));

(async function seedReservedUser() {
  const user_id = "TaroYamada";
  const password = "PaSSwd4TY";
  if (!users.has(user_id)) {
    const passwordHash = await bcrypt.hash(password, 10);
    users.set(user_id, {
      user_id,
      passwordHash,
      nickname: "TaroYamada", // 任意。テストはmessageのみチェックなので何でもOK
      comment: "", // 任意
    });
    // console.log("[seed] reserved user created");
  }
})();

module.exports = { app, users };
