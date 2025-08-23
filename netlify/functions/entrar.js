// netlify/functions/entrar.js
const crypto = require("crypto");

// ====== CONFIG ======
const LINK_KEY = process.env.LINK_KEY || "";              // mesma chave já usada hoje
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || "quiz_auth";
const COOKIE_MAX_AGE = Number(process.env.COOKIE_MAX_AGE || 120); // em segundos
const REDIRECT_OK = process.env.REDIRECT_OK || "/quiz/";  // para onde mandar após logar
// ====================

function sign(data, key) {
  return crypto.createHmac("sha256", key).update(String(data)).digest("hex");
}

exports.handler = async (event) => {
  try {
    // 1) BLOQUEIA GET/“link copiado”
    if (event.httpMethod !== "POST") {
      return {
        statusCode: 405,
        headers: { "content-type": "text/plain; charset=utf-8", "allow": "POST" },
        body: "Method Not Allowed",
      };
    }

    // 2) Lê corpo (aceita x-www-form-urlencoded ou JSON)
    const ct = (event.headers["content-type"] || "").toLowerCase();
    let body = {};
    if (ct.includes("application/x-www-form-urlencoded")) {
      body = Object.fromEntries(new URLSearchParams(event.body || ""));
    } else if (ct.includes("application/json")) {
      try { body = JSON.parse(event.body || "{}"); } catch (_) { body = {}; }
    } else if (ct.includes("multipart/form-data")) {
      // Netlify não decodifica multipart aqui; se sua plataforma usar multipart,
      // troque para x-www-form-urlencoded. Mantemos 400 para evitar bypass.
      return {
        statusCode: 400,
        headers: { "content-type": "text/plain; charset=utf-8" },
        body: "Bad Request (use application/x-www-form-urlencoded ou JSON)",
      };
    }

    // 3) Exige segredo via POST (não mais via query string)
    const k = String(body.k || "");
    if (!LINK_KEY || k !== LINK_KEY) {
      return {
        statusCode: 403,
        headers: { "content-type": "text/html; charset=utf-8" },
        body: `<h1>Acesso negado</h1><p>Use o botão da plataforma para entrar.</p>`,
      };
    }

    // 4) Emite cookie (expiração + HMAC, mesmo formato exp.hmac)
    const exp = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
    const token = `${exp}.${sign(exp, LINK_KEY)}`;

    // 5) Cabeçalho Set-Cookie
    const cookieParts = [
      `${SESSION_COOKIE_NAME}=${token}`,
      "Path=/",
      `Max-Age=${COOKIE_MAX_AGE}`,
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
    ];
    const headers = {
      "set-cookie": cookieParts.join("; "),
      "cache-control": "no-store",
      "content-type": "text/html; charset=utf-8",
      "location": REDIRECT_OK,
    };

    // 6) Redireciona para /quiz/ já autenticado
    return { statusCode: 302, headers, body: "Redirecting..." };

  } catch (err) {
    return {
      statusCode: 500,
      headers: { "content-type": "text/plain; charset=utf-8" },
      body: "Erro interno: " + String(err),
    };
  }
};
