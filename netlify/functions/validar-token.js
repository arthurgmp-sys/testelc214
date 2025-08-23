// netlify/functions/validar-token.js

const crypto = require("crypto");

const LINK_KEY = process.env.LINK_KEY || ""; // mesma chave usada em entrar.js

exports.handler = async (event) => {
  try {
    const token =
      (event.queryStringParameters && event.queryStringParameters.token) || "";

    // token precisa ter formato "exp.assinatura"
    const [exp, signature] = token.split(".");

    let success = false;

    if (LINK_KEY && exp && signature) {
      const expected = crypto
        .createHmac("sha256", LINK_KEY)
        .update(exp)
        .digest("hex");

      const now = Math.floor(Date.now() / 1000);
      if (expected === signature && now <= parseInt(exp, 10)) {
        success = true;
      }
    }

    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ success }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ success: false }),
    };
  }
};
