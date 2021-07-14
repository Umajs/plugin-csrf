"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TransType = void 0;
const crypto = require("crypto");
const Tokens = require("csrf");
var TransType;
(function (TransType) {
    TransType[TransType["header"] = 0] = "header";
    TransType[TransType["cookie"] = 1] = "cookie";
    TransType[TransType["body"] = 2] = "body";
})(TransType = exports.TransType || (exports.TransType = {}));
const aesEncrypt = (data, key) => {
    const cipher = crypto.createCipher('aes192', key);
    var crypted = cipher.update(data, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
};
const aesDecrypt = (encrypted, key) => {
    const decipher = crypto.createDecipher('aes192', key);
    var decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};
exports.default = (uma, opts = {}) => {
    let tokens = new Tokens();
    let options = Object.assign({ excludes: ['GET', 'HEAD', 'OPTIONS'], tokenKey: 'uma_token', secretKey: 'uma_token_key', ctxTokenKey: 'csrfToken', maxAge: 30 * 86400 * 1000, transType: TransType.header, withUid: false, uidKey: 'uid' }, opts);
    const { tokenKey, secretKey, ctxTokenKey, maxAge, excludes, transType, withUid, uidKey, } = options;
    return async (ctx, next) => {
        if (!excludes.includes(ctx.method)) {
            const secret = ctx.cookies.get(secretKey);
            let token;
            switch (transType) {
                case TransType.header:
                    token = ctx.headers && ctx.headers[tokenKey];
                    break;
                case TransType.body:
                    token = ctx.request.body && ctx.request.body[tokenKey];
                    break;
                case TransType.cookie:
                    token = ctx.cookies.get(tokenKey);
                    break;
                default:
                    token = ctx.headers && ctx.headers[tokenKey];
                    break;
            }
            if (!token || !secret) {
                ctx.throw(403, 'CSRF Token Not Found!');
            }
            if (withUid && ctx[uidKey]) {
                token = aesDecrypt(token, ctx[uidKey]);
            }
            if (!tokens.verify(secret, token)) {
                ctx.throw(403, 'CSRF Token Invalid!');
            }
        }
        const newSecret = tokens.secretSync();
        let newToken;
        if (withUid && ctx[uidKey]) {
            newToken = aesEncrypt(tokens.create(newSecret), ctx[uidKey]);
        }
        else {
            newToken = tokens.create(newSecret);
        }
        ctx[ctxTokenKey] = newToken;
        ctx.append(tokenKey, newToken);
        ctx.cookies.set(secretKey, newSecret, {
            maxAge: maxAge,
            httpOnly: true,
        });
        await next();
    };
};
