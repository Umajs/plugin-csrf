import * as Koa from 'koa';
import { Uma, IContext } from '@umajs/core';
import * as crypto from 'crypto';
import Tokens = require('csrf');

/** token 传输类型，包括 header、cookie 和body三种方式 */
export enum TransType {
    'header',
    'cookie',
    'body',
}

/**
 * @name Options - 插件配置项
 * @property {string} tokenKey - token key
 * @property {string} secretKey - 密钥 key
 * @property {Array<string>} excludes - 不检查的方法
 * @property {number} maxAge - cookie 有效期
 * @property {TransType} transType - 前端传递token的方式
 * @property {string} ctxTokenKey - 挂载在ctx上的token
 * @property {boolean} withUid - token是否关联uid
 * @property {string} uidKey - 挂载在ctx上的uid key
 */
export type Options = {
    tokenKey?: string;
    secretKey?: string;
    excludes?: Array<string>;
    maxAge?: number;
    transType?: TransType;
    ctxTokenKey?: string;
    withUid?: boolean;
    uidKey?: string;
};
/** aes加密 */
const aesEncrypt = (data: string, key: string): string => {
    const cipher = crypto.createCipher('aes192', key);
    var crypted = cipher.update(data, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
};
/** aes解密 */
const aesDecrypt = (encrypted: string, key: string): string => {
    const decipher = crypto.createDecipher('aes192', key);
    var decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

export default (uma: Uma, opts: Options = {}): Koa.Middleware => {
    let tokens = new Tokens();
    let options: Options = {
        excludes: ['GET', 'HEAD', 'OPTIONS'],
        tokenKey: 'uma_token',
        secretKey: 'uma_token_key',
        ctxTokenKey: 'csrfToken',
        maxAge: 30 * 86400 * 1000,
        transType: TransType.header,
        withUid: false,
        uidKey: 'uid',
        ...opts,
    };

    const {
        tokenKey,
        secretKey,
        ctxTokenKey,
        maxAge,
        excludes,
        transType,
        withUid,
        uidKey,
    } = options;

    return async (ctx: IContext, next: Function) => {
        if (!excludes.includes(ctx.method)) {
            const secret = ctx.cookies.get(secretKey);

            let token: string;
            // 根据约定的传输类型从请求获取token
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
        let newToken: string;
        // 生成token
        if (withUid && ctx[uidKey]) {
            newToken = aesEncrypt(tokens.create(newSecret), ctx[uidKey]);
        } else {
            newToken = tokens.create(newSecret);
        }


        // token 存储在 header，同时挂载在ctx上
        ctx[ctxTokenKey] = newToken;
        ctx.append(tokenKey, newToken);
        ctx.append('Access-Control-Expose-Headers', tokenKey);
        
        // secretKey 存储在cookie
        ctx.cookies.set(secretKey, newSecret, {
            maxAge: maxAge,
            httpOnly: true,
        });

        await next();
    };
};
