import {TransType} from '../plugins/csrf'
export default {
    'csrf': {
        enable: true,
        options: {
            // excluded: ['GET', 'HEAD', 'OPTIONS'],
            // tokenKey: 'csrf_token',
            // secretKey: 'csrf_token_key',
            // ctxTokenKey: 'csrfToken',
            withUid: true,
            transType:TransType.header,
        },
    },
};
