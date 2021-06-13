
require('dotenv').config();

const sign = (data) => {
    const hmac = crypto.createHmac('sha256', process.env.SESSION_KEY);
    hmac.update(data);
    return hmac.digest('hex');
};

const crypto = require('crypto');
const Koa = require('koa');
const Router = require('@koa/router');

const app = new Koa();
const router = new Router();

const {google} = require('googleapis');

const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URL,
);

const scopes = [
  'openid',
  'email',
  'profile',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

google.options({auth: oauth2Client});

router.get('/', (ctx, next) => {
    const data = ctx.cookies.get('utokyo.credentials') || '';
    const providedSignature = ctx.cookies.get('utokyo.credentials.sig') || '';
    const signature = sign(data);
    if (signature == providedSignature) {
        ctx.body = data;
        ctx.type = 'json';
    } else {
        ctx.body = 'Not signed in';
    }
});

router.get('/login', (ctx, next) => {
    const url = oauth2Client.generateAuthUrl({
        access_type: 'online',
        scope: scopes,
    });
    ctx.redirect(url);
});

router.get('/auth', async (ctx, next) => {
    const code = ctx.query.code;
    const {tokens} = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2('v2');
    const profile = (await oauth2.userinfo.get({})).data;
    const credentials = {
        profile: profile,
        tokens: tokens,
    };
    const data = JSON.stringify(credentials);
    const signature = sign(data);
    ctx.cookies.set('utokyo.credentials', data);
    ctx.cookies.set('utokyo.credentials.sig', signature);
    ctx.redirect('/');
});

app
.use(router.routes())
.use(router.allowedMethods());

app.listen(process.env.PORT || 3000);
