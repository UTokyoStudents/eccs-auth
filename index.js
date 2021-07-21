// vim: ts=4 sw=4 et ai

require('dotenv').config();
const { Sequelize, DataTypes } = require('sequelize');

/* Definitions */
const ECCS_HOSTED_DOMAIN = 'g.ecc.u-tokyo.ac.jp';
const ECCS_ID_PATTERN = /^([0-9]{10})@g\.ecc\.u-tokyo\.ac\.jp$/;

const {
    MARIADB_DB,
    MARIADB_USER,
    MARIADB_PASS,
} = process.env;

const sequelize = new Sequelize(MARIADB_DB, MARIADB_USER, MARIADB_PASS, {
    host: 'localhost',
    dialect: 'mariadb',
});

const User = sequelize.define('User', {
    // SAEC Account ID
    userId: {
        type: DataTypes.UUID,
        allowNull: false,
        defaultValue: DataTypes.UUIDV4,
        unique: true,
    },

    // UTokyo Account ID (10 digits)
    eccsId: {
        type: DataTypes.STRING,
        allowNull: true,
    },

    // Student ID
    studentId: {
        type: DataTypes.STRING,
        allowNull: true,
    },

    // This is not unique.
    userName: {
        type: DataTypes.STRING,
        allowNull: true,
    },

    // milliseconds since UNIX epoch
    eccsTimestamp: {
        type: DataTypes.DOUBLE,
        allowNull: true,
    },

    emailAddress: {
        type: DataTypes.STRING,
        allowNull: true,
    },
}, {});

sequelize.sync({alter: true}).then(() => {
    console.log('Database synced');
}).catch((e) => {
    console.error('Database sync failed');
});

const DOMAIN = 'u-tokyo.app.';


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

const oauth2 = google.oauth2('v2');
const people = google.people('v1');

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
    ctx.redirect(url + '&hd=' + ECCS_HOSTED_DOMAIN);
});

router.get('/auth', async (ctx, next) => {
    try {
        const code = ctx.query.code;
        const {tokens} = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(tokens);
        const person = (await people.people.get({
            resourceName: 'people/me',
            personFields: 'emailAddresses',
        })).data;

        const utokyoIds = [];
        for (const obj of person.emailAddresses) {
            if ('string' != typeof obj.value) continue;
            const matches = obj.value.match(ECCS_ID_PATTERN);
            if (matches) {
                utokyoIds.push(matches[1]);
            }
        }

        if (utokyoIds.length < 1) {
            throw new Error('No UTokyo account ID available for account');
        }

        const credentials = {
            utokyo_id: utokyoIds[0],
            email_addresses: person.emailAddresses.map(obj => obj.value).filter(value => 'string' == typeof value),
        };

        const data = JSON.stringify(credentials);
        const signature = sign(data);
        ctx.cookies.set('utokyo.credentials', data);
        ctx.cookies.set('utokyo.credentials.sig', signature);
        ctx.redirect('/');
    } catch (e) {
        console.error(e);
        ctx.body = JSON.stringify({
            error: e + '',
        });
        ctx.type = 'json';
    }
    
});

app
.use(router.routes())
.use(router.allowedMethods());

app.listen(process.env.PORT || 3000);
