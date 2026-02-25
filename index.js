require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoDBStoreFactory = require('connect-mongodb-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const path = require('path');

const app = express();
app.disable('x-powered-by');

const TECH_EVENTS = ['Blind Coding', 'Paper Presentation', 'Bug Smasher', 'Web Weavers'];
const NON_TECH_EVENTS = ['Gaming', 'Treasure Hunt', 'Photography'];
const MAX_LOGIN_ATTEMPTS = 5;
const ACCOUNT_LOCK_MS = 15 * 60 * 1000;
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const ABSOLUTE_SESSION_MS = 8 * 60 * 60 * 1000;
const FORCE_HTTPS = process.env.FORCE_HTTPS === 'true' || process.env.NODE_ENV === 'production';
const CONSENT_VERSION = process.env.CONSENT_VERSION || '2026-02';
const RETENTION_TEMP_USERS_DAYS = Number(process.env.RETENTION_TEMP_USERS_DAYS || 30);
const RETENTION_AUDIT_LOG_DAYS = Number(process.env.RETENTION_AUDIT_LOG_DAYS || 180);
const AUTH_ABUSE_WINDOW_MS = 15 * 60 * 1000;
const AUTH_ABUSE_THRESHOLD = Number(process.env.AUTH_ABUSE_THRESHOLD || 20);
const authAbuseTracker = new Map();
const TRUST_PROXY = process.env.TRUST_PROXY;
const trustProxySetting = TRUST_PROXY === 'true'
    ? 1
    : TRUST_PROXY === 'false'
        ? false
        : process.env.NODE_ENV === 'production' ? 1 : false;

/* ---------------- PROXY TRUST ---------------- */
app.set('trust proxy', trustProxySetting);

function validateSecurityConfig() {
    const isProduction = process.env.NODE_ENV === 'production';

    if (!process.env.MONGO_URI) {
        throw new Error('MONGO_URI is required.');
    }

    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
        const message = 'SESSION_SECRET should be set to a random value with at least 32 characters.';
        if (isProduction) {
            throw new Error(message);
        }
        console.warn(`⚠️ ${message}`);
    }

    if (FORCE_HTTPS && !trustProxySetting) {
        console.warn('⚠️ FORCE_HTTPS is enabled while trust proxy is disabled. If behind a reverse proxy, set TRUST_PROXY=true.');
    }
}

validateSecurityConfig();

function isSecureRequest(req) {
    return req.secure;
}

app.use((req, res, next) => {
    if (!FORCE_HTTPS || isSecureRequest(req)) {
        return next();
    }

    return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
});

/* ---------------- DATABASE ---------------- */
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ Mongo Error:', err));

/* ---------------- SECURITY MIDDLEWARE ---------------- */
app.use((req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    next();
});

app.use(helmet({
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                (req, res) => `'nonce-${res.locals.cspNonce}'`
            ],
            styleSrc: [
                "'self'",
                (req, res) => `'nonce-${res.locals.cspNonce}'`
            ],
            fontSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:", "https://api.qrserver.com"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            frameAncestors: ["'none'"],
            scriptSrcAttr: ["'none'"],
            styleSrcAttr: ["'none'"],
            upgradeInsecureRequests: [],
        },
    },
}));

app.use(bodyParser.urlencoded({ extended: false, limit: '10kb' }));
app.use('/vendor/bootstrap', express.static(path.join(__dirname, 'node_modules/bootstrap/dist')));
app.use('/vendor/fontawesome', express.static(path.join(__dirname, 'node_modules/@fortawesome/fontawesome-free')));
app.use('/vendor/animate', express.static(path.join(__dirname, 'node_modules/animate.css')));
app.use('/vendor/aos', express.static(path.join(__dirname, 'node_modules/aos/dist')));
app.use(express.static('public'));
app.set('view engine', 'ejs');

/* ---------------- SESSION ---------------- */
const MongoDBStore = MongoDBStoreFactory(session);
const sessionStore = new MongoDBStore({
    uri: process.env.MONGO_URI,
    collection: 'sessions'
});

sessionStore.on('error', (err) => {
    console.error('Session store error:', err);
});

app.use(session({
    name: 'symposium.sid',
    secret: process.env.SESSION_SECRET,
    proxy: true,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    unset: 'destroy',
    store: sessionStore,
    cookie: {
        httpOnly: true,
        secure: FORCE_HTTPS,
        sameSite: 'lax',
        maxAge: IDLE_TIMEOUT_MS
    }
}));

app.use((req, res, next) => {
    if (!req.session) return next();

    if (['GET', 'HEAD'].includes(req.method)) {
        res.locals.csrfToken = getCsrfToken(req);
    }

    return next();
});

app.use((req, res, next) => {
    if (!req.session) return next();

    if (['GET', 'HEAD'].includes(req.method)) {
        res.locals.csrfToken = getCsrfToken(req);
    }

    return next();
});

app.use((req, res, next) => {
    if (!req.session) return next();

    const now = Date.now();
    if (!req.session.createdAt) {
        req.session.createdAt = now;
        return next();
    }

    if ((now - req.session.createdAt) > ABSOLUTE_SESSION_MS) {
        return req.session.destroy(() => {
            res.clearCookie('symposium.sid');
            res.redirect('/?error=Session expired. Please login again.');
        });
    }

    return next();
});

/* ---------------- MAILER ---------------- */
const mailTransportConfigured = Boolean(
    process.env.SMTP_HOST &&
    process.env.SMTP_PORT &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS
);

const mailTransporter = mailTransportConfigured
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    })
    : null;

async function sendMail(to, subject, text) {
    if (!mailTransporter) {
        console.log(`[DEV OTP] To: ${to} | ${subject} | ${text}`);
        return;
    }

    await mailTransporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to,
        subject,
        text
    });
}

async function sendSecurityAlert(subject, text) {
    const alertTo = process.env.SECURITY_ALERT_TO || process.env.SMTP_FROM || process.env.SMTP_USER;
    if (!alertTo) {
        console.warn(`[SECURITY ALERT] ${subject} | ${text}`);
        return;
    }

    try {
        await sendMail(alertTo, subject, text);
    } catch (err) {
        console.error('Security alert email failed:', err);
    }
}

/* ---------------- CSRF PROTECTION ---------------- */
function getCsrfToken(req) {
    if (!Array.isArray(req.session.csrfTokens)) {
        req.session.csrfTokens = [];
    }

    const token = crypto.randomBytes(32).toString('hex');
    req.session.csrfTokens.push(token);

    if (req.session.csrfTokens.length > 25) {
        req.session.csrfTokens = req.session.csrfTokens.slice(-25);
    }

    return token;
}

function verifyCsrf(req, res, next) {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();

    const validTokens = Array.isArray(req.session.csrfTokens) ? req.session.csrfTokens : [];
    const requestToken = req.body && req.body._csrf;

    if (!requestToken) {
        return res.status(403).redirect('/?error=Invalid CSRF token. Please retry.');
    }

    const tokenIndex = validTokens.indexOf(requestToken);
    if (tokenIndex === -1) {
        return res.status(403).redirect('/?error=Invalid CSRF token. Please retry.');
    }

    validTokens.splice(tokenIndex, 1);
    req.session.csrfTokens = validTokens;

    return next();
}

app.use(verifyCsrf);

/* ---------------- RATE LIMITING ---------------- */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Too many login attempts. Please try again after 15 minutes."
});

const signupLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 8,
    message: "Too many signup attempts. Please try again after 15 minutes."
});

const registerLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: "Too many registration attempts. Please try again after 15 minutes."
});

/* ---------------- DB SCHEMA ---------------- */
const userSchema = new mongoose.Schema({
    event_id: { type: String, unique: true },
    name: String,
    email: { type: String, unique: true },
    phone: { type: String, unique: true },
    
    college: { type: String, default: 'Not Provided' },
    technical_event: { type: String, default: 'Pending' },
    non_technical_event: { type: String, default: 'Pending' },
    transaction_id: { type: String, default: null, select: false },
    transaction_id_hash: { type: String, default: null, unique: true, sparse: true },
    transaction_id_last4: { type: String, default: null, select: false },
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
    privacyConsent: { type: Boolean, default: false },
    consentVersion: { type: String, default: null },
    consentGivenAt: { type: Date, default: null },
    lastLoginAt: { type: Date, default: null },
    registeredAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

const auditLogSchema = new mongoose.Schema({
    eventType: { type: String, required: true, index: true },
    outcome: { type: String, required: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
    email: { type: String, default: null },
    route: { type: String, default: null },
    ip: { type: String, required: true, index: true },
    userAgent: { type: String, default: 'unknown' },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
    createdAt: { type: Date, default: Date.now, expires: RETENTION_AUDIT_LOG_DAYS * 24 * 60 * 60 }
});

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

/* ---------------- HELPERS ---------------- */
function isAuth(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/?error=Please login');
    }
    next();
}

app.use(['/home', '/register', '/confirmation', '/logout'], isAuth);

async function registerFailedLogin(user) {
    if (!user) return;

    const now = Date.now();
    if (user.lockUntil && user.lockUntil.getTime() > now) {
        return false;
    }

    user.loginAttempts = (user.loginAttempts || 0) + 1;
    let lockedNow = false;

    if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
        user.lockUntil = new Date(now + ACCOUNT_LOCK_MS);
        user.loginAttempts = 0;
        lockedNow = true;
    }

    await user.save();
    return lockedNow;
}

function hashSensitiveValue(value) {
    return crypto.createHash('sha256').update(String(value).trim()).digest('hex');
}

function getClientIp(req) {
    return req.ip || req.socket?.remoteAddress || 'unknown';
}

function getUserAgent(req) {
    const userAgent = req.get('user-agent') || 'unknown';
    return userAgent.slice(0, 300);
}

async function logAuditEvent({ eventType, outcome, req, userId = null, email = null, metadata = {} }) {
    try {
        await AuditLog.create({
            eventType,
            outcome,
            userId,
            email,
            route: req.originalUrl,
            ip: getClientIp(req),
            userAgent: getUserAgent(req),
            metadata
        });
    } catch (err) {
        console.error('Audit log write failed:', err.message);
    }
}

function recordAuthFailureAndMaybeAlert(req, reason) {
    const ip = getClientIp(req);
    const now = Date.now();
    const attempts = authAbuseTracker.get(ip) || [];
    const recentAttempts = attempts.filter((timestamp) => (now - timestamp) <= AUTH_ABUSE_WINDOW_MS);
    recentAttempts.push(now);
    authAbuseTracker.set(ip, recentAttempts);

    if (recentAttempts.length === AUTH_ABUSE_THRESHOLD) {
        const alertText = `Threshold reached for IP ${ip}. ${recentAttempts.length} failed auth attempts in ${AUTH_ABUSE_WINDOW_MS / 60000} minutes. Reason: ${reason}`;
        sendSecurityAlert('Auth abuse threshold reached', alertText);
        logAuditEvent({
            eventType: 'auth_abuse_threshold',
            outcome: 'alerted',
            req,
            metadata: { reason, attempts: recentAttempts.length }
        });
    }
}

app.use((req, res, next) => {
    if (!['/login', '/signup', '/register', '/logout'].includes(req.path)) {
        return next();
    }

    const startedAt = Date.now();
    res.on('finish', () => {
        logAuditEvent({
            eventType: 'auth_route_access',
            outcome: res.statusCode < 400 ? 'success' : 'failure',
            req,
            userId: req.session && req.session.userId ? req.session.userId : null,
            metadata: {
                method: req.method,
                statusCode: res.statusCode,
                durationMs: Date.now() - startedAt
            }
        });
    });

    return next();
});

async function runRetentionCleanup() {
    const staleTempCutoff = new Date(Date.now() - (RETENTION_TEMP_USERS_DAYS * 24 * 60 * 60 * 1000));

    const staleTempUsersResult = await User.deleteMany({
        event_id: { $regex: /^TEMP_/ },
        registeredAt: { $lt: staleTempCutoff }
    });

    if (staleTempUsersResult.deletedCount > 0) {
        console.log(`🧹 Retention cleanup removed ${staleTempUsersResult.deletedCount} stale temporary accounts.`);
    }

    const now = Date.now();
    for (const [ip, attempts] of authAbuseTracker.entries()) {
        const validAttempts = attempts.filter((timestamp) => (now - timestamp) <= AUTH_ABUSE_WINDOW_MS);
        if (validAttempts.length > 0) {
            authAbuseTracker.set(ip, validAttempts);
        } else {
            authAbuseTracker.delete(ip);
        }
    }
}

setInterval(() => {
    runRetentionCleanup().catch((err) => {
        console.error('Retention cleanup job failed:', err);
    });
}, 24 * 60 * 60 * 1000);

setTimeout(() => {
    runRetentionCleanup().catch((err) => {
        console.error('Initial retention cleanup failed:', err);
    });
}, 60 * 1000);

/* ---------------- ROUTES ---------------- */

// LOGIN PAGE
app.get('/', (req, res) => {
    const signupSuccessMsg = 'Account created! Please login to complete registration.';
    let error = req.query.error || null;
    let success = req.query.success || null;

    if (!success && error === signupSuccessMsg) {
        success = error;
        error = null;
    }

    res.render('login', {
        error,
        success,
        csrfToken: getCsrfToken(req)
    });
});

// LOGIN LOGIC
app.post(
    '/login',
    loginLimiter,
    body('email').isEmail().normalizeEmail(),
    body('phone').trim().isNumeric().isLength({ min: 10, max: 10 }),
    async (req, res) => {
        const genericAuthError = '/?error=Invalid credentials';
        const requestEmail = req.body && req.body.email ? req.body.email : null;

        if (!validationResult(req).isEmpty()) {
            recordAuthFailureAndMaybeAlert(req, 'input_validation_failed');
            await logAuditEvent({
                eventType: 'login',
                outcome: 'validation_failed',
                req,
                email: requestEmail
            });
            return res.redirect(genericAuthError);
        }

        const { email, phone } = req.body;

        try {
            const userByEmail = await User.findOne({ email });

            if (!userByEmail) {
                recordAuthFailureAndMaybeAlert(req, 'email_not_found');
                await logAuditEvent({
                    eventType: 'login',
                    outcome: 'user_not_found',
                    req,
                    email
                });
                return res.redirect(genericAuthError);
            }

            if (userByEmail.lockUntil && userByEmail.lockUntil.getTime() > Date.now()) {
                recordAuthFailureAndMaybeAlert(req, 'account_locked');
                await logAuditEvent({
                    eventType: 'login',
                    outcome: 'locked',
                    req,
                    userId: userByEmail._id,
                    email
                });
                return res.redirect(genericAuthError);
            }

            if (userByEmail.phone !== phone) {
                const lockedNow = await registerFailedLogin(userByEmail);
                recordAuthFailureAndMaybeAlert(req, 'phone_mismatch');
                await logAuditEvent({
                    eventType: 'login',
                    outcome: 'invalid_phone',
                    req,
                    userId: userByEmail._id,
                    email
                });

                if (lockedNow) {
                    sendSecurityAlert(
                        'Account lock triggered',
                        `Account lock triggered for user ${email} from IP ${getClientIp(req)} after repeated failed logins.`
                    );
                    await logAuditEvent({
                        eventType: 'account_lock',
                        outcome: 'locked',
                        req,
                        userId: userByEmail._id,
                        email
                    });
                }

                return res.redirect(genericAuthError);
            }

            userByEmail.loginAttempts = 0;
            userByEmail.lockUntil = null;
            userByEmail.lastLoginAt = new Date();
            await userByEmail.save();

            const loggedInUserId = String(userByEmail._id);
            req.session.regenerate((sessionErr) => {
                if (sessionErr) {
                    console.error('Session regenerate error:', sessionErr);
                    return res.redirect('/?error=Server error');
                }

                req.session.userId = loggedInUserId;
                req.session.csrfTokens = [];
                req.session.save((saveErr) => {
                    if (saveErr) {
                        console.error('Session save error:', saveErr);
                        logAuditEvent({
                            eventType: 'login',
                            outcome: 'session_save_failed',
                            req,
                            userId: loggedInUserId,
                            email
                        });
                        return res.redirect('/?error=Server error');
                    }

                    logAuditEvent({
                        eventType: 'login',
                        outcome: 'success',
                        req,
                        userId: loggedInUserId,
                        email
                    });

                    return res.redirect('/home');
                });
            });
        } catch (err) {
            console.error(err);
            await logAuditEvent({
                eventType: 'login',
                outcome: 'server_error',
                req,
                email: requestEmail,
                metadata: { message: err.message }
            });
            res.redirect('/?error=Server error');
        }
    }
);

// SIGNUP PAGE
app.get('/signup', (req, res) => {
    res.render('signup', {
        error: null,
        csrfToken: getCsrfToken(req)
    });
});

// SIGNUP LOGIC
app.post('/signup', 
    signupLimiter,
    body('email').isEmail().normalizeEmail(),
    body('phone').trim().isNumeric().isLength({ min: 10, max: 10 }),
    body('name').trim().isLength({ min: 2, max: 60 }).escape(),
    body('privacy_consent').equals('yes'),
    async (req, res) => {
        try {
            if (!validationResult(req).isEmpty()) {
                await logAuditEvent({
                    eventType: 'signup',
                    outcome: 'validation_failed',
                    req,
                    email: req.body && req.body.email ? req.body.email : null
                });
                return res.render('signup', { error: "Invalid inputs", csrfToken: getCsrfToken(req) });
            }

            const exists = await User.findOne({
                $or: [{ email: req.body.email }, { phone: req.body.phone }]
            });

            if (exists) {
                await logAuditEvent({
                    eventType: 'signup',
                    outcome: 'duplicate',
                    req,
                    email: req.body.email
                });
                return res.render('signup', { 
                    error: "Email or Phone already registered. Please Login.", 
                    csrfToken: getCsrfToken(req) 
                });
            }

            const tempEventId = 'TEMP_' + crypto.randomBytes(4).toString('hex').toUpperCase();

            const user = new User({
                event_id: tempEventId, 
                name: req.body.name,
                email: req.body.email,
                phone: req.body.phone,
                privacyConsent: true,
                consentVersion: CONSENT_VERSION,
                consentGivenAt: new Date()
            });

            await user.save();

            await logAuditEvent({
                eventType: 'signup',
                outcome: 'success',
                req,
                userId: user._id,
                email: user.email,
                metadata: { consentVersion: CONSENT_VERSION }
            });

            res.redirect('/?success=Account created! Please login to complete registration.');

        } catch (err) {
            console.error("Signup Error:", err); 
            await logAuditEvent({
                eventType: 'signup',
                outcome: 'server_error',
                req,
                email: req.body && req.body.email ? req.body.email : null,
                metadata: { message: err.message }
            });
            res.render('signup', { error: "System Error. Please try again.", csrfToken: getCsrfToken(req) });
        }
    }
);

// HOME PAGE
app.get('/home', isAuth, async (req, res) => {
    if (Object.keys(req.query || {}).length > 0) {
        return res.redirect('/home');
    }

    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            req.session.destroy();
            return res.redirect('/');
        }

        const isFullyRegistered = user.event_id && !user.event_id.startsWith('TEMP_');

        res.render('home', {
            registered: isFullyRegistered,
            event_id: user.event_id,
            user: user,
            csrfToken: getCsrfToken(req)
        });
    } catch (err) {
        console.error(err);
        req.session.destroy();
        res.redirect('/');
    }
});

// REGISTER PAGE (Pre-fill)
app.get('/register', isAuth, async (req, res) => {
    if (Object.keys(req.query || {}).length > 0) {
        return res.redirect('/register');
    }

    let user = null;
    if (req.session.userId) {
        user = await User.findById(req.session.userId);
    }
    res.render('register', {
        error: null,
        csrfToken: getCsrfToken(req),
        user: user
    });
});

// 🛡️ UPDATED REGISTER LOGIC: DUPLICATE CHECK ADDED
app.post('/register', 
    registerLimiter,
    body('college').trim().isLength({ min: 2, max: 120 }).escape(),
    body('technical_event').isIn(TECH_EVENTS),
    body('non_technical_event').isIn(NON_TECH_EVENTS),
    body('transaction_id').trim().matches(/^\d{12}$/),
    body('privacy_notice_ack').equals('yes'),
    async (req, res) => {
        try {
            if (!req.session.userId) return res.redirect('/signup');

            if (!validationResult(req).isEmpty()) {
                const user = await User.findById(req.session.userId);
                await logAuditEvent({
                    eventType: 'registration',
                    outcome: 'validation_failed',
                    req,
                    userId: req.session.userId
                });
                return res.render('register', {
                    error: "Invalid registration input. Please check all fields.",
                    csrfToken: getCsrfToken(req),
                    user: user
                });
            }

            const currentUser = await User.findById(req.session.userId);
            if (!currentUser) return res.redirect('/');

            // 1. DUPLICATE CHECK
            // Check if Transaction ID matches any OTHER user (exclude current user)
            const conflict = await User.findOne({
                _id: { $ne: currentUser._id },
                $or: [
                    { transaction_id_hash: hashSensitiveValue(req.body.transaction_id) },
                    { transaction_id: req.body.transaction_id }
                ]
            });

            if (conflict) {
                await logAuditEvent({
                    eventType: 'registration',
                    outcome: 'transaction_conflict',
                    req,
                    userId: currentUser._id,
                    email: currentUser.email
                });
                // Return to register page with error
                return res.render('register', {
                    error: "⚠️ Transaction ID is already used by another participant.",
                    csrfToken: getCsrfToken(req),
                    user: currentUser // Keep form pre-filled
                });
            }

            // 2. GENERATE ID (If needed)
            if (currentUser.event_id.startsWith('TEMP_')) {
                const lastUser = await User.findOne({ 
                    event_id: { $regex: /^sympo121/ } 
                }).sort({ event_id: -1 });
                
                let nextSequence = 1;
                if (lastUser) {
                    const currentIdStr = lastUser.event_id.replace('sympo121', '');
                    const currentIdNum = parseInt(currentIdStr, 10);
                    if (!isNaN(currentIdNum)) nextSequence = currentIdNum + 1;
                }

                const paddedSequence = nextSequence.toString().padStart(2, '0');
                currentUser.event_id = `sympo121${paddedSequence}`;
            }

            // 3. Update User
            currentUser.college = req.body.college;
            currentUser.technical_event = req.body.technical_event;
            currentUser.non_technical_event = req.body.non_technical_event;
            currentUser.transaction_id_hash = hashSensitiveValue(req.body.transaction_id);
            currentUser.transaction_id_last4 = req.body.transaction_id.slice(-4);
            currentUser.transaction_id = null;
            currentUser.privacyConsent = true;
            currentUser.consentVersion = CONSENT_VERSION;
            currentUser.consentGivenAt = currentUser.consentGivenAt || new Date();

            await currentUser.save();

            await logAuditEvent({
                eventType: 'registration',
                outcome: 'success',
                req,
                userId: currentUser._id,
                email: currentUser.email,
                metadata: {
                    technical_event: currentUser.technical_event,
                    non_technical_event: currentUser.non_technical_event
                }
            });
            
            return res.render('success', { name: currentUser.name, event_id: currentUser.event_id });

        } catch (err) {
            console.error(err);
            await logAuditEvent({
                eventType: 'registration',
                outcome: 'server_error',
                req,
                userId: req.session && req.session.userId ? req.session.userId : null,
                metadata: { message: err.message }
            });
            // Fallback for unexpected errors
            const user = await User.findById(req.session.userId);
            res.render('register', {
                error: "System error. Please verify input and try again.",
                csrfToken: getCsrfToken(req),
                user: user
            });
        }
    }
);

// CONFIRMATION TICKET
app.get('/confirmation', isAuth, async (req, res) => {
    if (Object.keys(req.query || {}).length > 0) {
        return res.redirect('/confirmation');
    }

    try {
        const user = await User.findById(req.session.userId);
        if (!user) return res.redirect('/');
        res.render('confirmation', { user });
    } catch (err) {
        res.redirect('/home');
    }
});

// LOGOUT
app.post('/logout', isAuth, (req, res) => {
    const userId = req.session.userId;
    logAuditEvent({ eventType: 'logout', outcome: 'success', req, userId });
    req.session.destroy(() => {
        res.clearCookie('symposium.sid');
        res.redirect('/');
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));