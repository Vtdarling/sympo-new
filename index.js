require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');

const app = express();
app.disable('x-powered-by');

const TECH_EVENTS = ['Blind Coding', 'Paper Presentation', 'Bug Smasher', 'Web Weavers'];
const NON_TECH_EVENTS = ['Gaming', 'Treasure Hunt', 'Photography'];
const MAX_LOGIN_ATTEMPTS = 5;
const ACCOUNT_LOCK_MS = 15 * 60 * 1000;
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const ABSOLUTE_SESSION_MS = 8 * 60 * 60 * 1000;

/* ---------------- PROXY TRUST ---------------- */
app.set('trust proxy', 1);

/* ---------------- DATABASE ---------------- */
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ Mongo Error:', err));

/* ---------------- SECURITY MIDDLEWARE ---------------- */
app.use(helmet({
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://unpkg.com", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:", "https://api.qrserver.com"],
            upgradeInsecureRequests: [],
        },
    },
}));

app.use(bodyParser.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

/* ---------------- SESSION ---------------- */
app.use(session({
    name: 'symposium.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    unset: 'destroy',
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI
    }),
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: IDLE_TIMEOUT_MS
    }
}));

app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production' && !req.secure) {
        return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
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
    transaction_id: { type: String }, 
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
    recoveryCodeHash: { type: String, default: null },
    recoveryCodeExpires: { type: Date, default: null },
    registeredAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

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
        return;
    }

    user.loginAttempts = (user.loginAttempts || 0) + 1;

    if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
        user.lockUntil = new Date(now + ACCOUNT_LOCK_MS);
        user.loginAttempts = 0;
    }

    await user.save();
}

function generateNumericCode(length = 6) {
    const min = 10 ** (length - 1);
    const max = (10 ** length) - 1;
    return String(crypto.randomInt(min, max + 1));
}

function hashCode(code) {
    return crypto.createHash('sha256').update(code).digest('hex');
}

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
        if (!validationResult(req).isEmpty()) {
            return res.redirect('/?error=Invalid credentials format');
        }

        const { email, phone } = req.body;

        try {
            const userByEmail = await User.findOne({ email });

            if (!userByEmail) {
                return res.redirect('/?error=Invalid credentials');
            }

            if (userByEmail.lockUntil && userByEmail.lockUntil.getTime() > Date.now()) {
                return res.redirect('/?error=Account temporarily locked. Use recovery or try later.');
            }

            if (userByEmail.phone !== phone) {
                await registerFailedLogin(userByEmail);
                return res.redirect('/?error=Invalid credentials');
            }

            userByEmail.loginAttempts = 0;
            userByEmail.lockUntil = null;
            await userByEmail.save();

            const otpCode = generateNumericCode(6);
            req.session.pendingMfa = {
                userId: String(userByEmail._id),
                otpHash: hashCode(otpCode),
                expiresAt: Date.now() + (5 * 60 * 1000),
                attempts: 0
            };

            await sendMail(
                userByEmail.email,
                "Your TechSymposium Login OTP",
                `Your login OTP is ${otpCode}. It expires in 5 minutes.`
            );

            return res.redirect('/mfa');
        } catch (err) {
            console.error(err);
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
    async (req, res) => {
        try {
            if (!validationResult(req).isEmpty()) {
                return res.render('signup', { error: "Invalid inputs", csrfToken: getCsrfToken(req) });
            }

            const exists = await User.findOne({
                $or: [{ email: req.body.email }, { phone: req.body.phone }]
            });

            if (exists) {
                return res.render('signup', { 
                    error: "Email or Phone already registered. Please Login.", 
                    csrfToken: getCsrfToken(req) 
                });
            }

            const tempEventId = 'TEMP_' + crypto.randomBytes(4).toString('hex').toUpperCase();
            const tempTxnId = 'PENDING_' + crypto.randomBytes(4).toString('hex').toUpperCase();

            const user = new User({
                event_id: tempEventId, 
                name: req.body.name,
                email: req.body.email,
                phone: req.body.phone,
                transaction_id: tempTxnId
            });

            await user.save();

            res.redirect('/?success=Account created! Please login to complete registration.');

        } catch (err) {
            console.error("Signup Error:", err); 
            res.render('signup', { error: "System Error. Please try again.", csrfToken: getCsrfToken(req) });
        }
    }
);

// MFA PAGE
app.get('/mfa', (req, res) => {
    if (!req.session.pendingMfa) {
        return res.redirect('/?error=Please login first');
    }

    res.render('mfa', {
        error: null,
        csrfToken: getCsrfToken(req)
    });
});

// MFA VERIFY
app.post('/mfa',
    body('otp').trim().matches(/^\d{6}$/),
    async (req, res) => {
        try {
            const pendingMfa = req.session.pendingMfa;
            if (!pendingMfa) return res.redirect('/?error=Session expired. Login again.');

            if (!validationResult(req).isEmpty()) {
                return res.render('mfa', { error: 'Invalid OTP format.', csrfToken: getCsrfToken(req) });
            }

            if (pendingMfa.expiresAt < Date.now()) {
                delete req.session.pendingMfa;
                return res.redirect('/?error=OTP expired. Please login again.');
            }

            pendingMfa.attempts = (pendingMfa.attempts || 0) + 1;
            if (pendingMfa.attempts > 5) {
                delete req.session.pendingMfa;
                return res.redirect('/?error=Too many OTP attempts. Please login again.');
            }

            if (hashCode(req.body.otp) !== pendingMfa.otpHash) {
                req.session.pendingMfa = pendingMfa;
                return res.render('mfa', { error: 'Incorrect OTP.', csrfToken: getCsrfToken(req) });
            }

            const loggedInUserId = pendingMfa.userId;
            delete req.session.pendingMfa;

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
                        return res.redirect('/?error=Server error');
                    }
                    return res.redirect('/home');
                });
            });
        } catch (err) {
            console.error('MFA Error:', err);
            return res.redirect('/?error=Server error');
        }
    }
);

// RECOVERY PAGE
app.get('/recover', (req, res) => {
    res.render('recover', {
        error: null,
        success: null,
        csrfToken: getCsrfToken(req)
    });
});

// RECOVERY REQUEST
app.post('/recover/request',
    body('email').isEmail().normalizeEmail(),
    async (req, res) => {
        try {
            if (!validationResult(req).isEmpty()) {
                return res.render('recover', { error: 'Invalid email.', success: null, csrfToken: getCsrfToken(req) });
            }

            const user = await User.findOne({ email: req.body.email });
            if (!user) {
                return res.render('recover', {
                    error: null,
                    success: 'If this email exists, a recovery code has been sent.',
                    csrfToken: getCsrfToken(req)
                });
            }

            const recoveryCode = generateNumericCode(6);
            user.recoveryCodeHash = hashCode(recoveryCode);
            user.recoveryCodeExpires = new Date(Date.now() + (10 * 60 * 1000));
            await user.save();

            await sendMail(
                user.email,
                'TechSymposium Recovery Code',
                `Your recovery code is ${recoveryCode}. It expires in 10 minutes.`
            );

            req.session.recoveryEmail = user.email;
            return res.redirect('/recover/verify');
        } catch (err) {
            console.error('Recovery request error:', err);
            return res.render('recover', { error: 'System error. Try again.', success: null, csrfToken: getCsrfToken(req) });
        }
    }
);

// RECOVERY VERIFY PAGE
app.get('/recover/verify', (req, res) => {
    if (!req.session.recoveryEmail) return res.redirect('/recover');

    return res.render('recover_verify', {
        error: null,
        csrfToken: getCsrfToken(req)
    });
});

// RECOVERY VERIFY LOGIC
app.post('/recover/verify',
    body('code').trim().matches(/^\d{6}$/),
    body('new_phone').trim().isNumeric().isLength({ min: 10, max: 10 }),
    async (req, res) => {
        try {
            const email = req.session.recoveryEmail;
            if (!email) return res.redirect('/recover');

            if (!validationResult(req).isEmpty()) {
                return res.render('recover_verify', { error: 'Invalid inputs.', csrfToken: getCsrfToken(req) });
            }

            const user = await User.findOne({ email });
            if (!user || !user.recoveryCodeHash || !user.recoveryCodeExpires) {
                return res.redirect('/recover?error=Recovery session expired');
            }

            if (user.recoveryCodeExpires.getTime() < Date.now()) {
                user.recoveryCodeHash = null;
                user.recoveryCodeExpires = null;
                await user.save();
                return res.render('recover_verify', { error: 'Recovery code expired.', csrfToken: getCsrfToken(req) });
            }

            if (hashCode(req.body.code) !== user.recoveryCodeHash) {
                return res.render('recover_verify', { error: 'Invalid recovery code.', csrfToken: getCsrfToken(req) });
            }

            const phoneExists = await User.findOne({ _id: { $ne: user._id }, phone: req.body.new_phone });
            if (phoneExists) {
                return res.render('recover_verify', { error: 'Phone already in use by another account.', csrfToken: getCsrfToken(req) });
            }

            user.phone = req.body.new_phone;
            user.loginAttempts = 0;
            user.lockUntil = null;
            user.recoveryCodeHash = null;
            user.recoveryCodeExpires = null;
            await user.save();

            delete req.session.recoveryEmail;

            return res.redirect('/?success=Recovery complete. Please login with your new phone number.');
        } catch (err) {
            console.error('Recovery verify error:', err);
            return res.render('recover_verify', { error: 'System error. Try again.', csrfToken: getCsrfToken(req) });
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
            user: user
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
    async (req, res) => {
        try {
            if (!req.session.userId) return res.redirect('/signup');

            if (!validationResult(req).isEmpty()) {
                const user = await User.findById(req.session.userId);
                return res.render('register', {
                    error: "Invalid registration input. Please check all fields.",
                    csrfToken: getCsrfToken(req),
                    user: user
                });
            }

            const currentUser = await User.findById(req.session.userId);
            if (!currentUser) return res.redirect('/logout');

            // 1. DUPLICATE CHECK
            // Check if Transaction ID matches any OTHER user (exclude current user)
            const conflict = await User.findOne({
                _id: { $ne: currentUser._id }, // Not equal to current user
                transaction_id: req.body.transaction_id
            });

            if (conflict) {
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
            currentUser.transaction_id = req.body.transaction_id;

            await currentUser.save();
            
            return res.render('success', { name: currentUser.name, event_id: currentUser.event_id });

        } catch (err) {
            console.error(err);
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
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('symposium.sid');
        res.redirect('/');
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));