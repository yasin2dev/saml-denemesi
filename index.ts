// SAML entegrasyonu için TypeScript örneği
// Gerekli paketleri yüklemek için:
// npm install express passport passport-saml body-parser cookie-parser express-session
// npm install --save-dev @types/express @types/passport @types/passport-saml @types/cookie-parser @types/express-session

// CommonJS modüllerini import etmek için require kullanımı
import express = require('express');
import passport = require('passport');
import bodyParser = require('body-parser');
import cookieParser = require('cookie-parser');
import session = require('express-session');
import fs = require('fs');
import path = require('path');

// SAML için özel import
const SamlStrategy = require('passport-saml').Strategy;

// Express tiplerini dahil etmek için interface tanımı
declare global {
  namespace Express {
    interface User {
      nameID?: string;
      email?: string;
      [key: string]: any;
    }
  }
}

// Uygulama örneği oluşturma
const app = express();

// Middleware yapılandırması
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: 'saml-entegrasyon-gizli-anahtar',
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// Kullanıcıyı serileştirme ve deserileştirme
passport.serializeUser((user: any, done: any) => {
  done(null, user);
});

passport.deserializeUser((user: any, done: any) => {
  done(null, user);
});

// SAML stratejisi yapılandırması
const samlStrategy = new SamlStrategy(
  {
    callbackUrl: 'http://localhost:3000/auth/saml/callback',
    entryPoint: 'https://mocksaml.com/api/saml/sso',
    issuer: 'saml-node-app',
    // Gerçek uygulamada mocksaml.com'dan sağlanan sertifikayı kullanın
    cert: fs.readFileSync(path.join(__dirname, 'cert.pem'), 'utf8'),
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    validateInResponseTo: false,
    disableRequestedAuthnContext: true
  },
  (profile: any, done: any) => {
    // SAML yanıtından kullanıcı profilini alın
    return done(null, profile);
  }
);

passport.use(samlStrategy);

// Ana sayfa rotası
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`
      <h1>SAML Kimlik Doğrulama Başarılı!</h1>
      <pre>${JSON.stringify(req.user, null, 2)}</pre>
      <a href="/logout">Çıkış Yap</a>
    `);
  } else {
    res.send(`
      <h1>SAML Kimlik Doğrulama Örneği</h1>
      <a href="/login">MockSAML.com ile Giriş Yap</a>
    `);
  }
});

// SAML ile giriş rotası
app.get('/login', passport.authenticate('saml', {
  successRedirect: '/',
  failureRedirect: '/login-failed'
}));

// SAML callback (ACS) rotası
app.post('/auth/saml/callback',
  passport.authenticate('saml', {
    failureRedirect: '/login-failed',
    failureFlash: true
  }),
  (req, res) => {
    // Başarılı kimlik doğrulama sonrası yönlendirme
    res.redirect('/');
  }
);

// Giriş hatası rotası
app.get('/login-failed', (req, res) => {
  res.send('Giriş başarısız. <a href="/">Ana sayfaya dön</a>');
});

// Çıkış rotası
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Çıkış yapılırken hata:', err);
    }
    res.redirect('/');
  });
});

// Metadata rotası - Service Provider metadata'sını İdP ile paylaşmak için
app.get('/metadata', (req, res) => {
  res.type('application/xml');
  
  try {
    const metadata = samlStrategy.generateServiceProviderMetadata(null, null);
    res.send(metadata);
  } catch (error) {
    res.status(500).send('Metadata oluşturulamadı');
    console.error('Metadata oluşturma hatası:', error);
  }
});

// Sunucuyu başlatma
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Sunucu ${PORT} portunda çalışıyor`);
  console.log(`SAML Metadata URL: http://localhost:${PORT}/metadata`);
});