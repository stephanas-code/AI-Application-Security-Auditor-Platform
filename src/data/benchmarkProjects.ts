import { ScanTarget } from '../types';

export const BENCHMARK_PROJECTS: ScanTarget[] = [
  {
    id: 'live-apex-bank-url',
    name: 'Apex Bank Portal (https://portal.apex-bank.stage)',
    type: 'url',
    platform: 'web',
    language: 'Web / Next.js & Nginx (Live URL)',
    description: 'Live website recon & vulnerability audit: Discovered missing Content-Security-Policy (CSP), disabled HSTS, exposed GraphQL schema introspection, insecure cookie flags, and unauthenticated /api/internal/debug route.',
    scannedAt: new Date().toISOString(),
    totalLines: 360,
    websiteMetadata: {
      url: 'https://portal.apex-bank.stage',
      hostname: 'portal.apex-bank.stage',
      ipAddress: '104.21.48.192 (Cloudflare Edge)',
      serverHeader: 'nginx/1.24.0 (Ubuntu)',
      tlsVersion: 'TLSv1.3 (ChaCha20-Poly1305 / ECDHE)',
      certificateIssuer: "Let's Encrypt Authority X3",
      certificateExpires: '2026-11-20 (Valid)',
      securityHeadersGrade: 'F',
      wafDetected: 'Cloudflare Edge (Standard Mode)',
      technologies: [
        'Next.js 14.1.0',
        'React 18.2.0',
        'Nginx 1.24.0',
        'Express 4.19.2',
        'Apollo GraphQL Server',
        'Tailwind CSS',
        'Redis 7.2'
      ],
      discoveredEndpoints: [
        {
          path: '/api/graphql',
          method: 'POST',
          status: 200,
          exposureType: 'GRAPHQL',
          riskLevel: 'HIGH'
        },
        {
          path: '/api/internal/debug',
          method: 'GET',
          status: 200,
          exposureType: 'SENSITIVE_DEBUG',
          riskLevel: 'CRITICAL'
        },
        {
          path: '/swagger-ui.html',
          method: 'GET',
          status: 200,
          exposureType: 'DOCS',
          riskLevel: 'MEDIUM'
        },
        {
          path: '/admin/console',
          method: 'GET',
          status: 401,
          exposureType: 'ADMIN_PORTAL',
          riskLevel: 'MEDIUM'
        },
        {
          path: '/.git/HEAD',
          method: 'GET',
          status: 403,
          exposureType: 'PUBLIC_API',
          riskLevel: 'LOW'
        }
      ],
      dnsRecords: [
        {
          type: 'A',
          value: '104.21.48.192 (Cloudflare CDN)',
          status: 'SECURE',
          details: 'DDoS protection active'
        },
        {
          type: 'TXT (SPF)',
          value: 'v=spf1 include:_spf.google.com ~all',
          status: 'WARNING',
          details: 'SoftFail (~all) allows potential spoofing'
        },
        {
          type: 'TXT (DMARC)',
          value: 'v=DMARC1; p=none; sp=none;',
          status: 'CRITICAL',
          details: 'Policy is set to "p=none", failing to enforce reject/quarantine on spoofed emails'
        }
      ],
      cookieAudit: [
        {
          name: 'apex_session_id',
          secure: false,
          httpOnly: false,
          sameSite: 'None',
          status: 'VULNERABLE'
        },
        {
          name: 'csrf_token',
          secure: true,
          httpOnly: false,
          sameSite: 'Lax',
          status: 'SAFE'
        },
        {
          name: 'remember_device',
          secure: false,
          httpOnly: true,
          sameSite: 'Lax',
          status: 'VULNERABLE'
        }
      ]
    },
    files: [
      {
        path: 'etc/nginx/nginx.conf',
        language: 'nginx',
        size: 1980,
        content: `server {
    listen 443 ssl http2;
    server_name portal.apex-bank.stage;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/apex-bank.crt;
    ssl_certificate_key /etc/ssl/private/apex-bank.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # HIGH: Missing HTTP Strict Transport Security (HSTS)
    # add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # HIGH: Missing Content-Security-Policy (CSP) - Allows XSS and unauthorized script injection
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';" always;

    # MEDIUM: Missing X-Frame-Options & X-Content-Type-Options
    # add_header X-Frame-Options "DENY" always;
    # add_header X-Content-Type-Options "nosniff" always;

    # MEDIUM: Information Disclosure - Server header version exposed
    server_tokens on;

    # CRITICAL: Exposed internal debug & actuator endpoints proxied to the internet without IP restrictions
    location /api/internal/ {
        proxy_pass http://internal-cluster-backend:8080/internal/;
        proxy_set_header Host $host;
    }

    # GraphQL endpoint with schema introspection enabled
    location /api/graphql {
        proxy_pass http://graphql-service:4000/graphql;
        proxy_set_header Host $host;
    }

    location / {
        proxy_pass http://nextjs-frontend:3000;
        proxy_set_header Host $host;
    }
}`
      },
      {
        path: 'src/server/sessionConfig.js',
        language: 'javascript',
        size: 1100,
        content: `const session = require('express-session');
const RedisStore = require('connect-redis')(session);

// CRITICAL: Insecure session cookie configuration allows XSS token theft & HTTP interception
module.exports = session({
  store: new RedisStore({ host: process.env.REDIS_HOST }),
  secret: 'apex_banking_session_secret_master_key',
  resave: false,
  saveUninitialized: false,
  name: 'apex_session_id',
  cookie: {
    secure: false, // Insecure: transmits over unencrypted HTTP
    httpOnly: false, // Insecure: accessible to client JavaScript (document.cookie)
    sameSite: 'none', // Insecure: vulnerable to CSRF
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
});`
      },
      {
        path: 'src/server/graphqlServer.js',
        language: 'javascript',
        size: 1320,
        content: `const { ApolloServer } = require('apollo-server-express');
const { typeDefs, resolvers } = require('./schema');

// HIGH: GraphQL introspection enabled in staging/production environment
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // Insecure: allows attackers to dump complete GraphQL schema and mutations
  playground: true,    // Insecure: exposes interactive GraphQL IDE to the public
  context: ({ req }) => ({ user: req.user })
});

module.exports = server;`
      }
    ]
  },
  {
    id: 'live-omnistore-url',
    name: 'OmniStore Checkout API (https://checkout.omnistore-api.net)',
    type: 'url',
    platform: 'web',
    language: 'Web / Python & FastAPI (Live URL)',
    description: 'Live e-commerce payment gateway recon: Discovered unrestricted wildcard CORS with credentials, missing anti-clickjacking frame headers, public OpenAPI documentation leak, and exposed Stripe test credentials.',
    scannedAt: new Date().toISOString(),
    totalLines: 310,
    websiteMetadata: {
      url: 'https://checkout.omnistore-api.net',
      hostname: 'checkout.omnistore-api.net',
      ipAddress: '52.84.162.33 (AWS CloudFront)',
      serverHeader: 'CloudFront / Uvicorn',
      tlsVersion: 'TLSv1.3',
      certificateIssuer: 'Amazon RSA 2048 M02',
      certificateExpires: '2026-09-15',
      securityHeadersGrade: 'D',
      wafDetected: 'AWS WAF (Default Web ACL)',
      technologies: [
        'FastAPI 0.110.0',
        'Python 3.11',
        'Uvicorn 0.29.0',
        'Redis 7.2',
        'Stripe Payments API',
        'AWS CloudFront'
      ],
      discoveredEndpoints: [
        {
          path: '/docs',
          method: 'GET',
          status: 200,
          exposureType: 'DOCS',
          riskLevel: 'MEDIUM'
        },
        {
          path: '/redoc',
          method: 'GET',
          status: 200,
          exposureType: 'DOCS',
          riskLevel: 'LOW'
        },
        {
          path: '/api/v1/payments/mock-webhook',
          method: 'POST',
          status: 200,
          exposureType: 'PUBLIC_API',
          riskLevel: 'HIGH'
        },
        {
          path: '/.env.backup',
          method: 'GET',
          status: 200,
          exposureType: 'SENSITIVE_DEBUG',
          riskLevel: 'CRITICAL'
        }
      ],
      dnsRecords: [
        {
          type: 'A',
          value: '52.84.162.33 (CloudFront Distribution)',
          status: 'SECURE',
          details: 'Global edge cache routing'
        },
        {
          type: 'TXT (DMARC)',
          value: 'v=DMARC1; p=quarantine; pct=100;',
          status: 'SECURE',
          details: 'Quarantine policy active'
        }
      ],
      cookieAudit: [
        {
          name: 'cart_token',
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
          status: 'SAFE'
        }
      ]
    },
    files: [
      {
        path: 'app/main.py',
        language: 'python',
        size: 1650,
        content: `from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import payments, cart

# HIGH: Swagger docs & Redoc exposed on production API surface
app = FastAPI(
    title="OmniStore Checkout API",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CRITICAL: Wildcard CORS origin combined with allow_credentials=True allows cross-origin credential theft
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(payments.router, prefix="/api/v1/payments")
app.include_router(cart.router, prefix="/api/v1/cart")`
      },
      {
        path: 'app/config/secrets.py',
        language: 'python',
        size: 920,
        content: `# Live production and sandbox payment credentials
STRIPE_PUBLISHABLE_KEY = "pk_live_51OmniStoreCheckoutProdKey992288"
# CRITICAL: Hardcoded Stripe Secret Key in live web service repository
STRIPE_SECRET_KEY = "sk_live_51OmniStoreSecretKey9988220011LiveProd"
WEBHOOK_SIGNING_SECRET = "whsec_omnistore_checkout_live_secret_7722"`
      }
    ]
  },
  {
    id: 'fintech-banking-core',
    name: 'FinTech Banking Core API (Web)',
    type: 'benchmark',
    platform: 'web',
    language: 'JavaScript / Node.js & Express',
    description: 'High-volume transaction routing API containing critical SQL injection, credential leaks, outdated dependencies, and broken access controls.',
    scannedAt: new Date().toISOString(),
    totalLines: 412,
    files: [
      {
        path: 'src/routes/transactions.js',
        language: 'javascript',
        size: 2420,
        content: `const express = require('express');
const router = express.Router();
const db = require('../database');

// GET /api/transactions/search
// Vulnerable to SQL Injection (Direct string concatenation)
router.get('/search', async (req, res) => {
  const { accountId, query } = req.query;
  
  // CRITICAL: Unsanitized user input concatenated directly into SQL statement
  const sql = "SELECT * FROM transactions WHERE account_id = " + accountId + " AND memo LIKE '%" + query + "%'";
  
  try {
    const results = await db.rawQuery(sql);
    res.json({ success: true, count: results.length, data: results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/transactions/transfer
// Vulnerable to Broken Auth / Missing Authorization Guard
router.post('/transfer', async (req, res) => {
  const { fromAccount, toAccount, amount } = req.body;
  
  // Missing check if req.user owns fromAccount! (IDOR / Broken Access Control)
  await db.execute("UPDATE accounts SET balance = balance - $1 WHERE id = $2", [amount, fromAccount]);
  await db.execute("UPDATE accounts SET balance = balance + $1 WHERE id = $2", [amount, toAccount]);
  
  res.json({ status: 'TRANSFER_COMPLETE', amount });
});

module.exports = router;`
      },
      {
        path: 'config/credentials.js',
        language: 'javascript',
        size: 1140,
        content: `// Application credentials & external service keys
module.exports = {
  // CRITICAL: Hardcoded AWS Production credentials
  aws: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: "us-east-1",
    s3Bucket: "fintech-customer-receipts-prod"
  },
  
  // CRITICAL: Hardcoded Stripe Live Secret Key
  stripe: {
    apiKey: "sk_live_51M3xyzBankingLiveProdSecretKey9988220011",
    webhookSecret: "whsec_banking_test_secret_998822"
  },
  
  jwtSecret: "bank_super_secret_master_jwt_key_2026"
};`
      },
      {
        path: 'package.json',
        language: 'json',
        size: 890,
        content: `{
  "name": "fintech-banking-core",
  "version": "1.0.0",
  "description": "Core transaction routing service",
  "main": "server.js",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "4.17.15",
    "jsonwebtoken": "8.5.1",
    "pg": "^8.11.3",
    "cors": "^2.8.5",
    "axios": "0.21.0"
  },
  "devDependencies": {
    "jest": "^29.7.0"
  }
}`
      },
      {
        path: 'server.js',
        language: 'javascript',
        size: 1650,
        content: `const express = require('express');
const cors = require('cors');
const transactionRoutes = require('./src/routes/transactions');

const app = express();
app.use(express.json());

// MISCONFIGURATION: Unrestricted CORS with Wildcard allowed
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

app.use('/api/transactions', transactionRoutes);

// Admin diagnostic endpoint without authentication
app.get('/api/admin/dump-users', async (req, res) => {
  const users = await require('./src/database').rawQuery("SELECT id, username, email, password_hash FROM users");
  res.json(users);
});

app.listen(8080, () => {
  console.log("Banking API listening on port 8080");
});`
      },
      {
        path: 'Dockerfile',
        language: 'dockerfile',
        size: 420,
        content: `FROM node:14-alpine

WORKDIR /app

# Insecure: Running container process as root
USER root

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 8080
CMD ["node", "server.js"]`
      }
    ]
  },
  {
    id: 'android-fintech-apk',
    name: 'SecurePay Mobile (Android APK)',
    type: 'apk',
    platform: 'android',
    language: 'Android / Kotlin & Java (APK)',
    description: 'Decompiled Android package containing exported broadcast receivers, disabled TLS certificate validation, cleartext HTTP traffic, and hardcoded AES keys.',
    scannedAt: new Date().toISOString(),
    totalLines: 320,
    binaryMetadata: {
      bundleId: 'com.securepay.mobile.bank',
      versionName: '2.4.1-release',
      targetSdk: '33',
      minSdk: '21',
      signed: true,
      permissions: [
        'android.permission.INTERNET',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.ACCESS_FINE_LOCATION'
      ]
    },
    files: [
      {
        path: 'AndroidManifest.xml',
        language: 'xml',
        size: 1450,
        content: `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.securepay.mobile.bank">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />

    <!-- CRITICAL: Debuggable flag active in release, allowing JTAG debugger attach -->
    <!-- HIGH: allowBackup enabled allowing adb backup extraction of private storage -->
    <!-- HIGH: usesCleartextTraffic allows insecure plaintext HTTP -->
    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true"
        android:label="@string/app_name"
        android:theme="@style/AppTheme">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- CRITICAL: Exported BroadcastReceiver with zero permission guard -->
        <receiver
            android:name=".receivers.TransactionInterceptReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="com.securepay.ACTION_AUTH_TOKEN_BROADCAST" />
            </intent-filter>
        </receiver>

    </application>
</manifest>`
      },
      {
        path: 'src/main/java/com/securepay/network/TrustAllCerts.java',
        language: 'java',
        size: 1280,
        content: `package com.securepay.network;

import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

// CRITICAL: Insecure TrustManager disables SSL/TLS validation, enabling MITM interception
public class TrustAllCerts implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        // Disabled certificate checking
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // Insecure: Trust all remote servers regardless of validity or self-signing
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}`
      },
      {
        path: 'src/main/java/com/securepay/crypto/CryptoStorage.java',
        language: 'java',
        size: 980,
        content: `package com.securepay.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoStorage {
    // CRITICAL: Hardcoded symmetric AES key in decompiled bytecode
    private static final String STATIC_AES_KEY = "SecureBankMasterSecretKey2026";

    public static byte[] encryptPin(String pin) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(STATIC_AES_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // HIGH: Insecure ECB Mode
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(pin.getBytes());
    }
}`
      }
    ]
  },
  {
    id: 'windows-desktop-terminal',
    name: 'Apex Trader Terminal (Windows .EXE)',
    type: 'exe',
    platform: 'windows',
    language: 'C++ / Win32 & Electron (.EXE)',
    description: 'Windows 64-bit desktop application binary with disabled ASLR/DEP protections, unquoted service execution paths, and insecure DLL search order.',
    scannedAt: new Date().toISOString(),
    totalLines: 280,
    binaryMetadata: {
      architecture: 'x86_64 (PE32+)',
      aslrEnabled: false,
      depEnabled: false,
      signed: false
    },
    files: [
      {
        path: 'win32/service_installer.cpp',
        language: 'cpp',
        size: 1540,
        content: `#include <windows.h>
#include <iostream>

// CRITICAL: Insecure Unquoted Service Path allows local privilege escalation
void InstallService() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    
    // Insecure: Path with spaces without surrounding quotation marks
    const char* binaryPath = "C:\\\\Program Files\\\\Apex Trading Systems\\\\ApexService.exe --daemon";
    
    SC_HANDLE schService = CreateServiceA(
        schSCManager,
        "ApexTradeDaemon",
        "Apex Trade Daemon",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        binaryPath,
        NULL, NULL, NULL, NULL, NULL
    );
}`
      },
      {
        path: 'win32/dll_loader.cpp',
        language: 'cpp',
        size: 1100,
        content: `#include <windows.h>

// CRITICAL: Insecure DLL loading without SetDefaultDllDirectories (DLL Hijacking)
void LoadTradePlugins() {
    // Relative LoadLibrary will look in current working directory first
    HMODULE hPlugin = LoadLibraryA("CustomTradeStrategy.dll");
    if (hPlugin) {
        typedef void (*RunStrategyFunc)();
        RunStrategyFunc runFunc = (RunStrategyFunc)GetProcAddress(hPlugin, "Execute");
        if (runFunc) runFunc();
    }
}`
      },
      {
        path: 'build/pe_flags.json',
        language: 'json',
        size: 320,
        content: `{
  "binaryName": "ApexTrader.exe",
  "flags": {
    "DYNAMIC_BASE_ASLR": false,
    "NX_COMPAT_DEP": false,
    "SAFESEH": false,
    "AUTHENTICODE_SIGNED": false
  }
}`
      }
    ]
  },
  {
    id: 'ios-crypto-wallet',
    name: 'OmniVault Crypto (iPhone iOS .IPA)',
    type: 'ipa',
    platform: 'ios',
    language: 'iOS / Swift & Objective-C (.IPA)',
    description: 'iOS application bundle with App Transport Security (ATS) disabled, debug task entitlements, insecure Keychain accessibility, and unencrypted SQLite database.',
    scannedAt: new Date().toISOString(),
    totalLines: 310,
    binaryMetadata: {
      bundleId: 'com.omnivault.crypto.ios',
      versionName: '3.1.0',
      hardenedRuntime: false,
      entitlements: [
        'get-task-allow',
        'keychain-access-groups: *'
      ]
    },
    files: [
      {
        path: 'Payload/OmniVault.app/Info.plist',
        language: 'xml',
        size: 1200,
        content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.omnivault.crypto.ios</string>
    <key>CFBundleVersion</key>
    <string>3.1.0</string>
    
    <!-- CRITICAL: App Transport Security (ATS) globally disabled -->
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
    
    <key>NSFaceIDUsageDescription</key>
    <string>Authenticate to sign vault transactions</string>
</dict>
</plist>`
      },
      {
        path: 'OmniVault/Security/KeychainManager.swift',
        language: 'swift',
        size: 1350,
        content: `import Foundation
import Security

public class KeychainManager {
    // CRITICAL: Insecure accessibility attribute permits access while device is locked
    public static func storeMnemonic(seed: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "master_wallet_seed",
            kSecValueData as String: seed.data(using: .utf8)!,
            // Insecure: kSecAttrAccessibleAlways has been deprecated due to forensic extraction risk
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
}`
      },
      {
        path: 'OmniVault.entitlements',
        language: 'xml',
        size: 650,
        content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- CRITICAL: get-task-allow enabled in release build allows lldb debug attachment -->
    <key>get-task-allow</key>
    <true/>
</dict>
</plist>`
      }
    ]
  },
  {
    id: 'macos-system-daemon',
    name: 'MacCloudSync Helper (macOS .DMG)',
    type: 'dmg',
    platform: 'macos',
    language: 'macOS / Swift & Objective-C (.DMG)',
    description: 'macOS universal binary application with missing Hardened Runtime, disabled library validation, and arbitrary AppleScript execution.',
    scannedAt: new Date().toISOString(),
    totalLines: 290,
    binaryMetadata: {
      bundleId: 'com.maccloudsync.helper.daemon',
      hardenedRuntime: false,
      entitlements: [
        'com.apple.security.cs.allow-unsigned-executable-memory',
        'com.apple.security.cs.disable-library-validation'
      ]
    },
    files: [
      {
        path: 'MacCloudSync.app/Contents/Info.plist',
        language: 'xml',
        size: 980,
        content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.maccloudsync.helper.daemon</string>
    <key>CFBundleExecutable</key>
    <string>MacCloudSync</string>
</dict>
</plist>`
      },
      {
        path: 'MacCloudSync.entitlements',
        language: 'xml',
        size: 780,
        content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- CRITICAL: Allows JIT/unsigned memory execution, enabling memory corruption exploits -->
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    
    <!-- HIGH: Disables dynamic library validation, allowing dylib injection -->
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>`
      },
      {
        path: 'src/AppleScriptBridge.swift',
        language: 'swift',
        size: 1100,
        content: `import Foundation

// HIGH: Unsanitized AppleScript execution permits arbitrary command injection
public func executeUserAppleScript(customScript: String) {
    let scriptSource = "tell application \"Finder\" to " + customScript
    if let appleScript = NSAppleScript(source: scriptSource) {
        var errorDict: NSDictionary?
        appleScript.executeAndReturnError(&errorDict)
    }
}`
      }
    ]
  }
];
