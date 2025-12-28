// Bucket Takeover Detector - manojxshrestha
// Detects bucket takeover vulnerabilities and sensitive URLs for bug bounty

class BucketTakeoverDetector {
  constructor() {
    this.vulnerabilities = [];
    this.checkedUrls = new Set();
  }

  // Bucket URL patterns
  static BUCKET_PATTERNS = {
    AWS_S3: [
      /https?:\/\/([a-z0-9.-]+)\.s3\.amazonaws\.com/gi,
      /https?:\/\/s3\.amazonaws\.com\/([a-z0-9.-]+)/gi,
      /https?:\/\/([a-z0-9.-]+)\.s3-([a-z0-9-]+)\.amazonaws\.com/gi,
      /s3:\/\/([a-z0-9.-]+)/gi,
    ],
    GOOGLE_STORAGE: [
      // Google Cloud Storage buckets - only real storage, not generic APIs
      /https?:\/\/storage\.googleapis\.com\/([a-z0-9._-]+)\//gi,
      /https?:\/\/([a-z0-9._-]+)\.storage\.googleapis\.com/gi,
      /gs:\/\/([a-z0-9._-]+)/gi,
    ],
    AZURE_BLOB: [
      /https?:\/\/([a-z0-9]+)\.blob\.core\.windows\.net/gi,
      /https?:\/\/([a-z0-9]+)\.blob\.core\.cloudapi\.de/gi,
    ],
    DIGITALOCEAN_SPACES: [
      /https?:\/\/([a-z0-9.-]+)\.([a-z0-9-]+)\.digitaloceanspaces\.com/gi,
    ],
    VERCEL_BLOB: [
      /https?:\/\/([a-z0-9]+)\.public\.blob\.vercel-storage\.com/gi,
      /https?:\/\/[a-z0-9.-]+\.vercel\.app/gi,
      /vercel\.app/gi,
    ],
    SUPABASE_STORAGE: [
      /https?:\/\/([a-z0-9]+)\.supabase\.co\/storage\/v1/gi,
      /https?:\/\/([a-z0-9]+)\.supabase\.co/gi,
      /supabase\.co/gi,
    ],
    FIREBASE_STORAGE: [
      // Firebase Storage - only real buckets
      /https?:\/\/firebasestorage\.googleapis\.com\/v0\/b\/([a-z0-9._-]+)/gi,
      // Firebase Hosting/Apps - Project URLs
      /https?:\/\/([a-z0-9-]+)\.firebaseapp\.com/gi,
      /https?:\/\/([a-z0-9-]+)\.web\.app/gi,
      // Firebase Realtime Database
      /https?:\/\/([a-z0-9-]+)\.firebaseio\.com/gi,
    ],
    CLOUDFRONT: [
      /https?:\/\/([a-z0-9]+)\.cloudfront\.net/gi,
    ],
    NETLIFY: [
      /https?:\/\/[a-z0-9.-]+\.netlify\.app/gi,
      /netlify\.app/gi,
    ],
    GITHUB_PAGES: [
      /https?:\/\/([a-z0-9-]+)\.github\.io/gi,
    ]
  };

  // Specific credential patterns for bug bounty
  static BUGBOUNTY_PATTERNS = {
    // Vercel
    VERCEL_TOKEN: [
      /vercel_[a-zA-Z0-9_]{24,}/gi,
      /['"](VERCEL_TOKEN)['"]\s*[:=]\s*['"]([a-zA-Z0-9_]{24,})['"]/gi,
      /Bearer\s+([a-zA-Z0-9_]{24,})/gi, // Vercel uses Bearer tokens
    ],
    VERCEL_PROJECT: [
      /['"](projectId)['"]\s*[:=]\s*['"]prj_([a-zA-Z0-9_]{21,})['"]/gi,
      /prj_[a-zA-Z0-9_]{21,}/gi,
    ],
    VERCEL_TEAM: [
      /['"](teamId)['"]\s*[:=]\s*['"]team_([a-zA-Z0-9_]{21,})['"]/gi,
      /team_[a-zA-Z0-9_]{21,}/gi,
    ],

    // Supabase
    SUPABASE_ANON_KEY: [
      /['"](SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY)['"]\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{100,})['"]/gi,
    ],
    SUPABASE_SERVICE_KEY: [
      /['"](SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SERVICE_KEY)['"]\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{100,})['"]/gi,
    ],
    SUPABASE_URL: [
      /['"](SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL)['"]\s*[:=]\s*['"]https?:\/\/([a-z0-9]+)\.supabase\.co['"]/gi,
    ],
    SUPABASE_PROJECT_REF: [
      /https?:\/\/([a-z0-9]{20})\.supabase\.co/gi,
    ],

    // AWS more specific
    AWS_ACCESS_KEY_ID: [
      /['"](AWS_ACCESS_KEY_ID)['"]\s*[:=]\s*['"]([A-Z0-9]{20})['"]/gi,
      /AKIA[0-9A-Z]{16}/g,
    ],
    AWS_SECRET_KEY: [
      /['"](AWS_SECRET_ACCESS_KEY)['"]\s*[:=]\s*['"]([a-zA-Z0-9/+=]{40})['"]/gi,
    ],
    AWS_SESSION_TOKEN: [
      /['"](AWS_SESSION_TOKEN)['"]\s*[:=]\s*['"]([a-zA-Z0-9/+=]{100,})['"]/gi,
    ],

    // Firebase more specific
    FIREBASE_CONFIG: [
      /['"](apiKey)['"]\s*[:=]\s*['"]AIzaSy([a-zA-Z0-9_\-]{33})['"]/gi,
      /['"](messagingSenderId)['"]\s*[:=]\s*['"]([0-9]{12})['"]/gi,
      /['"](appId)['"]\s*[:=]\s*['"]1:([0-9]{12}):web:[a-z0-9]{40}['"]/gi,
    ],

    // Database URLs
    MONGODB_URI: [
      /mongodb(\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s]+/gi,
    ],
    POSTGRES_URL: [
      /postgres(ql)?:\/\/[^:\s]+:[^@\s]+@[^\s]+/gi,
    ],
    REDIS_URL: [
      /redis:\/\/[^:\s]*:[^@\s]+@[^\s]+/gi,
    ],

    // Sensitive API Endpoints
    GRAPHQL_ENDPOINT: [
      /https?:\/\/[^\s]+\/graphql/gi,
      /['"](GRAPHQL_ENDPOINT|GRAPHQL_URL)['"]\s*[:=]\s*['"]([^'"]+)['"]/gi,
    ],
    ADMIN_ENDPOINT: [
      /https?:\/\/[^\s]+\/admin/gi,
      /https?:\/\/admin\.[^\s]+/gi,
    ],

    // Slack Webhooks
    SLACK_WEBHOOK: [
      /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24,}/gi,
    ],

    // Discord Webhooks
    DISCORD_WEBHOOK: [
      /https:\/\/discord\.com\/api\/webhooks\/[0-9]{17,19}\/[a-zA-Z0-9_-]{68}/gi,
    ],

    // SendGrid
    SENDGRID_API_KEY: [
      /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    ],

    // Twilio
    TWILIO_API_KEY: [
      /SK[a-z0-9]{32}/gi,
      /AC[a-z0-9]{32}/gi, // Account SID
    ],

    // Algolia
    ALGOLIA_API_KEY: [
      /['"](ALGOLIA_API_KEY|ALGOLIA_ADMIN_KEY)['"]\s*[:=]\s*['"]([a-z0-9]{32})['"]/gi,
    ],

    // Mapbox
    MAPBOX_TOKEN: [
      /pk\.eyJ[a-zA-Z0-9_-]{20,}\.[\w-]{20,}/g,
      /sk\.eyJ[a-zA-Z0-9_-]{20,}\.[\w-]{20,}/g, // Secret token
    ],

    // NPM Tokens
    NPM_TOKEN: [
      /npm_[a-zA-Z0-9]{36}/g,
      /\/\/registry\.npmjs\.org\/:_authToken=([a-zA-Z0-9-]{36,})/gi,
    ],

    // Private Keys
    RSA_PRIVATE_KEY: [
      /-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----[\s\S]+?-----END\s+RSA\s+PRIVATE\s+KEY-----/gi,
    ],
    OPENSSH_PRIVATE_KEY: [
      /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]+?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----/gi,
    ],
    PGP_PRIVATE_KEY: [
      /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[\s\S]+?-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/gi,
    ],
  };

  // Common Google service URLs that are NOT relevant for bug bounty
  static GOOGLE_COMMON_SERVICES = [
    'mail.google.com',
    'gmail.com',
    'drive.google.com',
    'docs.google.com',
    'sheets.google.com',
    'slides.google.com',
    'forms.google.com',
    'calendar.google.com',
    'meet.google.com',
    'chat.google.com',
    'maps.google.com',
    'maps.googleapis.com/maps',
    'youtube.com',
    'youtu.be',
    'accounts.google.com',
    'myaccount.google.com',
    'plus.google.com',
    'play.google.com',
    'photos.google.com',
    'contacts.google.com',
    'keep.google.com',
    'sites.google.com',
    'translate.google.com',
    'news.google.com',
    'books.google.com',
    'scholar.google.com',
    'adwords.google.com',
    'ads.google.com',
    'analytics.google.com',
    'tagmanager.google.com',
    'marketingplatform.google.com',
    'optimize.google.com',
    'surveys.google.com',
    'trends.google.com',
    'fonts.googleapis.com',
    'fonts.gstatic.com'
  ];

  // Check if URL is from common service (not relevant for bug bounty)
  static isCommonServiceUrl(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      const fullUrl = url.toLowerCase();

      // Check if it's a common Google service
      for (const service of BucketTakeoverDetector.GOOGLE_COMMON_SERVICES) {
        if (hostname === service || hostname.endsWith('.' + service) || fullUrl.includes(service)) {
          return true;
        }
      }

      // Generic navigation URLs that are not credentials
      const navigationPatterns = [
        /\/(inbox|sent|drafts|trash|spam)/i,
        /\/mail\/u\/\d+/i,
        /\/folders\//i,
        /\?q=/i, // Query strings for search
        /\/search\?/i,
        /\/(home|dashboard|settings|profile)/i,
        /\/(login|logout|signin|signout)/i,
        /\/(about|help|support|faq)/i
      ];

      for (const pattern of navigationPatterns) {
        if (pattern.test(url)) {
          return true;
        }
      }

      return false;
    } catch (error) {
      return false;
    }
  }

  // Check if URL is relevant for bug bounty
  static isBugBountyRelevant(url) {
    try {
      const urlLower = url.toLowerCase();

      // APIs and services relevant for bug bounty
      const relevantPatterns = [
        // Storage buckets
        /\.s3\.amazonaws\.com/i,
        /s3\.amazonaws\.com\//i,
        /s3:\/\//i,
        /storage\.googleapis\.com/i,
        /\.storage\.googleapis\.com/i,
        /gs:\/\//i,
        /\.blob\.core\.windows\.net/i,
        /\.digitaloceanspaces\.com/i,
        /\.blob\.vercel-storage\.com/i,
        /firebasestorage\.googleapis\.com/i,
        /\.cloudfront\.net/i,

        // Firebase and Supabase
        /\.firebaseapp\.com/i,
        /\.web\.app/i,
        /\.supabase\.co/i,
        /firebaseio\.com/i,

        // Google Cloud APIs
        /\.googleapis\.com\/(?!fonts|maps)/i, // APIs except fonts and maps
        /\/v\d+\/b\//i, // Firebase storage paths

        // Deployments and hosting
        /\.vercel\.app/i,
        /\.netlify\.app/i,
        /\.github\.io/i,
        /\.herokuapp\.com/i,
        /\.azurewebsites\.net/i,

        // Webhooks and APIs
        /\/api\//i,
        /\/webhook/i,
        /\/graphql/i,
        /\/admin\//i,
        /\/internal\//i
      ];

      for (const pattern of relevantPatterns) {
        if (pattern.test(urlLower)) {
          return true;
        }
      }

      return false;
    } catch (error) {
      return false;
    }
  }

  // Detect bucket and sensitive URLs
  async detectBuckets(content, sourceUrl) {
    const findings = [];

    for (const [type, patterns] of Object.entries(BucketTakeoverDetector.BUCKET_PATTERNS)) {
      for (const regex of patterns) {
        let match;
        while ((match = regex.exec(content)) !== null) {
          const url = match[0];
          const bucketName = match[1] || this.extractBucketName(url);

          if (this.checkedUrls.has(url)) continue;
          this.checkedUrls.add(url);

          // FILTER: Ignore common service URLs
          if (BucketTakeoverDetector.isCommonServiceUrl(url)) {
            continue;
          }

          // FILTER: Only URLs relevant for bug bounty
          if (!BucketTakeoverDetector.isBugBountyRelevant(url)) {
            continue;
          }

          findings.push({
            type: 'BUCKET_URL',
            subtype: type,
            url: url,
            bucketName: bucketName,
            sourceUrl: sourceUrl,
            severity: 'HIGH',
            foundAt: new Date().toISOString()
          });
        }
      }
    }

    return findings;
  }

  // Detect specific credentials for bug bounty
  async detectBugBountyCredentials(content, sourceUrl) {
    const findings = [];

    for (const [type, patterns] of Object.entries(BucketTakeoverDetector.BUGBOUNTY_PATTERNS)) {
      for (const regex of patterns) {
        let match;
        while ((match = regex.exec(content)) !== null) {
          const value = match[2] || match[1] || match[0];

          // Expanded context
          const matchIndex = match.index;
          const contextStart = Math.max(0, matchIndex - 150);
          const contextEnd = Math.min(content.length, matchIndex + match[0].length + 150);
          const context = content.substring(contextStart, contextEnd).replace(/\s+/g, ' ');

          findings.push({
            type: 'BUGBOUNTY_CREDENTIAL',
            subtype: type,
            value: value,
            sourceUrl: sourceUrl,
            context: context.substring(0, 300),
            severity: this.getSeverity(type),
            foundAt: new Date().toISOString()
          });
        }
      }
    }

    return findings;
  }

  // Validate bucket takeover
  async validateBucketTakeover(finding) {
    const url = finding.url;

    try {
      const response = await fetch(url, {
        method: 'HEAD',
        mode: 'no-cors'
      });

      // If it could respond, bucket exists
      if (response.ok || response.status === 403) {
        return {
          vulnerable: false,
          status: 'Bucket exists and is accessible',
          severity: 'INFO'
        };
      }

      // 404 status may indicate non-existent bucket
      if (response.status === 404) {
        return {
          vulnerable: true,
          status: 'POSSIBLE TAKEOVER: Bucket not found (404)',
          severity: 'CRITICAL',
          recommendation: 'Check if the bucket can be registered'
        };
      }

    } catch (error) {
      // CORS or DNS errors may indicate non-existent bucket
      if (error.message.includes('CORS') || error.message.includes('NetworkError')) {
        // Try additional validation
        return await this.deepBucketValidation(finding);
      }

      return {
        vulnerable: null,
        status: 'Could not validate: ' + error.message,
        severity: 'MEDIUM'
      };
    }

    return {
      vulnerable: null,
      status: 'Unknown status',
      severity: 'MEDIUM'
    };
  }

  // Deep bucket validation
  async deepBucketValidation(finding) {
    const bucketName = finding.bucketName;
    const type = finding.subtype;

    // Specific checks by type
    if (type === 'AWS_S3') {
      return await this.validateS3Bucket(bucketName);
    } else if (type === 'VERCEL_BLOB') {
      return await this.validateVercelDomain(finding.url);
    } else if (type === 'SUPABASE_STORAGE') {
      return await this.validateSupabaseProject(finding.url);
    }

    return {
      vulnerable: null,
      status: 'Deep validation not available for this type',
      severity: 'MEDIUM'
    };
  }

  // Validate S3 bucket
  async validateS3Bucket(bucketName) {
    try {
      // Try several regions
      const regions = ['us-east-1', 'us-west-2', 'eu-west-1'];

      for (const region of regions) {
        const testUrl = `https://${bucketName}.s3.${region}.amazonaws.com/`;

        try {
          const response = await fetch(testUrl, { method: 'HEAD' });

          if (response.status === 404) {
            return {
              vulnerable: true,
              status: `POSSIBLE BUCKET TAKEOVER: ${bucketName} does not exist in region ${region}`,
              severity: 'CRITICAL',
              recommendation: 'Try to register this bucket on AWS'
            };
          }

          if (response.status === 403 || response.status === 200) {
            return {
              vulnerable: false,
              status: `Bucket exists in region ${region}`,
              severity: 'INFO'
            };
          }
        } catch (e) {
          continue;
        }
      }
    } catch (error) {
      return {
        vulnerable: null,
        status: 'Error in S3 validation: ' + error.message,
        severity: 'MEDIUM'
      };
    }

    return {
      vulnerable: null,
      status: 'Could not determine bucket status',
      severity: 'MEDIUM'
    };
  }

  // Validate Vercel domain
  async validateVercelDomain(url) {
    try {
      const response = await fetch(url);

      if (response.status === 404) {
        const text = await response.text();

        // Vercel shows specific message for non-existent projects
        if (text.includes('The deployment could not be found') ||
            text.includes('This page could not be found')) {
          return {
            vulnerable: true,
            status: 'POSSIBLE VERCEL TAKEOVER: Project not found',
            severity: 'CRITICAL',
            recommendation: 'Check if the domain can be registered on Vercel'
          };
        }
      }

      return {
        vulnerable: false,
        status: 'Vercel project exists',
        severity: 'INFO'
      };

    } catch (error) {
      return {
        vulnerable: null,
        status: 'Error validating Vercel: ' + error.message,
        severity: 'MEDIUM'
      };
    }
  }

  // Validate Supabase project
  async validateSupabaseProject(url) {
    try {
      // Extract project ref
      const match = url.match(/https?:\/\/([a-z0-9]{20})\.supabase\.co/);
      if (!match) {
        return { vulnerable: null, status: 'Invalid URL', severity: 'LOW' };
      }

      const projectRef = match[1];
      const testUrl = `https://${projectRef}.supabase.co/rest/v1/`;

      const response = await fetch(testUrl);

      if (response.status === 404) {
        return {
          vulnerable: true,
          status: 'POSSIBLE SUPABASE TAKEOVER: Project not found',
          severity: 'CRITICAL',
          recommendation: 'Check if the project was deleted'
        };
      }

      return {
        vulnerable: false,
        status: 'Supabase project exists',
        severity: 'INFO'
      };

    } catch (error) {
      return {
        vulnerable: null,
        status: 'Error validating Supabase: ' + error.message,
        severity: 'MEDIUM'
      };
    }
  }

  // Extract bucket name from a URL
  extractBucketName(url) {
    // Try several extraction strategies
    const patterns = [
      /https?:\/\/([a-z0-9.-]+)\.s3/i,
      /https?:\/\/s3[^\/]*\/([a-z0-9.-]+)/i,
      /https?:\/\/([a-z0-9.-]+)\.blob/i,
      /https?:\/\/storage[^\/]*\/([a-z0-9.-]+)/i,
      /https?:\/\/([a-z0-9.-]+)\./i,
    ];

    for (const pattern of patterns) {
      const match = url.match(pattern);
      if (match) return match[1];
    }

    return url;
  }

  // Determine severity based on type
  getSeverity(type) {
    const critical = [
      'AWS_SECRET_KEY', 'AWS_SESSION_TOKEN', 'SUPABASE_SERVICE_KEY',
      'RSA_PRIVATE_KEY', 'OPENSSH_PRIVATE_KEY', 'PGP_PRIVATE_KEY',
      'MONGODB_URI', 'POSTGRES_URL', 'SENDGRID_API_KEY', 'TWILIO_API_KEY'
    ];

    const high = [
      'AWS_ACCESS_KEY_ID', 'VERCEL_TOKEN', 'SUPABASE_ANON_KEY',
      'FIREBASE_CONFIG', 'SLACK_WEBHOOK', 'DISCORD_WEBHOOK',
      'NPM_TOKEN', 'ALGOLIA_API_KEY', 'MAPBOX_TOKEN'
    ];

    if (critical.includes(type)) return 'CRITICAL';
    if (high.includes(type)) return 'HIGH';
    return 'MEDIUM';
  }

  // Full analysis
  async fullScan(content, sourceUrl) {
    const results = {
      buckets: [],
      credentials: [],
      totalFindings: 0
    };

    // Detect buckets
    const buckets = await this.detectBuckets(content, sourceUrl);
    results.buckets = buckets;

    // Detect credentials
    const credentials = await this.detectBugBountyCredentials(content, sourceUrl);
    results.credentials = credentials;

    results.totalFindings = buckets.length + credentials.length;

    return results;
  }
}

// Export for global use (compatible with Chrome extensions)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = BucketTakeoverDetector;
}

// Make globally available as well
if (typeof window !== 'undefined') {
  window.BucketTakeoverDetector = BucketTakeoverDetector;
}

// Export as ES6 module
export default BucketTakeoverDetector;
export { BucketTakeoverDetector };
