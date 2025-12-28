<div align="center">

**A Chrome Extension for Detecting Hardcoded Secrets in JavaScript Files**

[![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4?style=flat-square&logo=googlechrome&logoColor=white)](https://chrome.google.com/webstore)
[![Manifest V3](https://img.shields.io/badge/Manifest-V3-green?style=flat-square)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square)](https://github.com/manojxshrestha/CredStalker/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](https://opensource.org/licenses/MIT)

*Automatically detect exposed API keys, tokens, and sensitive credentials while browsing web applications.*

</div>

## About

CredStalker is a specialized Chrome extension developed for security professionals, bug bounty hunters, and penetration testers. It performs automated scanning of JavaScript files to identify hardcoded credentials, API keys, tokens, and other sensitive data that may be inadvertently exposed in client-side code.

The extension helps prevent data breaches by detecting security misconfigurations before they can be exploited.

---

## Features

### Detection Capabilities
CredStalker scans for over 50+ patterns of sensitive data including:

- **Cloud Providers**: AWS, GCP, Azure, DigitalOcean, Heroku
- **Authentication**: JWT, OAuth, API Keys, Bearer Tokens, GitHub/GitLab Tokens
- **Payment Systems**: Stripe, PayPal, Square, Braintree
- **Communication**: Twilio, SendGrid, Mailgun, Slack
- **Databases**: MongoDB, PostgreSQL, MySQL, Redis
- **Infrastructure**: Private Keys (RSA/SSH), Database Connection Strings
- **Other**: Firebase, Algolia, Mapbox, Sentry

### Advanced Features
- **Automated Scanning**: Passive background scanning while browsing
- **Manual Deep Scan**: On-demand comprehensive analysis with crawling
- **S3 Bucket Takeover Detection**: Identifies misconfigured AWS S3 buckets
- **Token Validation**: Verifies if detected credentials are still active
- **Discord Integration**: Real-time notifications via webhooks
- **History Tracking**: Comprehensive dashboard of all findings
- **Custom Patterns**: Add your own regex patterns for specific targets
- **False Positive Reduction**: Advanced filtering and validation

---

## Usage

### Automated Scanning
1. **Enable Auto Mode**:
   - Click the extension icon
   - Go to Settings
   - Enable "Automatic Scan"

2. **Browse Normally**:
   - The extension will passively scan JavaScript files on visited websites
   - Notifications will appear when secrets are detected

3. **Review Findings**:
   - Check the popup dashboard for detected tokens
   - Use the History tab to view all findings

### Manual Deep Scanning
1. **Navigate to Target**:
   - Go to the website you want to analyze

2. **Initiate Scan**:
   - Click the CredStalker icon
   - Click "Deep Scan" button

3. **Review Results**:
   - The extension will crawl and analyze all JavaScript files
   - Results include validation status and detailed information

---

## S3 Bucket Takeover Detection

CredStalker includes specialized detection for AWS S3 bucket misconfigurations that could lead to takeover attacks:

- **Non-existent Buckets**: Identifies buckets that don't exist, making them prime targets for takeover
- **Permission Issues**: Detects misconfigured access controls
- **Public Exposure**: Finds publicly accessible buckets
- **Bucket References**: Scans for bucket names embedded in JavaScript code

---

## Configuration

### Discord Integration
Receive real-time notifications when secrets are detected:

1. Create a webhook URL in your Discord server settings
2. Open CredStalker Settings
3. Paste the webhook URL in the Discord section
4. Enable Discord notifications

### Custom Detection Patterns
Extend the scanner with your own regex patterns:

```javascript
// Example custom pattern for proprietary API keys
{
  "name": "Company API Key",
  "regex": "COMPANY_[A-Za-z0-9]{32}",
  "severity": "high"
}
```

Add patterns through the Settings page to detect organization-specific secrets.

---

## Dashboard Features

- **Real-time Statistics**: Monitor tokens found, files scanned, and pages analyzed
- **Findings Overview**: Comprehensive list of all detected secrets with source information
- **Validation Status**: Check which tokens are still active and potentially exploitable
- **Export Capabilities**: Export findings to JSON or CSV formats
- **Historical Tracking**: Maintain records of all discoveries across browsing sessions

---

## Security & Ethics

### Authorized Use Cases
CredStalker is designed for legitimate security research and testing:

- Bug bounty programs with explicit permission
- Authorized security assessments and penetration testing
- Educational and research purposes
- Development environment security checks

### Important Restrictions
**DO NOT** use this tool for:

- Unauthorized access to systems or data
- Malicious exploitation of discovered credentials
- Sharing sensitive findings without proper disclosure channels
- Any activity violating applicable laws or terms of service

`Always ensure you have explicit permission before testing any application or system.`


## Example Output

```
🔐 AWS Access Key Detected
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Key: AKIA52XXXXXXXXXXXXXX
Source: https://example.com/app.js
Line: 1842
Status: Potentially Active
Validation: Confirmed via AWS API

🪣 S3 Bucket Takeover Vulnerability
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Bucket: company-sensitive-data
Status: Bucket does not exist
Risk: Critical - Takeover possible
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No tokens detected | Switch to Manual Deep Scan mode for thorough analysis |
| Extension not loading | Ensure Chrome supports Manifest V3 extensions |
| Discord notifications not working | Verify webhook URL is correct and server has proper permissions |
| Too many false positives | Adjust scan settings or add URL exclusions |

---

## References

- [OWASP Sensitive Data Exposure](https://owasp.org/www-project-web-security-testing-guide/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/general/latest/gr/aws-security-best-practices.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

For bug reports or feature requests, use the GitHub Issues page.

</div>
