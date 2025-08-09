// Load environment variables
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');

const app = express();
const PORT = process.env.PORT || 5000;

// In-memory storage for demo (in production, use database)
const links = new Map();
const redirectRules = new Map();
const clicksData = [];
const ipCache = new Map();

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});
app.use('/api', limiter);

// IP Analysis Service (Mock Implementation for Demo)
class MockIPAnalysisService {
  constructor() {
    this.demoData = {
      // European IPs (with VPN detection)
      '185.220.101.42': {
        country: 'DE', 
        isVPN: true, 
        isProxy: false, 
        isTor: true,
        riskScore: 95, 
        isp: 'TorProject',
        connectionType: 'datacenter'
      },
      '46.101.123.45': {
        country: 'DE', 
        isVPN: false, 
        isProxy: false, 
        isTor: false,
        riskScore: 5, 
        isp: 'Deutsche Telekom',
        connectionType: 'residential'
      },
      '217.160.0.152': {
        country: 'IT', 
        isVPN: true, 
        isProxy: true, 
        isTor: false,
        riskScore: 85, 
        isp: 'NordVPN',
        connectionType: 'datacenter'
      },
      '79.18.183.45': {
        country: 'IT', 
        isVPN: false, 
        isProxy: false, 
        isTor: false,
        riskScore: 10, 
        isp: 'TIM Italia',
        connectionType: 'mobile'
      },
      // American IPs
      '198.51.100.42': {
        country: 'US', 
        isVPN: true, 
        isProxy: false, 
        isTor: false,
        riskScore: 75, 
        isp: 'ExpressVPN',
        connectionType: 'datacenter'
      },
      '172.217.14.110': {
        country: 'US', 
        isVPN: false, 
        isProxy: false, 
        isTor: false,
        riskScore: 0, 
        isp: 'Google LLC',
        connectionType: 'datacenter'
      },
      '208.67.222.222': {
        country: 'US', 
        isVPN: false, 
        isProxy: false, 
        isTor: false,
        riskScore: 5, 
        isp: 'Verizon',
        connectionType: 'residential'
      },
      // Irish IP
      '52.210.112.33': {
        country: 'IE', 
        isVPN: false, 
        isProxy: false, 
        isTor: false,
        riskScore: 15, 
        isp: 'Amazon AWS Ireland',
        connectionType: 'datacenter'
      },
      // French IP
      '195.154.164.45': {
        country: 'FR', 
        isVPN: true, 
        isProxy: true, 
        isTor: false,
        riskScore: 80, 
        isp: 'ProtonVPN',
        connectionType: 'datacenter'
      }
    };
  }

  async analyzeIP(ip) {
    // Check cache first
    if (ipCache.has(ip)) {
      const cached = ipCache.get(ip);
      if (Date.now() - cached.timestamp < 3600000) { // 1 hour cache
        return cached.data;
      }
    }

    let result;

    // Check if we have demo data for this IP
    if (this.demoData[ip]) {
      const demoData = this.demoData[ip];
      result = {
        ip,
        country_code: demoData.country,
        is_vpn: demoData.isVPN,
        is_proxy: demoData.isProxy,
        is_tor: demoData.isTor,
        is_datacenter: demoData.connectionType === 'datacenter',
        is_mobile: demoData.connectionType === 'mobile',
        risk_score: demoData.riskScore,
        isp: demoData.isp,
        connection_type: demoData.connectionType,
        provider: 'demo_service',
        confidence: 'high',
        analyzed_at: new Date().toISOString()
      };
    } else {
      // Use geoip-lite for real IPs (fallback)
      const geo = geoip.lookup(ip) || {};
      
      // Generate realistic data based on country
      const riskScore = this.generateRiskScore(geo.country);
      const vpnProbability = this.getVPNProbability(geo.country);
      
      result = {
        ip,
        country_code: geo.country || 'XX',
        is_vpn: Math.random() < vpnProbability,
        is_proxy: Math.random() < 0.1,
        is_tor: Math.random() < 0.02,
        is_datacenter: Math.random() < 0.3,
        is_mobile: Math.random() < 0.6,
        risk_score: riskScore,
        isp: 'Unknown ISP',
        connection_type: 'unknown',
        provider: 'geoip_fallback',
        confidence: 'medium',
        analyzed_at: new Date().toISOString()
      };
    }

    // Cache the result
    ipCache.set(ip, {
      data: result,
      timestamp: Date.now()
    });

    return result;
  }

  generateRiskScore(country) {
    const baseRisk = {
      'US': 10, 'CA': 15, 'GB': 20, 'IE': 18, 'AU': 12,
      'DE': 25, 'FR': 30, 'IT': 35, 'ES': 28, 'NL': 22,
      'CN': 85, 'RU': 75, 'IR': 90, 'KP': 95
    };
    
    const base = baseRisk[country] || 30;
    return Math.min(100, base + Math.floor(Math.random() * 20));
  }

  getVPNProbability(country) {
    const vpnUsage = {
      'US': 0.15, 'CA': 0.18, 'GB': 0.20, 'IE': 0.16, 'AU': 0.19,
      'DE': 0.25, 'FR': 0.22, 'IT': 0.28, 'ES': 0.24, 'NL': 0.35,
      'CN': 0.60, 'RU': 0.45, 'IR': 0.70
    };
    
    return vpnUsage[country] || 0.20;
  }
}

const ipAnalysisService = new MockIPAnalysisService();

// Browser Detection Service
class BrowserDetectionService {
  detect(userAgent, headers = {}) {
    if (!userAgent) return { isInApp: false, confidence: 'low' };

    const inAppPatterns = {
      instagram: /Instagram/i,
      facebook: /FBAN|FBAV|FB_IAB/i,
      tiktok: /musical_ly|TikTok/i,
      twitter: /TwitterAndroid|Twitter for iPhone/i,
      linkedin: /LinkedInApp/i,
      snapchat: /Snapchat/i,
      whatsapp: /WhatsApp/i
    };

    const genericInAppPatterns = [
      /WebView/i,
      /wv\)/i,
      /Version.*Mobile.*Safari/i,
      /iPhone.*AppleWebKit(?!.*Safari)/i,
      /Android.*AppleWebKit(?!.*Chrome)/i
    ];

    // Check specific app patterns
    for (const [app, pattern] of Object.entries(inAppPatterns)) {
      if (pattern.test(userAgent)) {
        return { isInApp: true, app, confidence: 'high' };
      }
    }

    // Check generic patterns
    for (const pattern of genericInAppPatterns) {
      if (pattern.test(userAgent)) {
        return { isInApp: true, app: 'unknown', confidence: 'medium' };
      }
    }

    return { isInApp: false, confidence: 'high' };
  }

  generateNativeBrowserHTML(targetUrl, userAgent = '') {
    const ua = new UAParser(userAgent);
    const os = ua.getOS();
    const platform = os.name ? os.name.toLowerCase() : 'unknown';

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Redirect - Opening Browser</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-align: center;
            padding: 50px 20px;
            margin: 0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }
        .container {
            max-width: 400px;
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        .loader {
            width: 50px;
            height: 50px;
            border: 4px solid rgba(255,255,255,0.3);
            border-top: 4px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 30px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        h1 {
            margin: 0 0 20px;
            font-size: 24px;
            font-weight: 600;
        }
        p {
            margin: 10px 0;
            opacity: 0.9;
            line-height: 1.5;
        }
        .fallback-link {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 12px 24px;
            border-radius: 25px;
            text-decoration: none;
            margin-top: 20px;
            transition: background 0.3s;
        }
        .fallback-link:hover {
            background: rgba(255,255,255,0.3);
        }
        .status {
            margin-top: 20px;
            font-size: 14px;
            opacity: 0.8;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="loader"></div>
        <h1>Opening in Browser...</h1>
        <p>Redirecting you to the native browser for the best experience.</p>
        <p class="status">Platform: ${platform}</p>
        <a href="${targetUrl}" class="fallback-link" id="fallbackLink">
            Click here if not redirected automatically
        </a>
    </div>

    <script>
        (function() {
            const targetUrl = "${targetUrl}";
            const platform = "${platform}";
            let redirected = false;
            
            function tryRedirect(method, url, delay = 100) {
                if (redirected) return;
                
                setTimeout(() => {
                    if (redirected) return;
                    
                    try {
                        switch(method) {
                            case 'intentScheme':
                                if (platform.includes('android')) {
                                    const domain = new URL(url).hostname;
                                    const intentUrl = 'intent://' + domain + new URL(url).pathname + new URL(url).search + 
                                                     '#Intent;scheme=https;action=android.intent.action.VIEW;end';
                                    window.location.href = intentUrl;
                                }
                                break;
                            case 'universalLink':
                                if (platform.includes('ios')) {
                                    window.location.href = url;
                                }
                                break;
                            case 'windowOpen':
                                window.open(url, '_blank', 'noopener,noreferrer');
                                break;
                            case 'locationHref':
                                window.location.href = url;
                                break;
                        }
                        
                        console.log('Tried redirect method:', method);
                    } catch (e) {
                        console.log('Redirect method failed:', method, e);
                    }
                }, delay);
            }
            
            // Platform-specific redirect sequence
            if (platform.includes('android')) {
                tryRedirect('intentScheme', targetUrl, 0);
                tryRedirect('windowOpen', targetUrl, 500);
                tryRedirect('locationHref', targetUrl, 1000);
            } else if (platform.includes('ios')) {
                tryRedirect('universalLink', targetUrl, 0);
                tryRedirect('windowOpen', targetUrl, 300);
                tryRedirect('locationHref', targetUrl, 800);
            } else {
                tryRedirect('windowOpen', targetUrl, 0);
                tryRedirect('locationHref', targetUrl, 500);
            }
            
            // Final fallback
            setTimeout(() => {
                if (!redirected) {
                    window.location.href = targetUrl;
                }
            }, 3000);
            
            // Success detection
            window.addEventListener('blur', () => {
                redirected = true;
            });
            
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) {
                    redirected = true;
                }
            });
        })();
    </script>
    
    <!-- Meta refresh as final fallback -->
    <meta http-equiv="refresh" content="5;url=${targetUrl}">
</body>
</html>`;
  }
}

const browserDetectionService = new BrowserDetectionService();

// Filtering Engine
class FilteringEngine {
  constructor() {
    this.rules = {
      vpn_filtering: {
        strict_countries: ['IT'], // Italy has strict filtering
        moderate_countries: ['US', 'GB', 'CA', 'IE'], // USA, Ireland, Germany, etc.
        lenient_countries: ['FR', 'DE'] // France, others
      },
      risk_thresholds: {
        block: 85,
        redirect: 60,
        allow: 30
      }
    };
  }

  async shouldFilter(ipAnalysis, targetCountry, linkConfig = {}) {
    const decision = {
      action: 'allow',
      reason: 'low_risk',
      confidence: ipAnalysis.confidence || 'medium',
      details: {}
    };

    // Get filtering level for target country
    const filteringLevel = this.getFilteringLevel(targetCountry);
    
    if (filteringLevel === 'none') {
      return decision;
    }

    // Check for known threats
    if (ipAnalysis.is_tor || ipAnalysis.risk_score > 95) {
      decision.action = 'block';
      decision.reason = 'high_threat';
      return decision;
    }

    // Handle VPN/Proxy based on filtering level
    if (ipAnalysis.is_vpn || ipAnalysis.is_proxy) {
      switch (filteringLevel) {
        case 'strict':
          decision.action = ipAnalysis.risk_score > 70 ? 'block' : 'redirect';
          decision.reason = 'vpn_proxy_strict_filtering';
          break;
        case 'moderate':
          if (ipAnalysis.risk_score > this.rules.risk_thresholds.block) {
            decision.action = 'block';
            decision.reason = 'high_risk_vpn';
          } else if (ipAnalysis.risk_score > this.rules.risk_thresholds.redirect) {
            decision.action = 'redirect';
            decision.reason = 'moderate_risk_vpn';
          }
          break;
        case 'lenient':
          if (ipAnalysis.risk_score > 90) {
            decision.action = 'block';
            decision.reason = 'very_high_risk';
          }
          break;
      }
    }

    // Datacenter filtering
    if (ipAnalysis.is_datacenter && filteringLevel === 'strict') {
      decision.action = 'redirect';
      decision.reason = 'datacenter_detected';
    }

    return decision;
  }

  getFilteringLevel(countryCode) {
    if (this.rules.vpn_filtering.strict_countries.includes(countryCode)) {
      return 'strict';
    }
    if (this.rules.vpn_filtering.moderate_countries.includes(countryCode)) {
      return 'moderate';
    }
    if (this.rules.vpn_filtering.lenient_countries.includes(countryCode)) {
      return 'lenient';
    }
    return 'none';
  }
}

const filteringEngine = new FilteringEngine();

// Initialize demo data
function initializeDemoData() {
  // Create demo links
  const demoLinks = [
    {
      id: uuidv4(),
      shortCode: 'demo1',
      name: 'E-commerce Product Demo',
      defaultUrl: 'https://www.google.com',
      isActive: true,
      createdAt: new Date().toISOString()
    },
    {
      id: uuidv4(),
      shortCode: 'promo2024',
      name: 'Black Friday Campaign',
      defaultUrl: 'https://www.google.com',
      isActive: true,
      createdAt: new Date().toISOString()
    }
  ];

  demoLinks.forEach(link => {
    links.set(link.id, link);
  });

  // Create demo redirect rules
  const demoRules = [
    // For demo1 link
    {
      id: uuidv4(),
      linkId: demoLinks[0].id,
      countryCodes: ['US', 'IE', 'GB', 'CA', 'AU'],
      targetUrl: 'https://www.wikipedia.org',
      actionType: 'redirect',
      priority: 1,
      name: 'Safe Countries → Wikipedia (Safe Page)'
    },
    {
      id: uuidv4(),
      linkId: demoLinks[0].id,
      countryCodes: ['IT'],
      targetUrl: 'https://www.amazon.com',
      actionType: 'redirect',
      priority: 2,
      name: 'Italy → Amazon (Main Offer)'
    },
    {
      id: uuidv4(),
      linkId: demoLinks[0].id,
      countryCodes: ['DE', 'FR', 'ES', 'NL'],
      targetUrl: 'https://www.bbc.com',
      actionType: 'redirect',
      priority: 3,
      name: 'Other EU → BBC (Alternative)'
    },
    // For promo2024 link
    {
      id: uuidv4(),
      linkId: demoLinks[1].id,
      countryCodes: ['US', 'CA'],
      targetUrl: 'https://www.youtube.com',
      actionType: 'redirect',
      priority: 1,
      name: 'North America → YouTube (US Promo)'
    },
    {
      id: uuidv4(),
      linkId: demoLinks[1].id,
      countryCodes: ['IT', 'DE', 'FR', 'ES'],
      targetUrl: 'https://www.reddit.com',
      actionType: 'redirect',
      priority: 2,
      name: 'Europe → Reddit (EU Promo)'
    }
  ];

  demoRules.forEach(rule => {
    redirectRules.set(rule.id, rule);
  });

  console.log('✅ Demo data initialized successfully');
  console.log(`📦 Created ${demoLinks.length} demo links and ${demoRules.length} redirect rules`);
}

// Helper function to get client IP (handles various proxy headers)
// Get real client IP with demo override support
function getClientIP(req) {
  // Check for demo IP override in headers (for testing)
  const demoIP = req.headers['x-demo-ip'];
  if (demoIP && process.env.DEMO_MODE === 'true') {
    console.log(`🧪 Using demo IP: ${demoIP}`);
    return demoIP;
  }

  // Check for demo IP in query parameter (for easy testing)
  const queryDemoIP = req.query.demo_ip;
  if (queryDemoIP && process.env.DEMO_MODE === 'true') {
    console.log(`🧪 Using demo IP from query: ${queryDemoIP}`);
    return queryDemoIP;
  }

  const realIP = req.headers['x-forwarded-for'] || 
                 req.headers['x-real-ip'] || 
                 req.connection.remoteAddress || 
                 req.socket.remoteAddress ||
                 (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
                 req.ip || 
                 '127.0.0.1';

  // Convert IPv6 localhost to IPv4 for consistency
  if (realIP === '::ffff:127.0.0.1' || realIP === '::1') {
    return '127.0.0.1';
  }

  return realIP;
}

// Log click data
function logClick(linkId, ip, userAgent, ipAnalysis, targetUrl, filterDecision) {
  const clickData = {
    id: uuidv4(),
    linkId,
    ip,
    countryCode: ipAnalysis.country_code,
    isVPN: ipAnalysis.is_vpn,
    isProxy: ipAnalysis.is_proxy,
    isTor: ipAnalysis.is_tor,
    isDatacenter: ipAnalysis.is_datacenter,
    isMobile: ipAnalysis.is_mobile,
    riskScore: ipAnalysis.risk_score,
    isp: ipAnalysis.isp,
    userAgent,
    targetUrl,
    filterAction: filterDecision.action,
    filterReason: filterDecision.reason,
    timestamp: new Date().toISOString()
  };

  clicksData.push(clickData);
  
  // Keep only last 1000 clicks for demo
  if (clicksData.length > 1000) {
    clicksData.shift();
  }

  return clickData;
}

// API Routes

// Authentication (simplified for demo)
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  // Simple demo authentication
  if (username === 'admin' && password === 'demo123') {
    const token = 'demo-token-' + Date.now();
    res.json({
      success: true,
      token,
      user: { id: 1, username: 'admin', role: 'admin' }
    });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

// Links Management
app.get('/api/links', (req, res) => {
  const linksArray = Array.from(links.values()).map(link => {
    const linkRules = Array.from(redirectRules.values()).filter(rule => rule.linkId === link.id);
    const recentClicks = clicksData.filter(click => 
      click.linkId === link.id && 
      new Date(click.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000)
    ).length;

    return {
      ...link,
      rulesCount: linkRules.length,
      todayClicks: recentClicks
    };
  });

  res.json({ success: true, data: linksArray });
});

app.post('/api/links', (req, res) => {
  const { shortCode, name, defaultUrl } = req.body;
  
  const newLink = {
    id: uuidv4(),
    shortCode,
    name,
    defaultUrl,
    isActive: true,
    createdAt: new Date().toISOString()
  };

  links.set(newLink.id, newLink);
  
  res.json({ success: true, data: newLink });
});

// Rules Management
app.get('/api/links/:linkId/rules', (req, res) => {
  const { linkId } = req.params;
  const rules = Array.from(redirectRules.values()).filter(rule => rule.linkId === linkId);
  res.json({ success: true, data: rules });
});

app.post('/api/links/:linkId/rules', (req, res) => {
  const { linkId } = req.params;
  const { name, countryCodes, targetUrl, actionType = 'redirect', priority = 1 } = req.body;
  
  const newRule = {
    id: uuidv4(),
    linkId,
    name,
    countryCodes,
    targetUrl,
    actionType,
    priority,
    createdAt: new Date().toISOString()
  };

  redirectRules.set(newRule.id, newRule);
  
  res.json({ success: true, data: newRule });
});

// Analytics
app.get('/api/analytics/summary', (req, res) => {
  const last24h = Date.now() - 24 * 60 * 60 * 1000;
  const recentClicks = clicksData.filter(click => new Date(click.timestamp).getTime() > last24h);
  
  const summary = {
    totalClicks: clicksData.length,
    todayClicks: recentClicks.length,
    totalLinks: links.size,
    activeLinks: Array.from(links.values()).filter(link => link.isActive).length,
    topCountries: this.getTopCountries(recentClicks),
    riskDistribution: this.getRiskDistribution(recentClicks),
    filterActions: this.getFilterActions(recentClicks)
  };

  res.json({ success: true, data: summary });
});

app.get('/api/analytics/clicks/:linkId', (req, res) => {
  const { linkId } = req.params;
  const { period = '24h' } = req.query;
  
  let timeFilter = Date.now() - 24 * 60 * 60 * 1000; // 24 hours
  if (period === '7d') timeFilter = Date.now() - 7 * 24 * 60 * 60 * 1000;
  if (period === '30d') timeFilter = Date.now() - 30 * 24 * 60 * 60 * 1000;

  const linkClicks = clicksData.filter(click => 
    click.linkId === linkId && 
    new Date(click.timestamp).getTime() > timeFilter
  );

  const analytics = {
    totalClicks: linkClicks.length,
    countries: this.getCountryStats(linkClicks),
    riskScores: this.getRiskScoreStats(linkClicks),
    hourlyDistribution: this.getHourlyStats(linkClicks),
    filterResults: this.getFilterStats(linkClicks)
  };

  res.json({ success: true, data: analytics });
});

// Helper functions for analytics
function getTopCountries(clicks) {
  const countryCount = {};
  clicks.forEach(click => {
    countryCount[click.countryCode] = (countryCount[click.countryCode] || 0) + 1;
  });
  
  return Object.entries(countryCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([country, count]) => ({ country, count }));
}

function getRiskDistribution(clicks) {
  const distribution = { low: 0, medium: 0, high: 0 };
  clicks.forEach(click => {
    if (click.riskScore < 30) distribution.low++;
    else if (click.riskScore < 70) distribution.medium++;
    else distribution.high++;
  });
  return distribution;
}

function getFilterActions(clicks) {
  const actions = {};
  clicks.forEach(click => {
    actions[click.filterAction] = (actions[click.filterAction] || 0) + 1;
  });
  return actions;
}

function getCountryStats(clicks) {
  const stats = {};
  clicks.forEach(click => {
    if (!stats[click.countryCode]) {
      stats[click.countryCode] = { total: 0, vpn: 0, blocked: 0 };
    }
    stats[click.countryCode].total++;
    if (click.isVPN) stats[click.countryCode].vpn++;
    if (click.filterAction === 'block') stats[click.countryCode].blocked++;
  });
  return stats;
}

function getRiskScoreStats(clicks) {
  return clicks.map(click => ({
    timestamp: click.timestamp,
    riskScore: click.riskScore,
    country: click.countryCode,
    isVPN: click.isVPN
  }));
}

function getHourlyStats(clicks) {
  const hourly = {};
  clicks.forEach(click => {
    const hour = new Date(click.timestamp).getHours();
    hourly[hour] = (hourly[hour] || 0) + 1;
  });
  return hourly;
}

function getFilterStats(clicks) {
  const stats = { allowed: 0, redirected: 0, blocked: 0 };
  clicks.forEach(click => {
    if (click.filterAction === 'allow') stats.allowed++;
    else if (click.filterAction === 'redirect') stats.redirected++;
    else if (click.filterAction === 'block') stats.blocked++;
  });
  return stats;
}

// Main redirect endpoint
app.get('/:shortCode', async (req, res) => {
  const { shortCode } = req.params;
  const userAgent = req.headers['user-agent'] || '';
  const clientIP = getClientIP(req);
  
  try {
    console.log(`🔍 Processing redirect for ${shortCode} from IP ${clientIP}`);

    // Find link
    const link = Array.from(links.values()).find(l => l.shortCode === shortCode);
    if (!link || !link.isActive) {
      console.log(`❌ Link not found or inactive: ${shortCode}`);
      return res.status(404).send(`
        <h1>Link Not Found</h1>
        <p>The short link <strong>${shortCode}</strong> was not found or is no longer active.</p>
      `);
    }

    // Analyze IP
    const ipAnalysis = await ipAnalysisService.analyzeIP(clientIP);
    console.log(`🌍 IP Analysis for ${clientIP}:`, {
      country: ipAnalysis.country_code,
      isVPN: ipAnalysis.is_vpn,
      riskScore: ipAnalysis.risk_score,
      isp: ipAnalysis.isp
    });

    // Apply redirect rules
    let targetUrl = link.defaultUrl;
    const linkRules = Array.from(redirectRules.values())
      .filter(rule => rule.linkId === link.id)
      .sort((a, b) => a.priority - b.priority);

    for (const rule of linkRules) {
      if (rule.countryCodes.includes(ipAnalysis.country_code)) {
        targetUrl = rule.targetUrl;
        console.log(`✅ Applied rule: ${rule.name} → ${targetUrl}`);
        break;
      }
    }

    // Apply filtering
    const filterDecision = await filteringEngine.shouldFilter(
      ipAnalysis, 
      ipAnalysis.country_code, 
      link
    );

    console.log(`🛡️ Filter decision:`, filterDecision);

    // Handle filter decision
    if (filterDecision.action === 'block') {
      const clickData = logClick(link.id, clientIP, userAgent, ipAnalysis, 'BLOCKED', filterDecision);
      console.log(`🚫 Blocked access from ${clientIP} (${filterDecision.reason})`);
      
      return res.status(403).send(`
        <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
          <h1 style="color: #e74c3c;">Access Restricted</h1>
          <p>Sorry, access from your location is currently restricted.</p>
          <p><small>Reason: ${filterDecision.reason}</small></p>
          <p><small>Request ID: ${clickData.id}</small></p>
        </div>
      `);
    } else if (filterDecision.action === 'redirect') {
      // Redirect to safe/alternative URL
      targetUrl = link.defaultUrl; // Use safe fallback
      console.log(`🔄 Redirecting to safe URL due to: ${filterDecision.reason}`);
    }

    // Log the click
    const clickData = logClick(link.id, clientIP, userAgent, ipAnalysis, targetUrl, filterDecision);

    // Check for in-app browser
    const browserDetection = browserDetectionService.detect(userAgent, req.headers);
    
    if (browserDetection.isInApp) {
      console.log(`📱 In-app browser detected: ${browserDetection.app || 'unknown'}`);
      const redirectHTML = browserDetectionService.generateNativeBrowserHTML(targetUrl, userAgent);
      return res.send(redirectHTML);
    } else {
      console.log(`🌐 Regular browser detected, redirecting to result page`);
      
      // Prepare data for redirect result page
      const resultData = {
        shortCode: shortCode,
        originalUrl: targetUrl,
        clientIP: clientIP,
        country: ipAnalysis.country_code,
        city: ipAnalysis.city,
        isp: ipAnalysis.isp,
        isVPN: ipAnalysis.is_vpn,
        isProxy: ipAnalysis.is_proxy,
        isTor: ipAnalysis.is_tor,
        fraudScore: ipAnalysis.risk_score,
        userAgent: userAgent,
        browser: browserDetection.browser?.name,
        platform: browserDetection.os?.name,
        appliedRule: filterDecision.reason,
        status: ipAnalysis.is_tor ? 'tor' : ipAnalysis.is_vpn ? 'vpn' : ipAnalysis.is_proxy ? 'proxy' : 'safe',
        timestamp: new Date().toISOString()
      };
      
      const encodedData = encodeURIComponent(JSON.stringify(resultData));
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
      const redirectUrl = `${frontendUrl}/redirect-result?data=${encodedData}`;
      
      return res.redirect(302, redirectUrl);
    }

  } catch (error) {
    console.error('❌ Redirect processing error:', error);
    return res.status(500).send(`
      <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
        <h1 style="color: #e74c3c;">Service Temporarily Unavailable</h1>
        <p>Please try again in a few moments.</p>
      </div>
    `);
  }
});

// Test endpoint for demo IPs
app.post('/api/test-redirect/:shortCode', async (req, res) => {
  const { shortCode } = req.params;
  const { testIP, userAgent: testUserAgent } = req.body;
  
  try {
    const link = Array.from(links.values()).find(l => l.shortCode === shortCode);
    if (!link) {
      return res.status(404).json({ success: false, message: 'Link not found' });
    }

    const ipAnalysis = await ipAnalysisService.analyzeIP(testIP);
    
    let targetUrl = link.defaultUrl;
    const linkRules = Array.from(redirectRules.values())
      .filter(rule => rule.linkId === link.id)
      .sort((a, b) => a.priority - b.priority);

    let appliedRule = null;
    for (const rule of linkRules) {
      if (rule.countryCodes.includes(ipAnalysis.country_code)) {
        targetUrl = rule.targetUrl;
        appliedRule = rule;
        break;
      }
    }

    const filterDecision = await filteringEngine.shouldFilter(
      ipAnalysis, 
      ipAnalysis.country_code, 
      link
    );

    const browserDetection = browserDetectionService.detect(testUserAgent || '');

    const result = {
      link: { id: link.id, shortCode: link.shortCode, name: link.name },
      ipAnalysis,
      appliedRule,
      targetUrl,
      filterDecision,
      browserDetection,
      wouldRedirect: filterDecision.action !== 'block'
    };

    res.json({ success: true, data: result });
  } catch (error) {
    console.error('Test redirect error:', error);
    res.status(500).json({ success: false, message: 'Test failed' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    links: links.size,
    rules: redirectRules.size,
    clicks: clicksData.length
  });
});

// Initialize demo data
initializeDemoData();

// For Vercel deployment
if (process.env.VERCEL) {
  module.exports = app;
} else {
  // For local development
  app.listen(PORT, () => {
    console.log(`
🚀 Smart Redirect Demo Server running on port ${PORT}

📊 Demo Data:
- Links: ${links.size}
- Redirect Rules: ${redirectRules.size}
- API Endpoints: /api/*
- Redirect Endpoint: /:shortCode

🔗 Test Links:
- http://localhost:${PORT}/demo1
- http://localhost:${PORT}/promo2024

🛡️ Demo IPs for testing:
- 185.220.101.42 (Germany, Tor, High Risk)
- 217.160.0.152 (Italy, VPN, High Risk)
- 79.18.183.45 (Italy, Clean, Low Risk)
- 208.67.222.222 (USA, Clean, Low Risk)
- 52.210.112.33 (Ireland, Clean, Medium Risk)

📱 Admin Dashboard: Build frontend and access via React app

🎯 Ready for client demo!
    `);
  });
}