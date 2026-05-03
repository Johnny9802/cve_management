module.exports = {
  port: process.env.PORT || 3001,
  database: {
    url: process.env.DATABASE_URL,
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://redis:6379',
    password: process.env.REDIS_PASSWORD,
  },
  nvd: {
    baseUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    apiKey: process.env.NVD_API_KEY || '',
    // Without API key: 5 req/30s. With key: 50 req/30s
    requestDelay: process.env.NVD_API_KEY ? 600 : 6100,
    resultsPerPage: 100,
  },
  epss: {
    baseUrl: 'https://api.first.org/data/v1/epss',
  },
  cisaKev: {
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    refreshInterval: 6 * 60 * 60 * 1000, // 6 hours
  },
  cache: {
    ttl: {
      dashboard: 5 * 60,     // 5 min
      cveList: 10 * 60,      // 10 min
      cveDetail: 60 * 60,    // 1 hour
      epss: 24 * 60 * 60,    // 24 hours
      kev: 6 * 60 * 60,      // 6 hours
    },
  },
};
