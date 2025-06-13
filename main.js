// IMPORT our modules!
const GitHubScanner = require('./github-api.js');
const AIAnalyzer = require('./ai-analyzer.js');

const github = new GitHubScanner(process.env.GITHUB_TOKEN);
const ai = new AIAnalyzer(process.env.OPENROUTER_API_KEY);
