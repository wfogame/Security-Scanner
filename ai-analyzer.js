// File: ai-analyzer.js
// The Complete AI Security Analysis Brain!
// Multi-Model Failover + Vulnerability Detection Engine

const https = require('https');

class AIAnalyzer {
    constructor(apiKey) {
        if (!apiKey) {
            throw new Error('OpenRouter API key is required! Set OPENROUTER_API_KEY environment variable.');
        }
        
        this.apiKey = apiKey;
        this.baseURL = 'openrouter.ai';
        this.basePath = '/api/v1/chat/completions';
        
        // Our AI model arsenal with failover support!
        this.models = [
            {
                name: 'anthropic/claude-sonnet-4',
                priority: 1,
                description: '🧠 Primary AI Brain (Claude Sonnet 4)',
                maxTokens: 4096
            },
            {
                name: 'deepseek/deepseek-r1', 
                priority: 2,
                description: '⚡ Backup Brain (DeepSeek R1)',
                maxTokens: 4096
            }
        ];
        
        console.log('🤖 AI Analyzer initialized with failover support!');
        console.log(`📋 Available models: ${this.models.length}`);
    }

    async analyzeCode(filename, codeContent) {
        console.log(`🔍 Starting AI analysis of: ${filename}`);
        console.log(`📄 Code length: ${codeContent.length} characters`);
        
        // Craft our security-focused prompt!
        const securityPrompt = this.createSecurityPrompt(filename, codeContent);
        
        // Try each model with failover!
        for (const model of this.models) {
            try {
                console.log(`🤖 Attempting analysis with ${model.description}...`);
                const result = await this.callOpenRouter(model, securityPrompt);
                const parsedReport = this.parseSecurityReport(result);
                
                console.log(`✅ Analysis completed successfully with ${model.name}!`);
                return parsedReport;
                
            } catch (error) {
                console.log(`❌ ${model.name} failed: ${error.message}`);
                console.log(`🔄 Trying next model...`);
            }
        }
        
        throw new Error('💀 All AI models failed! Check your API key and network connection.');
    }

    createSecurityPrompt(filename, codeContent) {
        // Craft the PERFECT security analysis prompt!
        return `You are an elite cybersecurity expert conducting a thorough security audit. Analyze this code file with extreme attention to detail.

📁 File: ${filename}
💻 Code to analyze:
\`\`\`
${codeContent}
\`\`\`

🚨 CRITICAL SECURITY ANALYSIS REQUIRED:

Scan for these HIGH-PRIORITY vulnerabilities:
🔸 SQL Injection (missing parameterized queries, string concatenation)
🔸 Cross-Site Scripting (XSS) - stored, reflected, DOM-based
🔸 Hardcoded secrets (API keys, passwords, tokens, database credentials)
🔸 Authentication bypasses and weak session management
🔸 CSRF protection missing
🔸 Insecure file uploads and path traversal
🔸 Command injection and code execution risks
🔸 Weak cryptography and insecure random generation
🔸 Information disclosure and error handling issues
🔸 Authorization flaws and privilege escalation
🔸 Insecure dependencies and outdated libraries

RETURN ANALYSIS AS VALID JSON:
{
  "filename": "${filename}",
  "vulnerabilities": [
    {
      "id": "VULN_001",
      "type": "SQL_INJECTION",
      "severity": "HIGH",
      "confidence": "HIGH",
      "line": 42,
      "code_snippet": "problematic code here",
      "description": "Detailed vulnerability explanation",
      "impact": "What could happen if exploited",
      "fix": "Specific remediation steps",
      "cwe_id": "CWE-89"
    }
  ],
  "securityScore": 75,
  "riskLevel": "MEDIUM",
  "summary": "Overall security assessment",
  "recommendations": ["List of general security improvements"]
}

Be thorough, precise, and security-focused. If no vulnerabilities found, return empty vulnerabilities array with score 100.`;
    }

    async callOpenRouter(model, prompt) {
        return new Promise((resolve, reject) => {
            const requestData = {
                model: model.name,
                messages: [
                    {
                        role: "user", 
                        content: prompt
                    }
                ],
                max_tokens: model.maxTokens,
                temperature: 0.1, // Low temperature for consistent security analysis
                top_p: 0.9
            };

            const postData = JSON.stringify(requestData);
            
            const options = {
                hostname: this.baseURL,
                port: 443,
                path: this.basePath,
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                    'User-Agent': 'WebGuardian-Scanner/2.0'
                },
                timeout: 60000 // 60 second timeout
            };

            const req = https.request(options, (res) => {
                let responseData = '';

                res.on('data', (chunk) => {
                    responseData += chunk;
                });

                res.on('end', () => {
                    try {
                        if (res.statusCode !== 200) {
                            reject(new Error(`HTTP ${res.statusCode}: ${responseData}`));
                            return;
                        }

                        const parsedResponse = JSON.parse(responseData);
                        
                        if (parsedResponse.error) {
                            reject(new Error(`OpenRouter Error: ${parsedResponse.error.message}`));
                            return;
                        }

                        if (!parsedResponse.choices || parsedResponse.choices.length === 0) {
                            reject(new Error('No response choices returned from AI model'));
                            return;
                        }

                        const aiResponse = parsedResponse.choices[0].message.content;
                        resolve(aiResponse);

                    } catch (parseError) {
                        reject(new Error(`Failed to parse AI response: ${parseError.message}`));
                    }
                });
            });

            req.on('error', (error) => {
                reject(new Error(`Network error: ${error.message}`));
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout - AI model took too long to respond'));
            });

            // Send the request
            req.write(postData);
            req.end();
        });
    }

    parseSecurityReport(aiResponse) {
        try {
            console.log('🔧 Parsing AI security report...');
            
            // Clean up the AI response (remove markdown code blocks if present)
            let cleanResponse = aiResponse.trim();
            if (cleanResponse.startsWith('```json')) {
                cleanResponse = cleanResponse.replace(/^```json\s*/, '').replace(/\s*```$/, '');
            } else if (cleanResponse.startsWith('```')) {
                cleanResponse = cleanResponse.replace(/^```\s*/, '').replace(/\s*```$/, '');
            }

            const report = JSON.parse(cleanResponse);
            
            // Validate the report structure
            if (!report.vulnerabilities || !Array.isArray(report.vulnerabilities)) {
                throw new Error('Invalid report format: missing vulnerabilities array');
            }

            // Add metadata
            report.analyzedAt = new Date().toISOString();
            report.analyzerVersion = '2.0';
            report.totalVulnerabilities = report.vulnerabilities.length;
            
            // Calculate risk statistics
            const riskStats = this.calculateRiskStatistics(report.vulnerabilities);
            report.riskStatistics = riskStats;

            console.log(`📊 Analysis complete: ${report.totalVulnerabilities} vulnerabilities found`);
            console.log(`🎯 Security Score: ${report.securityScore}/100`);
            
            return report;

        } catch (parseError) {
            console.error('❌ Failed to parse AI response as JSON');
            console.error('Raw AI Response:', aiResponse);
            
            // Return a fallback report
            return {
                filename: 'unknown',
                vulnerabilities: [],
                securityScore: 0,
                riskLevel: 'UNKNOWN',
                summary: `Failed to parse AI analysis: ${parseError.message}`,
                error: parseError.message,
                rawResponse: aiResponse,
                analyzedAt: new Date().toISOString(),
                analyzerVersion: '2.0'
            };
        }
    }

    calculateRiskStatistics(vulnerabilities) {
        const stats = {
            high: 0,
            medium: 0,
            low: 0,
            critical: 0
        };

        vulnerabilities.forEach(vuln => {
            const severity = vuln.severity ? vuln.severity.toLowerCase() : 'unknown';
            if (stats.hasOwnProperty(severity)) {
                stats[severity]++;
            }
        });

        return stats;
    }

    // Utility method to test the analyzer
    async testConnection() {
        console.log('🧪 Testing AI analyzer connection...');
        
        const testCode = `
const password = "hardcoded123";
app.get('/user', (req, res) => {
    const sql = "SELECT * FROM users WHERE id = " + req.params.id;
    db.query(sql, (err, result) => {
        res.send(result);
    });
});`;

        try {
            const result = await this.analyzeCode('test.js', testCode);
            console.log('✅ AI Analyzer test successful!');
            return result;
        } catch (error) {
            console.error('❌ AI Analyzer test failed:', error.message);
            throw error;
        }
    }
}

// Export our beautiful AI analyzer!
module.exports = AIAnalyzer;