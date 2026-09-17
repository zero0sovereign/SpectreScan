console.log("HEURISTICS module is working");

async function heuristicsCheck(cleanUrl) 
{
    try 
    {
        const parsedUrl = new URL(cleanUrl);
        const hostname = parsedUrl.hostname;
        let riskScore = 0;
        let warnings = [];

        
        
        // 1. Raw IP address check
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipRegex.test(hostname)) 
        {
            riskScore += 40;
            warnings.push('Uses raw IP address instead of domain');
        }

        // 2. Excessive length
        if (cleanUrl.length > 75) 
        {
            riskScore += 20;
            warnings.push('Unusually long URL string');
        }

        // 3. Excessive subdomains
        const subdomains = hostname.split('.');
        if (subdomains.length > 4) 
        {
            riskScore += 25;
            warnings.push('High number of subdomains');
        }

        // 4. @ symbol obfuscation trick
        if (cleanUrl.includes('@')) 
        {
            riskScore += 50;
            warnings.push('Contains @ symbol (potential credential bypass trick)');
        }

        // 5. Direct executable extension
        if (/\.(exe|bat|cmd|sh|scr|pif)$/i.test(cleanUrl)) 
        {
            riskScore += 40;
            warnings.push('Points directly to an executable file extension');
        }

        // 6. High-risk TLDs, extensions after hostname
        const highRiskTlds = ['.zip', '.mov', '.xyz', '.top', '.gq', '.ml', '.cf', '.tk'];
        if (highRiskTlds.some(tld => hostname.endsWith(tld))) 
        {
            riskScore += 30;
            warnings.push('Uses a high-risk or commonly abused TLD');
        }

        // 7. Dangerous file/archive extensions inside the path
        const riskyExtensions = /\.(zip|rar|7z|tar|gz|exe|bat|cmd|sh|scr|pif)$/i;
        if (riskyExtensions.test(parsedUrl.pathname)) 
        {
            riskScore += 30;
            warnings.push('URL path points directly to an archive or executable file');
        }

        // 8. Sensitive keyword abuse in subdomains
        const sensitiveKeywords = ['login', 'verify', 'secure', 'account', 'banking', 'update'];
        if (subdomains.length > 2 && sensitiveKeywords.some(keyword => hostname.includes(keyword))) 
        {
            riskScore += 35;
            warnings.push('Sensitive security/brand keywords found in subdomain');
        }

        // 9. Double encoding / traversal patterns
        if (/%25|%00|\.\.%2f|\.\.\\/i.test(cleanUrl)) 
        {
            riskScore += 45;
            warnings.push('Contains double encoding or directory traversal sequences');
        }

        return {
            working: true,
            url: cleanUrl,
            riskScore,
            suspicious: riskScore >= 40,
            warnings
        };
    } 
    
    catch (error) 
    {
        return {
            working: true,
            error: 'Failed to run heuristics check.'
        };
    }
}

module.exports = heuristicsCheck;
