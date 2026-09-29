/*console.log("HEURISTICS module is working");

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
*/

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

        // --- NEW ADDED RULES ---

        // 10. Non-standard / suspicious port check
        if (parsedUrl.port && !['80', '443', '8080', '8443'].includes(parsedUrl.port)) 
        {
            riskScore += 25;
            warnings.push('Uses a non-standard or potentially risky port');
        }

        // 11. Punycode / IDN homograph attack check
        if (hostname && hostname.startsWith('xn--')) 
        {
            riskScore += 35;
            warnings.push('Uses Punycode (potential IDN homograph spoofing attack)');
        }

        // 12. Excessive slashes / deep directory path nesting
        const slashCount = (parsedUrl.pathname.match(/\//g) || []).length;
        if (slashCount > 5) 
        {
            riskScore += 20;
            warnings.push('Excessive directory nesting in URL path');
        }

        // 13. Suspicious nested structure: first directory after TLD is a random string followed by more paths
        const pathSegments = parsedUrl.pathname.split('/').filter(Boolean);
        
        if (pathSegments.length >= 2) {
            const firstSegment = pathSegments[0];
            
            // Check if the first segment looks like a random token/hash (alphanumeric or long number)
            const isFirstSegmentRandom = (
                (firstSegment.length > 6 && /[a-z]/i.test(firstSegment) && /\d/.test(firstSegment)) ||
                (firstSegment.length > 8 && /^\d+$/.test(firstSegment))
            );

            if (isFirstSegmentRandom) {
                riskScore += 35;
                warnings.push('URL starts with a random/obfuscated directory followed by nested paths');
            }
        }

        // 14. Long random string inside subdomain label
        if (subdomains.some(sub => sub.length > 15 && /\d/.test(sub))) 
        {
            riskScore += 35;
            warnings.push('Contains an unusually long, randomized subdomain label');
        }

        // 15. Catch uncommon/suspicious custom TLD length or format
        const tld = '.' + subdomains[subdomains.length - 1];
        if (tld.length > 6 && !['.com', '.org', '.net', '.edu', '.gov'].includes(tld))
        {
            riskScore += 20;
            warnings.push('Uses an uncommon or unusually long TLD suffix');
        }

        // -----------------------

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
            url: cleanUrl,
            error: 'Failed to run heuristics check.'
        };
    }
}

module.exports = heuristicsCheck;
