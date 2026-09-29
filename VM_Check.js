console.log("VM SANDBOX module is working");

async function vmSandboxCheck(url) 
{
    const TARGET_VM_URL = 'http://localhost:4000/scan';

    async function sendToVM(urlToScan) 
    {
        try 
        {
            console.log("----------------------------------------");
            console.log("[Host] ---> BEFORE sending request to VM API...");
            
            const response = await fetch(TARGET_VM_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targetUrl: urlToScan })
            });

            const data = await response.json();
            
            console.log("[Host] <--- AFTER receiving response from VM API:");
            console.log(JSON.stringify(data, null, 2));
            console.log("----------------------------------------");

        } 
        
        catch (error) 
        {
            console.error('[Host] Error communicating with VM:', error.message);
        }
    }

    // Await the call so the indicators show exact timing
    await sendToVM(url);

    return {
        working: true,
        url: url
    };
}

module.exports = vmSandboxCheck;
