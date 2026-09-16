const express = require('express');
const cors = require('cors');

//importing all the modules
const blacklistCheck = require('./modules/Black_List');
const heuristicsCheck = require('./modules/Heuristics');
const vmSandboxCheck = require('./modules/VM_Check');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

app.post('/api/scan', async (req, res) => {
    const { url } = req.body;

    if (!url || typeof url !== 'string') 
    {
        return res.status(400).json({
            error: 'URL is required.'
        });
    }

    let cleanUrl;

    try 
    {
        cleanUrl = new URL(url.trim()).href;
    } 
    
    catch (error) 
    {
        return res.status(400).json({
            error: 'Invalid URL format.'
        });
    }

    try 
    {
        // Run all 3 checks in parallel
        const [blacklist, heuristics, vmSandbox] = await Promise.all([
            blacklistCheck(cleanUrl),
            heuristicsCheck(cleanUrl),
            vmSandboxCheck(cleanUrl)
        ]);

        return res.json({
            status: 'success',
            target: cleanUrl,
            results: {
                blacklist,
                heuristics,
                vmSandbox
            }
        });

    } 
    
    catch (error) 
    {
        console.error('Scan execution error:', error);

        return res.status(500).json({
            error: 'Internal server error during scan.'
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
