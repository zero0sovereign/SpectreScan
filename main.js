console.log("Initiating sequence");

document.addEventListener('DOMContentLoaded', () => 
{
    const submitBtn = document.getElementById('submitBtn');
    const myInput = document.getElementById('myInput');

    submitBtn.addEventListener('click', async () => {
        const inputUrl = myInput.value.trim(); 
        
        if (!inputUrl) 
        {
            alert('Please enter a URL');
            return;
        }

        try 
        {
            const response = await fetch('http://localhost:3000/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: inputUrl })
            });

            const data = await response.json();
            console.log('Scan results:', data);
            // TODO: Render 'data' into your terminal UI
        } 
        
        catch (error) 
        {
            console.error('Request failed:', error);
        }
    });
});