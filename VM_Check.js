console.log("VM SANDBOX module is working");

async function vmSandboxCheck(url) {
    return {
        working: true,
        url: url
    };
}

module.exports = vmSandboxCheck;
