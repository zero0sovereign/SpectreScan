console.log("BLACKLIST module is working");

async function blacklistCheck(url) {
    return {
        working: true,
        url: url
    };
}

module.exports = blacklistCheck;
