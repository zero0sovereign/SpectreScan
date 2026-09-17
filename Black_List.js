console.log("BLACKLIST module is working");

async function blacklistCheck(url) {
    return {
        working: true,
        url: url
    };
}

module.exports = blacklistCheck;
//usman sun, apna program local files i.e blacklist files me dhundega, lekin unn files ko update karne ke liye kuch code karna padega
//pehle sirf files ko integrate karke try kar, phir file update ka dekhte
