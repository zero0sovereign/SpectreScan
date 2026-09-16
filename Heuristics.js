console.log("HEURISTICS module is working");

async function heuristicsCheck(url) {
    return {
        working: true,
        url: url
    };
}

module.exports = heuristicsCheck;
