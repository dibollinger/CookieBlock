// Author: Dino Bollinger
// License: MIT

/**
 * Retrieve the extension debug setting from extension local storage, or default if not present.
 * @returns {Promise<boolean>}  Debug toggle setting state.
 */
const getDebugState = async function() {
    let debugToggle = (await browser.storage.local.get("cblk_debug"))["cblk_debug"];
    if (debugToggle === undefined) {
        console.warn(`Warning: Debug toggle not found in local storage. Using 'false' as default.`);
        debugToggle = false;
        browser.storage.local.set({"cblk_debug": debugToggle });
    }
    console.assert(typeof debugToggle === "boolean", "Error: Stored debug mode value wasn't a boolean!");
    return debugToggle;
}

/**
 * Retrieve a list of website exceptions from extension sync storage, for which cookies are not removed.
 * Empty list is retrieved if not present.
 * @param {String} sKey Type of list. One of: {"cblk_exglobal", "cblk_exfunc", "cblk_exanal", "cblk_exadvert"}.
 * @returns {Promise<object>} Array of exceptions.
 */
const getExceptionsList = async function(sKey) {
    let exceptionsList = (await browser.storage.sync.get(sKey))[sKey];
    if (exceptionsList === undefined) {
        console.warn(`Warning: Exceptions list for key ${sKey} not in sync storage. Using empty array default.`);
        exceptionsList = [];
        let sobj = {}; sobj[sKey] = exceptionsList;
        browser.storage.sync.set(sobj);
    }
    console.assert(Array.isArray(exceptionsList), "Error: Stored exception list was not an array!");
    return exceptionsList;
}

/**
 * Retrieve statistics counter from extension local storage. zero array if not present.
 * @returns {Promise<object>} Array of statistics counters.
 */
const getStatsCounter = async function() {
    let stats = (await browser.storage.local.get("cblk_counter"))["cblk_counter"];
    if (stats === undefined) {
        console.warn("Warning: Stats not found in local storage. Using zero init array.");
        stats = [0,0,0,0,0];
        browser.storage.local.set({"cblk_counter": stats });
    }
    console.assert(Array.isArray(stats), "Error: Stored stats was not an array!");
    return stats;
}

/**
 * Retrieve the current user policy from sync storage.
 * @returns {Promise<object>} Array of user policy, containing a boolean for each category.
 */
const getUserPolicy = async function() {
    let policy = (await browser.storage.sync.get("cblk_userpolicy"))["cblk_userpolicy"];
    if (policy === undefined) {
        console.warn("Warning: User policy not found in sync storage. Using strict config as default.");
        policy = [1, 0, 0, 0];
        browser.storage.sync.set({"cblk_userpolicy": policy });
    }
    console.assert(Array.isArray(policy), "Error: Stored user policy was not an array!");
    return policy;
}

/**
 * Retrieve the cookie data from local storage.
 * @returns {Promise<object>} Cookie data object, storing each cookie.
 */
const getCookieStorage = async function() {
    let storage = (await browser.storage.local.get("cblk_storage"))["cblk_storage"];
    if (storage === undefined) {
        console.warn("Warning: CookieBlock cookie store was not found. Initializing empty storage.");
        storage = {};
        browser.storage.local.set({ "cblk_storage": storage });
    }
    console.assert(typeof storage === "object", "Error in CookieBlock cookie storage!");
    return storage;
}

/**
 * Retrieve the update limit from sync storage.
 * @returns {Promise<number>} Maximum number of updates to store for each cookie.
 */
const getUpdateLimit = async function() {
    let ulimit = (await browser.storage.sync.get("cblk_ulimit"))["cblk_ulimit"];
    if (ulimit === undefined) {
        console.warn("Warning: CookieBlock update limit was undefined. Initializing limit of 10 updates.");
        ulimit = 10;
        browser.storage.sync.set({"cblk_ulimit": ulimit });
    }
    console.assert(typeof ulimit === "number", "Stored update limit was not a number!");
    return ulimit;
}


/**
* Retrieves the data at the given URL with the specified type. Only intended for local extension data access.
* Once the response arrives, a callback is executed with the response object.
* @param {String} url          URL to send the GET request to, intended to be a local extension URL.
* @param {String} dtype        Type of the data. Examples: "json", "text", "binary"
* @param {Function} callback   Callback function that will be executed as soon as the data is available, receives data as first argument.
*/
const getLocalData = function(url, dtype, callback) {
    const req = new XMLHttpRequest();

    req.responseType = dtype;
    req.onreadystatechange = function(event)
    {
        if (this.readyState === XMLHttpRequest.DONE)
        {
            if (this.status === 200) {
                callback(this.response);
            }
            else {
                console.log("Error -- could not retrieve data at (%s): %d (%s)", url, this.status, this.statusText);
            }
        }
    };

    req.open('GET', url, true);
    req.send(null);
};


/**
* Remove URL encoding from the string
* @param  {String} str   Maybe URL encoded string.
* @return {String}       Decoded String.
*/
const escapeString = function(str) {
    if (typeof str != "string") {
        str = String(str);
    }
    return unescape(encodeURIComponent(str));
}


/**
 * Takes a URL or a domain string and transforms it into a uniform format.
 * Examples: {"www.example.com", "https://example.com/", ".example.com"} --> "example.com"
 * @param {String} domain  Domain to clean and bring into uniform format
 * @return {String}        Cleaned domain string.
 */
const urlToUniformDomain = function(url) {
    let new_url = url.trim();
    new_url = new_url.replace(/^http(s)?:\/\//, "");
    new_url = new_url.replace(/^www([0-9])?/, "");
    new_url = new_url.replace(/^\./, "");
    new_url = new_url.replace(/\/$/, "");
    return new_url;
}

/**
 * Transforms the given domain or URL into a uniform representation.
 * @param {String} domainOrURL    Domain or URL to transform into uniform format
 * @return {String}               Transformed domain.
 */
 const sanitizeDomain = (domainOrURL) => {
    try {
        return urlToUniformDomain(new URL(domainOrURL).hostname);
    } catch(error) {
        return urlToUniformDomain(domainOrURL);
    }
}

/**
* Given a cookie expiration date, compute the expiry time in seconds,
* starting from the current time and date.
* @param  {Object} cookie  Cookie object that contains the attributes "session" and "expirationDate".
* @return {Number}         Expiration time in seconds. Zero if session cookie.
*/
const datetimeToExpiry = function(cookie) {
    let curTS = Math.floor(Date.now() / 1000);
    return cookie.session ? 0 : cookie.expirationDate - curTS;
};


/**
 * Generic error handler function.
 * @param {String} error
 */
 const onError = (error) => {
    console.error(`An error occurred: ${error}`);
}

/**
 * Transform class index to human-readable meaning.
 * @param {Number} idx class label index
 * @returns {String} human-readable string
 */
const classIndexToString = (idx) => {
    switch(idx){
        case -1: return "Unknown";
        case 0: return "Necessary";
        case 1: return "Functionality";
        case 2: return "Analytical";
        case 3: return "Advertising";
        case 4: return "Uncategorized";
        case 5: return "Social Media";
        default: return "Invalid Category Index"
    }
}
