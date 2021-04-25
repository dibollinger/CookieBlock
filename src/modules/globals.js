// Author: Dino Bollinger
// License: MIT

const enableExtraOptions = false;

/**
 * Helper function for storing content in sync or local storage.
 * @param {*} newValue New value to store.
 * @param {Object} stType  Sync or Local Storage Object
 * @param {String} key Unique storage key identifier
 * @param {Boolean} override If true, will override the existing value.
 */
const setStorageValue = async function(newValue, stType, key, override = true) {
    let obj;
    if (override) {
        obj = {}; obj[key] = newValue;
        stType.set(obj)
    } else {
        let cValue = (await stType.get(key))[key];
        if (cValue === undefined) {
            obj = {}; obj[key] = newValue;
            stType.set(obj)
        }
    }
}


/**
 * Helper function for retrieving content in sync or local storage.
 * @param {*} stType Storage type
 * @param {*} key
 * @returns
 */
 const getStorageValue = async function(stType, key) {
    let value = (await stType.get(key))[key];
    if (value === undefined) {
        console.warn(`Warning: Value '${key}' not found in storage!`);
        console.trace();
        if (Array.isArray(defaultConfig[key])){
            await setStorageValue([...defaultConfig[key]], stType, key, override=false);
        } else {
            await setStorageValue(defaultConfig[key], stType, key, override=false);
        }
    }
    return value;
 }


/**
* Retrieves the data at the given URL with the specified type. Only intended for local extension data access.
* Once the response arrives, a callback is executed with the response object.
* @param {String} url          URL to send the GET request to, intended to be a local extension URL.
* @param {String} dtype        Type of the data. Examples: "json", "text", "binary"
* @param {Function} callback   Callback function that will be executed as soon as the data is available, receives data as first argument.
*/
const getExtensionFile = function(url, dtype, callback) {
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
    new_url = new_url.replace(/^\./, ""); // cookies can start like .www.example.com
    new_url = new_url.replace(/^http(s)?:\/\//, "");
    new_url = new_url.replace(/^www([0-9])?/, "");
    new_url = new_url.replace(/^\./, "");
    new_url = new_url.replace(/\/.*$/, "");
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

/**
 * Helper function to assign static localization text to an element's textContent field.
 * @param {String} elemID Element ID
 * @param {String} locID Localization ID
 * @param {Array} args List of positional arguments for the localization.
 */
const setStaticLocaleText = (elemID, locID, args=[]) => {
    try{
        document.getElementById(elemID).textContent = browser.i18n.getMessage(locID, args);
    } catch (err) {
        console.error(`Failed to apply localization for id '${elemID}' with text '${locID}'.`)
        console.error("Original Error Message: " + err.message)
    }
};

/**
 * Reset the default values no matter what is currently stored.
 * @param {Object} resp  Default configuration
 */
 const overrideDefaults = function(dfConfig) {
    setStorageValue([...dfConfig["cblk_userpolicy"]], browser.storage.sync, "cblk_userpolicy");
    setStorageValue(dfConfig["cblk_pscale"], browser.storage.sync, "cblk_pscale");
    setStorageValue(dfConfig["cblk_pause"], browser.storage.local, "cblk_pause");
    setStorageValue(dfConfig["cblk_ulimit"], browser.storage.local, "cblk_ulimit");
    setStorageValue([...dfConfig["cblk_exglobal"]], browser.storage.sync, "cblk_exglobal");
    setStorageValue([...dfConfig["cblk_exfunc"]], browser.storage.sync, "cblk_exfunc");
    setStorageValue([...dfConfig["cblk_exanal"]], browser.storage.sync, "cblk_exanal");
    setStorageValue([...dfConfig["cblk_exadvert"]], browser.storage.sync, "cblk_exadvert");
  }


// default configuration
var defaultConfig = undefined;
getExtensionFile(browser.extension.getURL("ext_data/default_config.json"), "json", (df)=> {defaultConfig = df});
