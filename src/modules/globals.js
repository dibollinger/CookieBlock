//-------------------------------------------------------------------------------
/*
Copyright (C) 2021 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------


const enableExtraOptions = false;

/**
 * Helper used to transform the local.storage.get callback into an async function.
 * @param {String} key Key of the storage to retrieve.
 * @returns {Promise} A promise which will eventually contain the retrieved value.
 */
 function chromeWorkaround(stType, key) {
    return new Promise((resolve, reject) => {
        stType.get([key], function(result) {
            if (chrome.runtime.lastError){
                reject("Failed to retrieve data from storage: " + chrome.runtime.lastError);
            } else {
                resolve(result[key]);
            }
        });
    });
}

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
        try {
            let cValue = await chromeWorkaround(stType, key);
            if (cValue === undefined) {
                obj = {}; obj[key] = newValue;
                stType.set(obj)
            }
        } catch(err) {
            throw err;
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
    // try to retrieve the value
    let value = undefined;
    try {
        value = await chromeWorkaround(stType, key);
    } catch(err) {
        console.error("Failed to access storage! Error: " + err.message)
    }

    // error handling
    if (value === undefined) {
        console.warn(`Warning: Value '${key}' not found in storage!`);
        if (Array.isArray(defaultConfig[key])) {
            value = [...defaultConfig[key]];
        } else {
            value = defaultConfig[key];
        }
        setStorageValue(value, stType, key, override=false);
    }
    return value;
 }


/**
* Retrieves the data at the given URL with the specified type.
* Once the response arrives, a callback is executed with the response object.
* @param {String} url          URL to send the GET request to, intended to be a local extension URL.
* @param {String} dtype        Type of the data. Examples: "json", "text", "binary"
* @param {Function} callback   Callback function that will be executed as soon as the data is available, receives data as first argument.
*/
const getExtensionFile = function(url, dtype, callback, errorCallback = null) {
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
                console.error("Error -- could not retrieve data at (%s): %d (%s)", url, this.status, this.statusText);
                if (errorCallback){
                    errorCallback(this.status);
                }
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
    if (url === null) {
        return null;
    }
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
        document.getElementById(elemID).textContent = chrome.i18n.getMessage(locID, args);
    } catch (err) {
        console.error(`Failed to apply localization for id '${elemID}' with text '${locID}'.`)
        console.error("Original Error Message: " + err.message)
    }
};


// default configuration
var defaultConfig = undefined;
getExtensionFile(chrome.extension.getURL("ext_data/default_config.json"), "json", (df)=> {defaultConfig = df});
