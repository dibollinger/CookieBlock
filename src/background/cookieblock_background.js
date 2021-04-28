//-------------------------------------------------------------------------------
/*
Copyright (C) 2021 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------


// for debugging
var httpRemovalCounter = 0;
var httpsRemovalCounter = 0;

// Lookup for known cookies, to prevent some critical login issues.
var known_cookies = {};

// key used with the known_cookies object
const regexKey = "~regex;";

// Local cookie and stats storage, required so as to not constantly have to hammer the storage.local object.
var localCookieStorage = undefined;
var localStatsCounter = undefined;

/**
 * Check if the cookie is contained in the storage.
 * @param {Object} cookieDat Raw untransformed cookie data.
 * @returns {Boolean} true if contained, false otherwise
 */
const checkCookieInStorage = function(cookieDat) {
    console.assert(localCookieStorage !== undefined, "Local cookie storage was undefined!");
    let d = urlToUniformDomain(cookieDat.domain);
    if (d in localCookieStorage) {
        let p = cookieDat.path;
        if (p in localCookieStorage[d]) {
            return cookieDat.name in localCookieStorage[d][p];
        }
    }
    return false;
}

/**
 * Insert serialized cookie into storage
 * @param {Object} cookieDat
 * @returns
 */
const insertCookieIntoStorage = function(cookieDat, serializedCookie) {
    console.assert(localCookieStorage !== undefined, "Local cookie storage was undefined!");

    let d = urlToUniformDomain(cookieDat.domain);
    let p = cookieDat.path;

    localCookieStorage[d] = localCookieStorage[d] || {};
    localCookieStorage[d][p] = localCookieStorage[d][p] || {};
    localCookieStorage[d][p][cookieDat.name] = serializedCookie;
}

/**
 * Retrieve serialized cookie from storage
 * @param {*} cookieDat
 * @returns
 */
const retrieveCookieFromStorage = function(cookieDat) {
    console.assert(localCookieStorage !== undefined, "Local cookie storage was undefined!");
    let d = urlToUniformDomain(cookieDat.domain);
    return localCookieStorage[d][cookieDat.path][cookieDat.name];
}


/**
 * Asynchronous callback function to set up config and storage defaults.
 * This initializes all chrome local and sync storage objects if undefined.
 * @param {Object} resp  Default configuration
 */
 const initDefaults = async function(dfConfig) {
    setStorageValue([...dfConfig["cblk_userpolicy"]], chrome.storage.sync, "cblk_userpolicy", false);
    setStorageValue(dfConfig["cblk_pscale"], chrome.storage.sync, "cblk_pscale", false);
    setStorageValue(dfConfig["cblk_pause"], chrome.storage.local, "cblk_pause", false);
    setStorageValue(dfConfig["cblk_ulimit"], chrome.storage.local, "cblk_ulimit", false);
    setStorageValue(dfConfig["cblk_hconsent"], chrome.storage.sync, "cblk_hconsent", false);
    setStorageValue([...dfConfig["cblk_exglobal"]], chrome.storage.sync, "cblk_exglobal", false);
    setStorageValue([...dfConfig["cblk_exfunc"]], chrome.storage.sync, "cblk_exfunc", false);
    setStorageValue([...dfConfig["cblk_exanal"]], chrome.storage.sync, "cblk_exanal", false);
    setStorageValue([...dfConfig["cblk_exadvert"]], chrome.storage.sync, "cblk_exadvert", false);
    setStorageValue(dfConfig["cblk_mintime"], chrome.storage.sync, "cblk_mintime", false);
    await setStorageValue({}, chrome.storage.local, "cblk_storage", false);
    await setStorageValue([0,0,0,0,0], chrome.storage.local, "cblk_counter", false);
    localCookieStorage = await getStorageValue(chrome.storage.local, "cblk_storage");
    localStatsCounter = await getStorageValue(chrome.storage.local, "cblk_counter");
  }


/**
* Clear the local storage.
*/
const clearLocalStorage = function() {
    localCookieStorage = {};
    localStatsCounter = [0,0,0,0,0];
    setStorageValue({}, chrome.storage.local, "cblk_storage");
    setStorageValue([0,0,0,0,0], chrome.storage.local, "cblk_counter");
}


/**
* Creates a new feature extraction input object from the raw cookie data.
* @param  {Object} cookie    Raw cookie data as received from the browser.
* @return {Promise<object>}  Feature Extraction input object.
*/
const createFEInput = function(cookie) {
    return {
      "name": escapeString(cookie.name),
      "domain": escapeString(cookie.domain),
      "path": escapeString(cookie.path),
      // empty string if browser does not have first party isolation active
      "first_party_domain": null,
      "storeId": escapeString(cookie.storeId),
      "variable_data":
      [
        {
          "host_only": cookie.hostOnly,
          "http_only": cookie.httpOnly,
          "secure": cookie.secure,
          "session": cookie.session,
          "expiry": datetimeToExpiry(cookie),
          "value": escapeString(cookie.value),
          "same_site": escapeString(cookie.sameSite),
          "timestamp": Date.now()
        }
      ],
      // last category label and timestamp
      "last_label": -1,
      "label_ts": 0
    };
}

/**
 * Updates the existing feature extraction object with data from the new cookie.
 * Specifically, the variable data attribute will have the new cookie's data appended to it.
 * If the update limit is reached, the oldest update will be removed.
 * @param  {Object} prevCookie   Feature Extraction input, previously constructed.
 * @param  {Object} newCookie    New cookie data, untransformed.
 * @return {Promise<object>}     The existing cookie object, updated with new data.
 */
const updateFEInput = async function(prevCookie, newCookie) {

    let updateArray = prevCookie["variable_data"];
    let updateLimit = await getStorageValue(chrome.storage.local, "cblk_ulimit");

    let updateStruct = {
        "host_only": newCookie.hostOnly,
        "http_only": newCookie.httpOnly,
        "secure": newCookie.secure,
        "session": newCookie.session,
        "expiry": datetimeToExpiry(newCookie),
        "value": escapeString(newCookie.value),
        "same_site": escapeString(newCookie.sameSite),
        "timestamp": Date.now()
    };

    // remove head if limit reached
    if (updateArray.length === updateLimit)
        updateArray.shift();

    updateArray.push(updateStruct);
    console.assert(updateArray.length <= updateLimit, "Error: cookie update limit still exceeded!");

    return prevCookie;
};


/**
* Update the extension-specific cookie update storage, for feature extraction inputs.
* Either creates a new object or updates an existing one if found.
* @param  {Object} cookieDat     Cookie data object as received from the browser.
* @param  {Object} cookieStore   Object in which all cookies are indexed.
* @return {Promise<object>}      The new feature extraction input.
*/
const serializeOrUpdate = async function(cookieDat) {
    let serializedCookie;
    if (checkCookieInStorage(cookieDat)) {
        serializedCookie = await updateFEInput(retrieveCookieFromStorage(cookieDat), cookieDat);
    } else {
        serializedCookie = createFEInput(cookieDat);
    }
    return serializedCookie;
};


/**
 * Using the cookie input, extract features from the cookie and classify it, retrieving a label.
 * @param  {Object} feature_input   Transformed cookie data input, for the feature extraction.
 * @return {Promise<Number>}        Cookie category label as an integer, ranging from [0,3].
 */
const classifyCookie = async function(feature_input) {
    let features = extractFeatures(feature_input);
    let pscale = await getStorageValue(chrome.storage.sync, "cblk_pscale");
    let label = await predictClass(features, pscale);
    console.assert(label >= 0 && label < 4, "Predicted label exceeded valid range: %d", label);
    return label;
};


/**
 * Decides whether to keep the cookie or delete it, based on user policy.
 * @param  {Object} cookieDat   Raw cookie data as retrieved from the browser, with "storeId".
 * @param  {Number} label       Label predicted by the classifier.
 */
const makePolicyDecision = async function(cookieDat, label) {

    let cName = classIndexToString(label);

    let ckDomain = sanitizeDomain(escapeString(cookieDat.domain));
    let skipRejection = false;
    switch(label) {
        case 1: // functionality
            skipRejection = (await getStorageValue(chrome.storage.sync, "cblk_exfunc")).includes(ckDomain);
            break;
        case 2: // analytics
            skipRejection = (await getStorageValue(chrome.storage.sync, "cblk_exanal")).includes(ckDomain);
            break;
        case 3: // advertising
            skipRejection = (await getStorageValue(chrome.storage.sync, "cblk_exadvert")).includes(ckDomain);
            break;
    }

    if (skipRejection) {
        console.debug(`Cookie found on whitelist for category '${cName}': '${cookieDat.name}';'${cookieDat.domain}';'${cookieDat.path}'`);
    } else {
        let consentArray = await getStorageValue(chrome.storage.sync, "cblk_userpolicy");
        console.assert(consentArray !== undefined, "User policy was somehow undefined!")
        if (consentArray[label]) {
            // spare the cookie
            //console.debug("Affirmative consent for cookie (%s;%s;%s) with label (%s).", cookieDat.name, cookieDat.domain, cookieDat.path, cName);
        } else {
            //console.debug("Negative consent for cookie (%s;%s;%s) with label (%s).", cookieDat.name, cookieDat.domain, cookieDat.path, cName);

            // First try to remove the cookie, using https as the protocol
            chrome.cookies.remove({
                "name": cookieDat.name,
                "url": "https://" + cookieDat.domain + cookieDat.path,
                "storeId": cookieDat.storeId
            }, (remResultHTTPS) => {
                // check if removal was successful -- if not, retry with http protocol
                if (remResultHTTPS === null){
                    remResultHTTPS = chrome.cookies.remove({
                        "name": cookieDat.name,
                        "url": "http://" + cookieDat.domain + cookieDat.path,
                        "storeId": cookieDat.storeId
                    }, (remResultHTTP) => {
                        if (remResultHTTP === null){
                            // If failed again, report error.
                            console.error("Could not remove cookie (%s;%s;%s) with label (%s).", cookieDat.name, cookieDat.domain, cookieDat.path, cName);
                        } else {
                            //console.debug("Cookie (%s;%s;%s) with label (%s) has been removed successfully over HTTP protocol.", cookieDat.name, cookieDat.domain, cookieDat.path, cName);
                            httpRemovalCounter += 1;
                        }
                    });
                } else {
                    //console.debug("Cookie (%s;%s;%s) with label (%s) has been removed successfully over HTTPS protocol.", cookieDat.name, cookieDat.domain, cookieDat.path, cName);
                    httpsRemovalCounter += 1;
                }
            });
        }
    }
};

/**
 * Given a cookie, checks the local known_cookies listing (exact domain match and regex).
 * @param {Object} cookieDat Contains the current cookie's data.
 */
const cookieLookup = function(cookieDat) {
    let nameLookup = (cName, namesObj) => {
        if (cName in namesObj) return namesObj[cName];
        else return -1;
    };

    let cleanDomain = sanitizeDomain(cookieDat.domain);
    if (cleanDomain in known_cookies["exact_match"]) {
        return nameLookup(cookieDat.name, known_cookies["exact_match"][cleanDomain]);
    } else {
        for (let obj of Object.values(known_cookies["regex_match"])) {
            if (obj[regexKey].test(cleanDomain)){
                return nameLookup(cookieDat.name, obj);
            }
        }
        return -1;
    }
}


/**
 * Enforce the consent policy.
 * @param {Object} cookieDat Original untransformed cookie object.
 * @param {Object} serializedCookie Transformed cookie object, with potential updates.
 */
const enforcePolicy = async function (cookieDat, serializedCookie, storeUpdate) {
    let ckey = cookieDat.name + ";" + cookieDat.domain + ";" + cookieDat.path;
    let globalExcepts = await getStorageValue(chrome.storage.sync, "cblk_exglobal");
    let ckDomain = sanitizeDomain(serializedCookie.domain);
    if (globalExcepts.includes(ckDomain)) {
        console.debug(`Cookie found in domain whitelist: (${ckey})`);
        localStatsCounter[4] += 1;
    } else {
        let minTime = await getStorageValue(chrome.storage.sync, "cblk_mintime");
        let elapsed = Date.now() - serializedCookie["label_ts"];

        console.assert(typeof serializedCookie["last_label"] === "number", "Incorrect type stored in last label.");
        console.assert(typeof serializedCookie["label_ts"] === "number", "Incorrect type stored in label timestamp.");

        let label;
        if (serializedCookie["last_label"] === -1 || elapsed > minTime) {
            // classify the cookie
            label = cookieLookup(cookieDat);
            if (label === -1) {
                label = await classifyCookie(serializedCookie);
            }

            localStatsCounter[label] += 1;
            serializedCookie["last_label"] = label;
            serializedCookie["label_ts"] = Date.now();
            let cName = classIndexToString(label);
            console.debug("Perform Prediction: Cookie (%s;%s;%s) receives label (%s)", cookieDat.name, cookieDat.domain, cookieDat.path, cName)
        } else {
            label = serializedCookie["last_label"];
            let cName = classIndexToString(label);
            console.debug("Skip Prediction: Cookie (%s;%s;%s) with label (%s)", cookieDat.name, cookieDat.domain, cookieDat.path, cName)
        }

        // make a decision
        let dstate = await getStorageValue(chrome.storage.local, "cblk_pause")
        if (dstate) {
            let cName = classIndexToString(label);
            console.debug(`Pause Mode Removal Skip: Cookie Identifier: ${ckey} -- Assigned Label: ${cName}`);
        } else {
            makePolicyDecision(cookieDat, label);
        }
    }

    if (storeUpdate) {
        // check if consent is given for history storing
        insertCookieIntoStorage(cookieDat, serializedCookie);
    }
}

/**
 * Enforces the cookie consent policy without using or updating a local cookie storage.
 * @param {Object} cookieDat Object that contains the data for the current cookie.
 */
 const enforcePolicyWithoutHistory = function (cookieDat){
    let serializedCookie = createFEInput(cookieDat);
    enforcePolicy(cookieDat, serializedCookie, false);
}


/**
 * Enforce the cookie consent policy, utilizing and updating the local cookie history.
 * @param {Object} cookieDat Object that contains the data for the current cookie update.
 * @param {Boolean} storeUpdate If true, will store the update to the cookie.
 */
 const enforcePolicyWithHistory = async function (cookieDat, storeUpdate){
    let serializedCookie = await serializeOrUpdate(cookieDat);
    enforcePolicy(cookieDat, serializedCookie, storeUpdate);
}


/**
* Listener that is executed any time a cookie is added, updated or removed.
* Classifies the cookie and rejects it based on user policy.
* @param {Object} changeInfo  Contains the cookie itself, and cause info.
*/
const cookieChangeListener = async function(changeInfo) {
    // do nothing in this case
    if (changeInfo.removed) {
        return;
    }

    // check if consent is given for history storing
    let history_consent = await getStorageValue(chrome.storage.sync, "cblk_hconsent");
    if (history_consent) {
        enforcePolicyWithHistory(changeInfo.cookie, true);
    } else {
        enforcePolicyWithoutHistory(changeInfo.cookie);
    }
};


/**
 * Listener function that opens the first time setup when the extension is installed.
 * @param {Object} details Contains the reason for the change.
 */
const firstTimeSetup = function(details) {
  if (details.reason === "install") {
    chrome.tabs.create({"active": true, "url": "/options/cookieblock_setup.html"});
  }
}


/**
 * Handle messages from other content scripts within the extension.
 * @param {Object} request Request object, containing the function type.
 * @param {Object} sender Sender origin.
 * @param {*} sendResponse response function
 */
const handleInternalMessage = function(request, sender, sendResponse) {
    console.debug("Background script received a message.")
    if (request.classify_all) {
        getStorageValue(chrome.storage.sync, "cblk_hconsent").then((history_consent) => {
            chrome.cookies.getAll({}, (allCookies) => {
                for (let cookieDat of allCookies) {
                    if (history_consent) {
                        enforcePolicyWithHistory(cookieDat, false);
                    } else {
                        enforcePolicyWithoutHistory(cookieDat);
                    }
                }
                setStorageValue(localCookieStorage, chrome.storage.local, "cblk_storage");
                setStorageValue(localStatsCounter, chrome.storage.local, "cblk_counter");
                sendResponse({response: "All cookies classified and policy enforced."});
            });
        });
        return true;
    } else if (request.get_stats) {
        sendResponse({response: localStatsCounter});
    } else if (request.reset_storage) {
        clearLocalStorage();
        sendResponse({response: "Local cookie and stats storage cleared."});
    } else {
        sendResponse({response: undefined});
    }
}


// Periodically save the current cookie store (every minute)
setInterval( async () => {
    setStorageValue(localCookieStorage, chrome.storage.local, "cblk_storage");
    setStorageValue(localStatsCounter, chrome.storage.local, "cblk_counter");
    console.debug("Saved current cookie store and stats counter.");
}, 60_000);

// set up defaults and listeners
getExtensionFile(chrome.extension.getURL("ext_data/default_config.json"), "json", initDefaults);
getExtensionFile(chrome.extension.getURL("ext_data/known_cookies.json"), "json", (result) => {
    for (let k of Object.keys(result["regex_match"])) {
        result["regex_match"][k][regexKey] = new RegExp(k);
    }
    known_cookies = result;
});
chrome.cookies.onChanged.addListener(cookieChangeListener);
chrome.runtime.onInstalled.addListener(firstTimeSetup);
chrome.runtime.onMessage.addListener(handleInternalMessage);
