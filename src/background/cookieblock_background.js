//-------------------------------------------------------------------------------
/*
Copyright (C) 2021 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------

// local counters for debugging
var debug_httpRemovalCounter = 0;
var debug_httpsRemovalCounter = 0;

// debug performance timers (FE, FE + Prediction)
var debug_perfsum = [BigInt(0), BigInt(0)];
var debug_perfsum_squared = [BigInt(0), BigInt(0)];
var debug_Ntotal = [BigInt(0), BigInt(0)];
var debug_maxTime = [BigInt(0), BigInt(0)];
var debug_minTime = [BigInt(1e10), BigInt(1e10)];

var debug_Nskipped = BigInt(0);

// Variables for all the user options, which is persisted in storage.local and storage.sync
// Retrieving these from disk all the time is a bottleneck.
var cblk_userpolicy = undefined;
var cblk_pscale = undefined;
var cblk_pause = undefined;
var cblk_ulimit = undefined;
var cblk_hconsent = undefined;
var cblk_exglobal = undefined;
var cblk_exfunc = undefined;
var cblk_exanal = undefined;
var cblk_exadvert = undefined;
var cblk_mintime = undefined;

/**
 * Helper function to record the debug timing value.
 * @param {*} elapsed
 */
 const recordDebugTimings = function(elNum, idx) {
    let elapsed = BigInt(elNum);
    if (elapsed > debug_maxTime[idx]) {
        debug_maxTime[idx] = elapsed;
    } else if (elapsed < debug_minTime[idx]) {
        debug_minTime[idx] = elapsed;
    }
    debug_perfsum[idx] += elapsed;
    debug_perfsum_squared[idx] += elapsed * elapsed;
    debug_Ntotal[idx]++;
}

/**
 * To be used in the debug console.
 */
var timingsDebug = function () {
    for (let i = 0; i < 2; i++) {
        console.log(`------------- INDEX ${i} ---------------`)
        if (debug_Ntotal[i] === BigInt(0)){
            console.error(`No cookies classified for index ${i} yet!`)
        } else {
            let mean = debug_perfsum[i] / debug_Ntotal[i];
            let variance = (debug_perfsum_squared[i] / debug_Ntotal[i]) - (mean * mean);
            console.log(`Total Cookies for index ${i}: ${debug_Ntotal[i]}`);
            console.log(`Mean Time: ${mean} ms`);
            console.log(`Variance Time: ${variance} ms`);
            console.log(`Minimum Time: ${debug_minTime[i]} ms`);
            console.log(`Maximum Time: ${debug_maxTime[i]} ms`);
        }
    }
    console.log(`Number of cookies with labels already known: ${debug_Nskipped}`);
    return 0;
}

// lookup for known cookies, to prevent some critical login issues
// will be imported form an external file and kept here
var known_cookies = {};

// key used to access the regular expression pattern in the known_cookies object
const regexKey = "~regex;";

// indexed DB for cookie history
var historyDB = undefined;
const openDBRequest = window.indexedDB.open("CookieBlockHistory", 1);

// executed if the database is new or needs to be updated
openDBRequest.onupgradeneeded = function(event) {
    let objectStore = event.target.result.createObjectStore("cookies");
    objectStore.createIndex("name", "name", { unique: false });
    objectStore.createIndex("domain", "domain", { unique: false });
    objectStore.createIndex("path", "path", { unique: false });
    objectStore.createIndex("label", "current_label", { unique: false });
    console.info("Upgraded the CookieBlock history database.");
};

// success will be called after upgradeneeded
openDBRequest.onsuccess = function(ev1) {
    console.info("Successfully connected to CookieBlock history database.");
    historyDB = ev1.target.result;
    historyDB.onerror = function(ev2) {
        console.error("Database error: " + ev2.target.errorCode);
    };
};

// if the connection failed
openDBRequest.onerror = function(event) {
    console.error(`Failed to open history database with error code: ${event.target.errorCode}`);
};


/**
 * Construct a string formatted key that uniquely identifies the given cookie object.
 * @param {Object} cookieDat Stores the cookie data, expects attributes name, domain and path.
 * @returns {String} string representing the cookie's key
 */
const constructKeyFromCookie = function(cookieDat) {
    return `${cookieDat.name};${urlToUniformDomain(cookieDat.domain)};${cookieDat.path}`;
}


/**
 * Insert serialized cookie into IndexedDB storage via a transaction.
 * @param {Object} serializedCookie Cookie to insert into storage.
 */
const insertCookieIntoStorage = function(serializedCookie) {
    if (historyDB !== undefined) {
        let ckey = constructKeyFromCookie(serializedCookie);
        let putRequest = historyDB.transaction("cookies", "readwrite").objectStore("cookies").put(serializedCookie, ckey);
        putRequest.onerror = function(event) {
            console.error(`Failed to insert cookie (${ckey}) into IndexedDB storage: ${event.target.errorCode}`);
        }
    } else {
        console.error("Could not insert cookie because database connection is closed!");
    }
}

/**
 * Retrieve serialized cookie from IndexedDB storage via a transaction.
 * @param {Object} cookieDat Raw cookie object that provides name, domain and path.
 * @returns {Promise<Object>} Either the cookie if found, or undefined if not.
 */
const retrieveCookieFromStorage = function(cookieDat) {
    if (historyDB !== undefined) {
        let ckey = constructKeyFromCookie(cookieDat);

        let request = historyDB.transaction("cookies").objectStore("cookies").get(ckey);
        return new Promise((resolve, reject) => {
            request.onerror = function(event) {
                console.error("Failed to retrieve cookie: " + ckey);
                reject(`Error on retrieving cookie (${ckey}) -- Error code ${event.target.errorCode}`);
            };
            request.onsuccess = function(event) {
                resolve(event.target.result);
            };
        });
    } else {
        console.error("Could not retrieve cookie because database connection is closed!");
        return new Promise((resolve, reject) => { reject("Database connection closed."); });
    }
}

/**
 * Retrieve the number of cookies in the current history, by label.
 * @returns {Promise<Object>} The array of label counts.
 */
const getCurrentLabelCount = function() {
    if (historyDB !== undefined) {
        let objectStore = historyDB.transaction("cookies").objectStore("cookies");
        let cursor = objectStore.index("label").openCursor();
        return new Promise((resolve, reject) => {
            let statsCount = [0, 0, 0, 0, 0];
            cursor.onsuccess = function(event) {
                var cursor = event.target.result;
                if (cursor) {
                  statsCount[cursor.value.current_label] += 1
                  cursor.continue();
                } else {
                    resolve(statsCount);
                }
            };
            cursor.onerror = (event) => { reject(event.target.errorCode) }
        });
    } else {
        console.error("Could not insert cookie because database connection is closed!");
        return new Promise((resolve, reject) => { reject("Database connection closed."); });
    }
}


/**
 * Callback function to set up config and storage defaults.
 * This initializes all chrome local and sync storage objects if undefined.
 * @param {Object} resp  Default configuration
 */
 const initDefaults = async function(dfConfig, override) {
    await setStorageValue([...dfConfig["cblk_userpolicy"]], chrome.storage.sync, "cblk_userpolicy", override);
    cblk_userpolicy = getStorageValue(chrome.storage.sync, "cblk_userpolicy");

    await setStorageValue(dfConfig["cblk_pscale"], chrome.storage.sync, "cblk_pscale", override);
    cblk_pscale = getStorageValue(chrome.storage.sync, "cblk_pscale");

    await setStorageValue(dfConfig["cblk_pause"], chrome.storage.local, "cblk_pause", override);
    cblk_pause = getStorageValue(chrome.storage.local, "cblk_pause");

    await setStorageValue(dfConfig["cblk_ulimit"], chrome.storage.local, "cblk_ulimit", override);
    cblk_ulimit = getStorageValue(chrome.storage.local, "cblk_ulimit");

    await setStorageValue(dfConfig["cblk_hconsent"], chrome.storage.sync, "cblk_hconsent", override);
    cblk_hconsent = getStorageValue(chrome.storage.sync, "cblk_hconsent");

    await setStorageValue([...dfConfig["cblk_exglobal"]], chrome.storage.sync, "cblk_exglobal", override);
    cblk_exglobal = getStorageValue(chrome.storage.sync, "cblk_exglobal");

    await setStorageValue([...dfConfig["cblk_exfunc"]], chrome.storage.sync, "cblk_exfunc", override);
    cblk_exfunc = getStorageValue(chrome.storage.sync, "cblk_exfunc");

    await setStorageValue([...dfConfig["cblk_exanal"]], chrome.storage.sync, "cblk_exanal", override);
    cblk_exanal = getStorageValue(chrome.storage.sync, "cblk_exanal");

    await setStorageValue([...dfConfig["cblk_exadvert"]], chrome.storage.sync, "cblk_exadvert", override);
    cblk_exadvert = getStorageValue(chrome.storage.sync, "cblk_exadvert");

    await setStorageValue(dfConfig["cblk_mintime"], chrome.storage.sync, "cblk_mintime", override);
    cblk_mintime = getStorageValue(chrome.storage.sync, "cblk_mintime");
}


/**
 * Reset the default values no matter what is currently stored.
 * @param {Object} resp  Default configuration
 */
 const overrideDefaults = function() {
    getExtensionFile(chrome.extension.getURL("ext_data/default_config.json"), "json", (dfConfig) => {
        initDefaults(dfConfig, true);
    });
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
      "current_label": -1,
      "label_ts": 0,
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
      ]
    };
}

/**
 * Updates the existing feature extraction object with data from the new cookie.
 * Specifically, the variable data attribute will have the new cookie's data appended to it.
 * If the update limit is reached, the oldest update will be removed.
 * @param  {Object} storedFEInput   Feature Extraction input, previously constructed.
 * @param  {Object} rawCookie       New cookie data, untransformed.
 * @return {Promise<object>}        The existing cookie object, updated with new data.
 */
const updateFEInput = async function(storedFEInput, rawCookie) {

    let updateArray = storedFEInput["variable_data"];
    let updateLimit = cblk_ulimit;

    let updateStruct = {
        "host_only": rawCookie.hostOnly,
        "http_only": rawCookie.httpOnly,
        "secure": rawCookie.secure,
        "session": rawCookie.session,
        "expiry": datetimeToExpiry(rawCookie),
        "value": escapeString(rawCookie.value),
        "same_site": escapeString(rawCookie.sameSite),
        "timestamp": Date.now()
    };

    // remove head if limit reached
    if (updateArray.length === updateLimit)
        updateArray.shift();

    updateArray.push(updateStruct);
    console.assert(updateArray.length <= updateLimit, "Error: cookie update limit still exceeded!");

    return storedFEInput;
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
    try {
        let storedDat = await retrieveCookieFromStorage(cookieDat);
        if (storedDat) {
            serializedCookie = await updateFEInput(storedDat, cookieDat);
        } else {
            serializedCookie = createFEInput(cookieDat);
        }
    } catch (err) {
        console.error("Retrieving or updating FE Input failed unexpectedly. Proceeding with raw cookie data instead. Error : " + err.msg);
        serializedCookie = createFEInput(cookieDat);
    }

    return serializedCookie;
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
 * Using the cookie input, extract features from the cookie and classify it, retrieving a label.
 * @param  {Object} feature_input   Transformed cookie data input, for the feature extraction.
 * @return {Promise<Number>}        Cookie category label as an integer, ranging from [0,3].
 */
const classifyCookie = async function(cookieDat, feature_input) {
    let label = cookieLookup(cookieDat);
    if (label === -1) {
        let startTime = window.performance.now();

        let features = extractFeatures(feature_input);
        recordDebugTimings(window.performance.now() - startTime, 0);

        label = await predictClass(features, cblk_pscale);
        recordDebugTimings(window.performance.now() - startTime, 1);
    } else {
        debug_Nskipped++;
    }


    if (label < 0 && label > 3) {
        throw new Error(`Predicted label exceeded valid range: ${label}`);
    }

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
    try {
        switch(label) {
            case 1: // functionality
                skipRejection = cblk_exfunc.includes(ckDomain);
                break;
            case 2: // analytics
                skipRejection = cblk_exanal.includes(ckDomain);
                break;
            case 3: // advertising
                skipRejection = cblk_exadvert.includes(ckDomain);
                break;
        }
    } catch (err){
        console.error(`Failed to retrieve exception storage value. Error: ${err.msg}`);
        console.error("Continuing without exceptions.")
    }

    if (skipRejection) {
        console.debug(`Cookie found on whitelist for category '${cName}': '${cookieDat.name}';'${cookieDat.domain}';'${cookieDat.path}'`);
    } else if (!cblk_userpolicy[label]) {
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
                        debug_httpRemovalCounter += 1;
                    }
                });
            } else {
                //console.debug("Cookie (%s;%s;%s) with label (%s) has been removed successfully over HTTPS protocol.", cookieDat.name, cookieDat.domain, cookieDat.path, cName);
                debug_httpsRemovalCounter += 1;
            }
        });
    }
};


/**
 * Enforce the consent policy.
 * @param {Object} cookieDat Original untransformed cookie object.
 * @param {Object} serializedCookie Transformed cookie object, with potential updates.
 */
const enforcePolicy = async function (cookieDat, serializedCookie, storeUpdate) {
    let ckey = cookieDat.name + ";" + cookieDat.domain + ";" + cookieDat.path;

    let ckDomain = sanitizeDomain(serializedCookie.domain);
    if (cblk_exglobal.includes(ckDomain)) {
        console.debug(`Cookie found in domain whitelist: (${ckey})`);
    } else {
        let elapsed = Date.now() - serializedCookie["label_ts"];

        let clabel = -1;
        if (serializedCookie["current_label"] === -1 || elapsed > cblk_mintime) {
            clabel = await classifyCookie(cookieDat, serializedCookie);
            serializedCookie["current_label"] = clabel;
            serializedCookie["label_ts"] = Date.now();
            console.debug("Perform Prediction: Cookie (%s;%s;%s) receives label (%s)", cookieDat.name, cookieDat.domain, cookieDat.path, classIndexToString(clabel));
        } else {
            debug_Nskipped++;
            clabel = serializedCookie["current_label"];
            console.debug("Skip Prediction: Cookie (%s;%s;%s) with label (%s)", cookieDat.name, cookieDat.domain, cookieDat.path, classIndexToString(clabel));
        }

        if (cblk_pause) {
            console.debug(`Pause Mode Removal Skip: Cookie Identifier: ${ckey} -- Assigned Label: ${classIndexToString(clabel)}`);
        } else {
            makePolicyDecision(cookieDat, clabel);
        }
    }

    if (storeUpdate) {
        insertCookieIntoStorage(serializedCookie);
    }
}

/**
 * Enforces the cookie consent policy without using or updating a local cookie storage.
 * @param {Object} cookieDat Object that contains the data for the current cookie.
 */
 const enforcePolicyWithoutHistory = function (cookieDat) {
    let serializedCookie = createFEInput(cookieDat);
    enforcePolicy(cookieDat, serializedCookie, false);
}


/**
 * Enforce the cookie consent policy, utilizing and updating the local cookie history.
 * @param {Object} cookieDat Object that contains the data for the current cookie update.
 * @param {Boolean} storeUpdate If true, will store the update to the cookie.
 */
 const enforcePolicyWithHistory = async function (cookieDat, storeUpdate){
    try {
        let serializedCookie = await serializeOrUpdate(cookieDat);
        enforcePolicy(cookieDat, serializedCookie, storeUpdate);
    } catch (err) {
        console.error("Policy enforcement with history failed. Skipping enforcement. Error: " + err.msg);
    }
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
    try {
        if (cblk_hconsent) {
            enforcePolicyWithHistory(changeInfo.cookie, true);
        } else {
            enforcePolicyWithoutHistory(changeInfo.cookie);
        }
    } catch (err) {
        console.error("Failed to run classification due to an unexpected error: " + err.msg)
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
 * Construct a JSON document out of the contents of IndexedDB.
 * Can be complete history, or restricted to a single label.
 * @param {String} type One of (full|necessary|functional|analytics|advertising). Restricts the output to the given label.
 * @returns {Promise<object>} Promise that will yield an object representing the cookie structure.
 */
const constructHistoryJSON = function(type) {
    console.assert(historyDB !== undefined, "Cookie database link was undefined!");

    let target_label;
    switch (type) {
        case "full": target_label = null; break;
        case "necessary": target_label = 0; break;
        case "functional": target_label = 1; break;
        case "analytics": target_label = 2; break;
        case "advertising": target_label = 3; break;
        default:
            throw new Error("Incorrect label type");
    }

    let tempCookieJSON = {};
    let objectStore = historyDB.transaction("cookies").objectStore("cookies");
    let cursor = objectStore.index("domain").openCursor();
    return new Promise((resolve, reject) => {
        cursor.onsuccess = function(event) {
            var cursor = event.target.result;
            if (cursor) {
                if (target_label === null || cursor.value.current_label === target_label) {
                    let d = cursor.value.domain;
                    let p = cursor.value.path;
                    tempCookieJSON[d] = tempCookieJSON[d] || {};
                    tempCookieJSON[d][p] = tempCookieJSON[d][p] || {};
                    tempCookieJSON[d][p][cursor.value.name] = cursor.value;
                }
                cursor.continue();
            } else {
                resolve(tempCookieJSON);
            }
        };
        cursor.onerror = (event) => { reject(`Error Code: ${event.target.errorCode}`); }
    });
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
        chrome.cookies.getAll({}, (allCookies) => {
            if (chrome.runtime.lastError) {
                console.error("Encountered an error when trying to retrieve all cookies: " + chrome.runtime.lastError);
            } else {
                for (let cookieDat of allCookies) {
                    if (cblk_hconsent) {
                        enforcePolicyWithHistory(cookieDat, false);
                    } else {
                        enforcePolicyWithoutHistory(cookieDat);
                    }
                }
                sendResponse({response: "All cookies classified and policy enforced."});
            }
        });
        return true;
    } else if (request.get_stats) {
        let sendStatsResponse = async () => {
            try {
                let statsCount = await getCurrentLabelCount();
                sendResponse({response: statsCount});
            } catch (err) {
                console.error("Failed to retrieve label count. Error : " + err.msg)
                sendResponse({response: null});
            }
        };
        sendStatsResponse();
        return true;
    } else if (request.reset_storage) {
        historyDB.transaction("cookies", "readwrite").objectStore("cookies").clear();
        sendResponse({response: "Cookie history cleared."});
    } else if (request.open_json) {
        let sendJSONResponse = async () => {
            try {
                let cookieJSON = await constructHistoryJSON(request.open_json);
                sendResponse({response: cookieJSON});
            } catch (err) {
                console.error("Failed to retrieve JSON. Error : " + err.msg)
                sendResponse({response: null});
            }
        }
        sendJSONResponse();
        return true;
    } else if (request.reset_defaults) {
        overrideDefaults();
        sendResponse({response: "Defaults overridden by BG."});
    } else {
        sendResponse({response: undefined});
    }
}


/**
 * Whenever storage.local or storage.sync updates, update the local
 * variables that track these as well.
 * @param {Object} changes Stores the objects that were altered.
 * @param {Object} area Storage area that was changed
 */
 const updateStorageVars = function(changes, area) {
    let changedItems = Object.keys(changes);
    if (area === "sync") {
        if (changedItems.includes("cblk_userpolicy")) {
            cblk_userpolicy = changes["cblk_userpolicy"].newValue;
        }
        if (changedItems.includes("cblk_pscale")) {
            cblk_pscale = changes["cblk_pscale"].newValue;
        }
        if (changedItems.includes("cblk_hconsent")) {
            cblk_hconsent = changes["cblk_hconsent"].newValue;
        }
        if (changedItems.includes("cblk_exglobal")) {
            cblk_exglobal = changes["cblk_exglobal"].newValue;
        }
        if (changedItems.includes("cblk_exfunc")) {
            cblk_exfunc = changes["cblk_exfunc"].newValue;
        }
        if (changedItems.includes("cblk_exanal")) {
            cblk_exanal = changes["cblk_exanal"].newValue;
        }
        if (changedItems.includes("cblk_exadvert")) {
            cblk_exadvert = changes["cblk_exadvert"].newValue;
        }
        if (changedItems.includes("cblk_mintime")) {
            cblk_mintime = changes["cblk_mintime"].newValue;
        }
    } else if (area === "local") {
        if (changedItems.includes("cblk_pause")) {
            cblk_pause = changes["cblk_pause"].newValue;
        }
        if (changedItems.includes("cblk_ulimit")) {
            cblk_ulimit = changes["cblk_ulimit"].newValue;
        }
    }
}

chrome.storage.onChanged.addListener(updateStorageVars);


// set up defaults and listeners
getExtensionFile(chrome.extension.getURL("ext_data/default_config.json"), "json", (dConfig) => {initDefaults(dConfig, false)});
getExtensionFile(chrome.extension.getURL("ext_data/known_cookies.json"), "json", (result) => {
    for (let k of Object.keys(result["regex_match"])) {
        result["regex_match"][k][regexKey] = new RegExp(k);
    }
    known_cookies = result;
});
chrome.cookies.onChanged.addListener(cookieChangeListener);
chrome.runtime.onInstalled.addListener(firstTimeSetup);
chrome.runtime.onMessage.addListener(handleInternalMessage);
