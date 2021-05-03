//-------------------------------------------------------------------------------
/*
Copyright (C) 2021 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------

// local counters for debugging
var httpRemovalCounter = 0;
var httpsRemovalCounter = 0;

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
 const initDefaults = function(dfConfig) {
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
    let updateLimit;
    try {
        updateLimit = await getStorageValue(chrome.storage.local, "cblk_ulimit");
    } catch (err) {
        throw new Error("Failed to retrieve the update limit from local storage. Error : " + err.msg)
    }

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
 * Using the cookie input, extract features from the cookie and classify it, retrieving a label.
 * @param  {Object} feature_input   Transformed cookie data input, for the feature extraction.
 * @return {Promise<Number>}        Cookie category label as an integer, ranging from [0,3].
 */
const classifyCookie = async function(feature_input) {
    let features = extractFeatures(feature_input);
    let label;
    try {
        let pscale = await getStorageValue(chrome.storage.sync, "cblk_pscale");
        label = await predictClass(features, pscale);
        if (label < 0 && label > 3) {
            throw new Error(`Predicted label exceeded valid range: ${label}`);
        }
    } catch (err) {
        console.error("Label prediction failed: " + err.msg);
        throw err;
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
                skipRejection = (await getStorageValue(chrome.storage.sync, "cblk_exfunc")).includes(ckDomain);
                break;
            case 2: // analytics
                skipRejection = (await getStorageValue(chrome.storage.sync, "cblk_exanal")).includes(ckDomain);
                break;
            case 3: // advertising
                skipRejection = (await getStorageValue(chrome.storage.sync, "cblk_exadvert")).includes(ckDomain);
                break;
        }
    } catch (err){
        console.error(`Failed to retrieve exception storage value. Error: ${err.msg}`);
        console.error("Continuing without exceptions.")
    }

    if (skipRejection) {
        console.debug(`Cookie found on whitelist for category '${cName}': '${cookieDat.name}';'${cookieDat.domain}';'${cookieDat.path}'`);
    } else {
        let consentArray = undefined;
        try {
            consentArray = await getStorageValue(chrome.storage.sync, "cblk_userpolicy");
        } catch(err) {
            console.error("Failed to retrieve user policy! Error: " + err.msg);
        }

        if (consentArray !== undefined && !consentArray[label]) {
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
    let globalExcepts = {};
    try {
        globalExcepts = await getStorageValue(chrome.storage.sync, "cblk_exglobal");
    } catch (err) {
        console.error("Could not retrieve the domain exceptions: " + err.msg);
    }

    let ckDomain = sanitizeDomain(serializedCookie.domain);
    if (globalExcepts.includes(ckDomain)) {
        console.debug(`Cookie found in domain whitelist: (${ckey})`);
    } else {
        let minTime = 60000;
        try {
            minTime = await getStorageValue(chrome.storage.sync, "cblk_mintime");
        } catch (err) {
            console.error("Could not retrieve the minimum label retention time. Error: " + err.msg)
        }
        let elapsed = Date.now() - serializedCookie["label_ts"];

        let label = -1;
        if (serializedCookie["current_label"] === -1 || elapsed > minTime) {
            // classify the cookie
            try {
                label = cookieLookup(cookieDat);
                if (label === -1) {
                    label = await classifyCookie(serializedCookie);
                }

                serializedCookie["current_label"] = label;
                serializedCookie["label_ts"] = Date.now();
                let cName = classIndexToString(label);
                console.debug("Perform Prediction: Cookie (%s;%s;%s) receives label (%s)", cookieDat.name, cookieDat.domain, cookieDat.path, cName)
            } catch (err) {
                throw new Error("Could not predict the label. Error: " + err.msg)
            }
        } else {
            label = serializedCookie["current_label"];
            let cName = classIndexToString(label);
            console.debug("Skip Prediction: Cookie (%s;%s;%s) with label (%s)", cookieDat.name, cookieDat.domain, cookieDat.path, cName)
        }

        // retrieve pause state
        let dstate = false;
        try {
            dstate = await getStorageValue(chrome.storage.local, "cblk_pause")
        } catch (err) {
            console.error("Could not retrieve pause state. Continuing with policy enforcement without pause. Error: " + err.msg)
        }

        // make the decision
        if (dstate) {
            let cName = classIndexToString(label);
            console.debug(`Pause Mode Removal Skip: Cookie Identifier: ${ckey} -- Assigned Label: ${cName}`);
        } else {
            makePolicyDecision(cookieDat, label);
        }
    }

    if (storeUpdate) {
        // check if consent is given for history storing
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
        let history_consent = await getStorageValue(chrome.storage.sync, "cblk_hconsent");
        if (history_consent) {
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
        getStorageValue(chrome.storage.sync, "cblk_hconsent").then((history_consent) => {
            chrome.cookies.getAll({}, (allCookies) => {
                for (let cookieDat of allCookies) {
                    if (history_consent) {
                        enforcePolicyWithHistory(cookieDat, false);
                    } else {
                        enforcePolicyWithoutHistory(cookieDat);
                    }
                }
                sendResponse({response: "All cookies classified and policy enforced."});
            });
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
        sendResponse({response: "Local cookie and stats storage cleared."});
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
    }
    else {
        sendResponse({response: undefined});
    }
}


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
