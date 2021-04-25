// Author: Dino Bollinger
// License: MIT

const regexKey = "~regex;";

var httpRemovalCounter = 0;
var httpsRemovalCounter = 0;

var localCookieStorage = undefined;
var localStatsCounter = undefined;

var known_cookies = {};


/**
 * Set cookie storage to the specified object value.
 * @param {Object} newStorage
 */
 const setCookieStorage = async function(newStorage) {
    localCookieStorage = newStorage;
    await browser.storage.local.set({ "cblk_storage": newStorage });
}

/**
 * Set the statistics array.
 * @param {Array} newStats New stats array
 */
 const setStatsCounter = async function(newStats) {
    localStatsCounter = newStats;
    await browser.storage.local.set({"cblk_counter": newStats });
}


/**
 * Asynchronous callback function to set up config and storage defaults.
 * This initializes all browser local and sync storage objects if undefined.
 * @param {Object} resp  Default configuration
 */
 const initDefaults = async function(defaultConfig) {

    let defaultCheckIfSet = async function(syncOrLocal, key, setValFunc) {
        let value = (await syncOrLocal.get(key))[key];
        if (value === undefined) {
          setValFunc(defaultConfig[key]);
        }
    };

    let excDefFunc = async function (sKey, confKey) {
        let exceptionsList = (await browser.storage.sync.get(sKey))[sKey];
        if (exceptionsList === undefined) {
            await setExceptionsListStore(sKey, defaultConfig[confKey]);
        }
    };

    defaultCheckIfSet(browser.storage.sync, "default_policy", setUserPolicy);
    defaultCheckIfSet(browser.storage.sync, "update_limit", setUpdateLimit);
    defaultCheckIfSet(browser.storage.sync, "perm_scale", setPermScale);
    defaultCheckIfSet(browser.storage.local, "pause_state", setPauseState);
    excDefFunc("cblk_exglobal", "website_exceptions");
    excDefFunc("cblk_exfunc", "functionality_exceptions");
    excDefFunc("cblk_exanal", "analytics_exceptions");
    excDefFunc("cblk_exadvert", "advertising_exceptions");

    // Need to be separate
    localCookieStorage = (await browser.storage.local.get("cblk_storage"))["cblk_storage"];
    if (localCookieStorage === undefined) {
        localCookieStorage = {};
        setCookieStorage(localCookieStorage);
    }

    // Need to be separate
    localStatsCounter = (await browser.storage.local.get("cblk_counter"))["cblk_counter"];
    if (localStatsCounter === undefined) {
        localStatsCounter = [0,0,0,0,0];
        setStatsCounter(localStatsCounter);
    }

  }


/**
 * Clear the local storage.
 */
  const clearLocalStorage = function() {
    setCookieStorage({});
    setStatsCounter([0, 0, 0, 0, 0]);
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
      "first_party_domain": escapeString(cookie.firstPartyDomain),
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
        }
      ]
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
    let updateLimit = await getUpdateLimit();

    let updateStruct = {
        "host_only": newCookie.hostOnly,
        "http_only": newCookie.httpOnly,
        "secure": newCookie.secure,
        "session": newCookie.session,
        "expiry": datetimeToExpiry(newCookie),
        "value": escapeString(newCookie.value),
        "same_site": escapeString(newCookie.sameSite)
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
* @param  {String} ckey          String key that identifies the cookie.
* @param  {Object} cookieDat     Cookie data object as received from the browser.
* @param  {Object} cookieStore   Object in which all cookies are indexed.
* @return {Promise<object>}      The new feature extraction input.
*/
const retrieveUpdatedCookie = async function(ckey, cookieDat, cookieStore) {
    let transformedCookie;
    if (ckey in cookieStore) {
        transformedCookie = await updateFEInput(cookieStore[ckey], cookieDat);
    } else {
        transformedCookie = createFEInput(cookieDat);
    }
    return transformedCookie;
};


/**
 * Using the cookie input, extract features from the cookie and classify it, retrieving a label.
 * @param  {Object} feature_input   Transformed cookie data input, for the feature extraction.
 * @return {Promise<Number>}        Cookie category label as an integer, ranging from [0,3].
 */
const classifyCookie = async function(feature_input) {
    let features = extractFeatures(feature_input);
    let label = await predictClass(features, await getPermScale());
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
            skipRejection = (await getExceptionsList("cblk_exfunc")).includes(ckDomain);
            break;
        case 2: // analytics
            skipRejection = (await getExceptionsList("cblk_exanal")).includes(ckDomain);
            break;
        case 3: // advertising
            skipRejection = (await getExceptionsList("cblk_exadvert")).includes(ckDomain);
            break;
    }

    if (skipRejection) {
        //console.debug(`Cookie found on whitelist for category '${cName}': '${cookieDat.name}';'${cookieDat.domain}';'${cookieDat.path}'`);
    } else {
        let consentArray = await getUserPolicy();
        console.assert(consentArray !== undefined, "User policy was somehow undefined!")
        if (consentArray[label]) {
            // spare the cookie
            console.debug("Affirmative consent for cookie (%s;%s;%s) with label (%s).", cookieDat.name, cookieDat.domain, cookieDat.path, cName);
        } else {
            console.debug("Negative consent for cookie (%s;%s;%s) with label (%s).", cookieDat.name, cookieDat.domain, cookieDat.path, cName);

            // First try to remove the cookie, using https as the protocol
            let remResult = await browser.cookies.remove({
                "name": cookieDat.name,
                "url": "https://" + cookieDat.domain + cookieDat.path,
                "firstPartyDomain": cookieDat.firstPartyDomain,
                "storeId": cookieDat.storeId
            });

            // check if removal was successful -- if not, retry with http protocol
            if (remResult === null){
                remResult = await browser.cookies.remove({
                    "name": cookieDat.name,
                    "url": "http://" + cookieDat.domain + cookieDat.path,
                    "firstPartyDomain": cookieDat.firstPartyDomain,
                    "storeId": cookieDat.storeId
                });

                if (remResult === null){
                    // If failed again, report error.
                    console.error("Could not remove cookie (%s;%s;%s) with label (%s).", cookieDat.name, cookieDat.domain, cookieDat.path, cName);
                } else {
                    console.debug("Cookie (%s;%s;%s) with label (%s) has been removed successfully over HTTP protocol.", cookieDat.name, cookieDat.domain, cookieDat.path, cName);
                    httpRemovalCounter += 1;
                }
            } else {
                console.debug("Cookie (%s;%s;%s) with label (%s) has been removed successfully over HTTPS protocol.", cookieDat.name, cookieDat.domain, cookieDat.path, cName);
                httpsRemovalCounter += 1;
            }
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
 * Async helper to reduce code duplication
 */
const classifyWithExceptions = async function (globalExcepts, ckey, cookieDat, serializedCookie) {
    let ckDomain = sanitizeDomain(serializedCookie.domain);
    if (globalExcepts.includes(ckDomain)) {
        console.debug(`Cookie found in domain whitelist: (${ckey})`);
        localStatsCounter[4] += 1;

    } else {
        // classify the cookie
        let label = cookieLookup(cookieDat);
        if (label === -1) {
            label = await classifyCookie(serializedCookie);
        }

        localStatsCounter[label] += 1;

        // make a decision
        let dstate = await getPauseState();
        if (dstate) {
            let cName = classIndexToString(label);
            console.debug(`Pause Mode Removal Skip: Cookie Identifier: ${ckey} -- Assigned Label: ${cName}`);
        } else {
            makePolicyDecision(cookieDat, label);
        }
    }
}

/**
 * Enforce the user policy by classifying the cookie and deleting it if it belongs to a rejected category.
 * @param {String} ckey String that identifies the cookie uniquely.
 * @param {Object} cookieDat Object that contains the data for the current cookie update.
 */
const enforcePolicyWithUpdates = async function (ckey, cookieDat){
    // Update the current cookie storage
    let serializedCookie = await retrieveUpdatedCookie(ckey, cookieDat, localCookieStorage);
    localCookieStorage[ckey] = serializedCookie;

    let globalExcepts = await getExceptionsList("cblk_exglobal");
    classifyWithExceptions(globalExcepts, ckey, cookieDat, serializedCookie);
}


/**
* Listener that is executed any time a cookie is added, updated or removed.
* Classifies the cookie and rejects it based on user policy.
* @param {Object} changeInfo  Contains the cookie itself, and cause info.
*/
const cookieChangeListener = function(changeInfo) {
    // do nothing in this case
    if (changeInfo.removed) {
        return;
    }

    // construct the key for keeping track of cookie updates
    let cookieDat = changeInfo.cookie;
    let ckey = cookieDat.name + ";" + cookieDat.domain + ";" + cookieDat.path;
    enforcePolicyWithUpdates(ckey, cookieDat);
};


/**
 * Synchronous variant of policy enforcement used for the "classify current cookies" button.
 * Does not append cookie updates if the cookie already is recorded.
 * @param {String} ckey String that identifies the cookie uniquely.
 * @param {Object} cookieDat Object that contains the data for the current cookie.
 */
const enforcePolicyWithoutUpdates = function (ckey, cookieDat){

    let serializedCookie;
    if (ckey in localCookieStorage) {
        serializedCookie = localCookieStorage[ckey];
    } else {
        serializedCookie = createFEInput(cookieDat);
        localCookieStorage[ckey] = serializedCookie;
    }

    getExceptionsList("cblk_exglobal").then((ge) => {
        classifyWithExceptions(ge, ckey, cookieDat, serializedCookie);
    });
}


/**
 * Listener function that opens the first time setup when the extension is installed.
 * @param {Object} details Contains the reason for the change.
 */
const firstTimeSetup = function(details) {
  if (details.reason === "install") {
    browser.tabs.create({"active": true, "url": "/options/cookieblock_setup.html"});
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
        browser.cookies.getAll({}).then( (allCookies) => {
            for (let cookieDat of allCookies) {
                let ckey = cookieDat.name + ";" + cookieDat.domain + ";" + cookieDat.path;
                enforcePolicyWithoutUpdates(ckey, cookieDat);
            }
            setCookieStorage(localCookieStorage);
            setStatsCounter(localStatsCounter);
            sendResponse({response: "All cookies classified and policy enforced."});
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
  await setCookieStorage(localCookieStorage);
  await setStatsCounter(localStatsCounter);
  console.debug("Saved current cookie store and stats counter.");
}, 60_000);

// set up defaults and listeners
getLocalData(browser.extension.getURL("ext_data/default_config.json"), "json", initDefaults);
getLocalData(browser.extension.getURL("ext_data/known_cookies.json"), "json", (result) => {
    for (let k of Object.keys(result["regex_match"])) {
        result["regex_match"][k][regexKey] = new RegExp(k);
    }
    known_cookies = result;
});
browser.cookies.onChanged.addListener(cookieChangeListener);
browser.runtime.onInstalled.addListener(firstTimeSetup);
browser.runtime.onMessage.addListener(handleInternalMessage);
