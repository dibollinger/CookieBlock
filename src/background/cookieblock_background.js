// Author: Dino Bollinger
// License: MIT

var httpRemovalCounter = 0;
var httpsRemovalCounter = 0;

var localCookieStorage = undefined;
var localStatsCounter = undefined;


/**
 * Set cookie storage to the specified object value.
 * @param {Object} newStorage
 */
 const setCookieStorage = async function(newStorage) {
    await browser.storage.local.set({ "cblk_storage": newStorage });
}

/**
 * Set the statistics array.
 * @param {Array} newStats New stats array
 */
 const setStatsCounter = async function(newStats) {
    await browser.storage.local.set({"cblk_counter": newStats });
}


/**
 * Asynchronous callback function to set up config and storage defaults.
 * This initializes all browser local and sync storage objects if undefined.
 * @param {Object} resp  Default configuration
 */
const setupDefaults = async function(defaultConfig) {

  let dp = defaultConfig["default_policy"];

  let policy = (await browser.storage.sync.get("cblk_userpolicy"))["cblk_userpolicy"];
  if (policy === undefined) {
    policy = [dp["acc_nec"], dp["acc_func"], dp["acc_anal"], dp["acc_ads"]];
    setUserPolicy(policy);
  }

  let ulimit = (await browser.storage.sync.get("cblk_ulimit"))["cblk_ulimit"];
  if (ulimit === undefined) {
    ulimit = defaultConfig["update_limit"];
    setUpdateLimit(ulimit);
  }

  let debugState = (await browser.storage.local.get("cblk_debug"))["cblk_debug"];
  if (debugState === undefined) {
    setDebugState(false);
  }

  let excdefFunc = async (sKey) => {
    let exceptionsList = (await browser.storage.sync.get(sKey))[sKey];
    if (exceptionsList === undefined) {
        await setExceptionsListStore(sKey, []);
    }
  };

  excdefFunc("cblk_exglobal");
  excdefFunc("cblk_exfunc");
  excdefFunc("cblk_exanal");
  excdefFunc("cblk_exadvert");

  // Cookie store is local as an object, initialized at launch and periodically saved to extension storage.
  localCookieStorage = (await browser.storage.local.get("cblk_storage"))["cblk_storage"];
  if (localCookieStorage === undefined) {
    localCookieStorage = {};
    setCookieStorage(localCookieStorage);
  }

  localStatsCounter = (await browser.storage.local.get("cblk_counter"))["cblk_counter"];
  if (localStatsCounter === undefined) {
      localStatsCounter = [0,0,0,0,0];
      setStatsCounter(localStatsCounter);
  }

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
    let label = await predictClass(features);
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
        console.debug(`Cookie found on whitelist for category '${cName}': '${cookieDat.name}';'${cookieDat.domain}';'${cookieDat.path}'`);
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
                    console.debug(remResult);
                    httpRemovalCounter += 1;
                }
            } else {
                console.debug("Cookie (%s;%s;%s) with label (%s) has been removed successfully over HTTPS protocol.", cookieDat.name, cookieDat.domain, cookieDat.path, cName);
                console.debug(remResult);
                httpsRemovalCounter += 1;
            }
        }
    }
};

/**
 * Enforce the user policy by classifying the cookie and deleting it if it belongs to a rejected category.
 * @param {String} ckey String that identifies the cookie uniquely.
 * @param {Object} cookieDat Object that contains the data for the current cookie update.
 */
const enforcePolicy = async function (ckey, cookieDat){
    // Update the current cookie storage
    let serializedCookie = await retrieveUpdatedCookie(ckey, cookieDat, localCookieStorage);
    localCookieStorage[ckey] = serializedCookie;

    let ckDomain = sanitizeDomain(serializedCookie.domain);
    let globalExcepts = await getExceptionsList("cblk_exglobal");
    if (globalExcepts.includes(ckDomain)) {
        console.debug(`Cookie found in domain whitelist: (${ckey})`);
        localStatsCounter[4] += 1;
    } else {
        // classify the cookie
        let label = await classifyCookie(serializedCookie);
        localStatsCounter[label] += 1;

        // make a decision
        let dstate = await getDebugState();
        if (dstate) {
            console.debug(`Debug Mode Removal Skip: Cookie Identifier: ${ckey} -- Assigned Label: ${label}`);
        } else {
            makePolicyDecision(cookieDat, label);
        }
    }
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
    enforcePolicy(ckey, cookieDat);
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

    getExceptionsList("cblk_exglobal").then(async (globalExcepts) => {
        let ckDomain = sanitizeDomain(serializedCookie.domain);
        if (globalExcepts.includes(ckDomain)) {
            console.debug(`Cookie found in domain whitelist: (${ckey})`);
            localStatsCounter[4] += 1;
        } else {
            // classify the cookie
            let label = await classifyCookie(serializedCookie).then(() =>{});
            localStatsCounter[label] += 1;

            // make a decision
            let dstate = await getDebugState();
            if (dstate) {
                console.debug(`Debug Mode Removal Skip: Cookie Identifier: ${ckey} -- Assigned Label: ${label}`);
            } else {
                makePolicyDecision(cookieDat, label);
            }
        }
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
    console.debug(`Received a message from ${sender} : ` + request.classify_all)
    if (request.classify_all) {
        browser.cookies.getAll({}).then( (allCookies) => {
            for (let cookieDat of allCookies) {
                let ckey = cookieDat.name + ";" + cookieDat.domain + ";" + cookieDat.path;
                enforcePolicyWithoutUpdates(ckey, cookieDat);
            }
            sendResponse({response: "All cookies classified and policy enforced."});
        });
        return true;
    } else if (request.get_stats) {
        sendResponse({response: localStatsCounter})
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
getLocalData(browser.extension.getURL("ext_data/default_config.json"), "json", setupDefaults);
browser.cookies.onChanged.addListener(cookieChangeListener);
browser.runtime.onInstalled.addListener(firstTimeSetup);
browser.runtime.onMessage.addListener(handleInternalMessage);
