// Author: Dino Bollinger
// License: MIT

var httpRemovalCounter = 0;
var httpsRemovalCounter = 0;

/**
* Creates a new feature extraction input object from the raw cookie data.
* @param  {Object} cookie    Raw cookie data as received from the browser.
* @return {Promise<object>}  Feature Extraction input object.
*/
const createFEInput = async function(cookie) {
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
        updateArray.shift()

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
        transformedCookie = await createFEInput(cookieDat);
    }
    return transformedCookie;
};


/**
 * Using the cookie input, extract features from the cookie and classify it, retrieving a label.
 * @param  {Object} feature_input   Transformed cookie data input, for the feature extraction.
 * @return {Number}                 Cookie category label as an integer, ranging from [0,3].
 */
const classifyCookie = function(feature_input) {
    let features = extractFeatures(feature_input);
    let label = predictClass(features);
    console.assert(label >= 0 && label < 4, "Predicted label exceeded valid range: %d", label)
    return label
};


/**
 * Decides whether to keep the cookie or delete it, based on user policy.
 * @param  {Object} cookieDat   Raw cookie data as retrieved from the browser, with "storeId".
 * @param  {Number} label       Label predicted by the classifier.
 */
const makePolicyDecision = async function(cookieDat, label) {

    let cName = classIndexToString(label);

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


    let ckDomain = sanitizeDomain(escapeString(cookieDat.domain));
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

    let cblk_store = await getCookieStorage();
    let serializedCookie = await retrieveUpdatedCookie(ckey, cookieDat, cblk_store);

    cblk_store[ckey] = serializedCookie;
    browser.storage.local.set({"cblk_storage": cblk_store});

    let ckDomain = sanitizeDomain(serializedCookie.domain);

    let updateCounters = async (idx) => {
        let stats = await getStatsCounter();
        stats[idx] += 1;
        browser.storage.local.set({"cblk_counter": stats});
    };

    let globalExcepts = await getExceptionsList("cblk_exglobal");
    if (globalExcepts.includes(ckDomain)) {
        console.debug(`Cookie found in domain whitelist: (${ckey})`);
        updateCounters(4);
    } else {
        // classify the cookie
        let label = classifyCookie(serializedCookie);
        updateCounters(label);

        // make a decision
        let dstate = await getDebugState();
        if (dstate) {
            console.debug(`Debug Mode Removal Skip: Cookie Identifier: ${ckey} -- Assigned Label: ${label}`);
        } else {
            makePolicyDecision(cookieDat, label);
        }
    }
}