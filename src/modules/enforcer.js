// Author: Dino Bollinger
// License: MIT

// Maximum number of cookie updates to store in the extension. If exceeded, will evict the oldest update.
var updateLimit;
getLocalData(browser.extension.getURL("ext_data/config.json"), "json", (r) => {
    updateLimit = r["update_limit"];
});

/**
 * Generic error handler function.
 * @param {String} error
 */
const onError = (error) => {
    console.error(`An error occurred: ${error}`);
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
* Creates a new feature extraction input object from the raw cookie data.
* @param  {Object} cookie  Raw cookie data as received from the browser.
* @return {Object}  Feature Extraction input object.
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
 * @return {Object}              The existing cookie object, updated with new data.
 */
const updateFEInput = function(prevCookie, newCookie) {

    let updateArray = prevCookie["variable_data"];

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
* @return {Object}               The new feature extraction input
*/
const updateCookieStore = function(ckey, cookieDat, cookieStore) {
    let transformedCookie;
    if (ckey in cookieStore) {
        transformedCookie = updateFEInput(cookieStore[ckey], cookieDat);
    }
    else {
        transformedCookie = createFEInput(cookieDat);
    }
    cookieStore[ckey] = transformedCookie
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
const makePolicyDecision = function(cookieDat, label) {

    let onRemoval = () => {

        console.debug("Cookie (%s,%s,%s) classified as class %d has been removed.", cookieDat.name, cookieDat.domain, cookieDat.path, label);
    };

    let onKeep = () => {
        console.debug("Cookie (%s,%s,%s) classified as class %d has been spared.", cookieDat.name, cookieDat.domain, cookieDat.path, label);
    };

    browser.storage.sync.get(exceptionKeys).then((r) => {

        let skipRejection = false;
        let ckDomain = sanitizeDomain(escapeString(cookieDat.domain));
        switch(label){
            case 1:
            skipRejection = r["cblk_exfunc"].includes(ckDomain);
            break;
            case 2:
            skipRejection = r["cblk_exanal"].includes(ckDomain);
            break;
            case 3:
            skipRejection = r["cblk_exadvert"].includes(ckDomain);
            break;
        }

        if (!skipRejection) {
            let policy = browser.storage.sync.get("cblk_userpolicy");
            policy.then((r) => {
            console.assert(r.cblk_userpolicy !== undefined, "User Policy is undefined!")

            if (r.cblk_userpolicy[label]) {
                // First try to remove the cookie, using https as the protocol
                var https_removed = browser.cookies.remove({
                "name": cookieDat.name,
                "url": "https://" + cookieDat.domain + cookieDat.path,
                "firstPartyDomain": cookieDat.firstPartyDomain,
                "storeId": cookieDat.storeId
                });

                // check if removal was successful -- if not, retry with http protocol
                https_removed.then((rem) => {
                if (rem === null){

                    var http_removed = browser.cookies.remove({
                    "name": cookieDat.name,
                    "url": "http://" + cookieDat.domain + cookieDat.path,
                    "firstPartyDomain": cookieDat.firstPartyDomain,
                    "storeId": cookieDat.storeId
                    });

                    http_removed.then((rem2) => {
                    if (rem2 === null){
                        // If failed again, something strange is going on.
                        console.error(`Failure to remove cookie: (${cookieDat.name},${cookieDat.domain})`)
                    }
                    else onRemoval();
                    }, onError);
                }
                else onRemoval();
                }, onError);
            }
            else onKeep();

            }, onError);
        } else {
            console.debug(`Spared cookie ${cookieDat.name};${cookieDat.domain} with label ${label} as it is whitelisted for this category.`);
        }
    }, onError);
};


const enforcePolicy = function (ckey, cookieDat){

    browser.storage.local.get("cblk_storage").then((r) => {

        // update the extension cookie storage
        let serializedCookie = updateCookieStore(ckey, cookieDat, r["cblk_storage"]);
        //console.debug("Stored Data: " + JSON.stringify(serializedCookie));

        // update the cookie storage
        browser.storage.local.set({
        "cblk_storage": r["cblk_storage"]
        });

        let ckDomain = sanitizeDomain(serializedCookie.domain);

        browser.storage.sync.get("cblk_exglobal").then((r) => {
        if (!r["cblk_exglobal"].includes(ckDomain)) {
            // classify the cookie
            let label = classifyCookie(serializedCookie);

            // Update counters
            browser.storage.local.get("cblk_counter").then((r) => {
                r["cblk_counter"][label] += 1;
                browser.storage.local.set({"cblk_counter": r["cblk_counter"]})
            }, onError);

            browser.storage.local.get("cblk_debug").then((r) => {
            if (r["cblk_debug"])
                console.debug(`Cookie Identifier: ${ckey} -- Assigned Label: ${label} -- Removal Skipped!`)
            else{
                // decide on the cookie
                makePolicyDecision(cookieDat, label);
            }
            },(error) => {
            console.error(`An error occurred: ${error}`);
            });
        } else {
            browser.storage.local.get("cblk_counter").then((r) => {
                r["cblk_counter"][4] += 1;
                browser.storage.local.set({"cblk_counter": r["cblk_counter"]})
            }, onError);
            console.debug(`Did not classify cookie ${ckey} because its domain is contained in the global whitelist.`)
        }
        });
    });
}