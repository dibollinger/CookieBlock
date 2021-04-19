// Author: Dino Bollinger
// License: MIT


/**
 * Remove an item from a dynamically generated exception list.
 * @param {String} listItem List item to be removed.
 * @param {String} storageID Extension storage id for exception list.
 * @param {String} removedDomain
 */
 const removeExceptionFromList = async function(removedDomain, listItem, storageID) {
    let exlist = listItem.parentElement;

    // remove the internal stored string (async with promise)
    domainList = await getExceptionsList(storageID);
    let index = domainList.indexOf(removedDomain);
    domainList.splice(index, 1)

    // update storage
    setExceptionsListStore(storageID, domainList);

    // finally, remove the element from the visible list
    exlist.removeChild(listItem);
}


/**
 * Append an item to a dynamically generated exception list.
 * @param {String} exceptionDomain Domain to add an exception for.
 * @param {String} listID HTML List identity
 * @param {String} storageID Extension storage id for exception list.
 */
const appendExceptionToList = async function(exceptionDomain, listID, storageID) {
    let node = document.createElement("li")

    // button has the remove event set up directly
    let button = document.createElement("button");
    button.textContent = "x";
    button.addEventListener("click", () => { removeExceptionFromList(exceptionDomain, node, storageID) });

    let textdiv = document.createElement("div");
    let textnode = document.createTextNode(exceptionDomain);

    textdiv.appendChild(textnode);
    textdiv.class = "text_content";

    node.appendChild(button);
    node.appendChild(textnode);
    document.getElementById(listID).appendChild(node);
}



/**
 * Handle the mouse click event to submit a custom domain exception to the list.
 * @param {String} inputID    Identity of the input box.
 * @param {String} storageID  Storage identity for the exception list.
 * @param {String} listID     Identity of the list to append the exception to.
 */
const handleExceptionSubmit = async function(inputID, storageID, listID) {
    let iElem = document.querySelector(inputID);
    if (iElem.value != null && iElem.value != "")
    {
        let domainOrURL = (' ' + iElem.value).slice(1);
        let sanitizedDomain = undefined;
        try {
            sanitizedDomain = urlToUniformDomain(new URL(domainOrURL).hostname);
        } catch(error) {
            sanitizedDomain = urlToUniformDomain(domainOrURL);
        }

        let domainList = await getExceptionsList(storageID);
        domainList.push(domainOrURL);
        setExceptionsListStore(storageID, domainList);

        appendExceptionToList(sanitizedDomain, listID, storageID);

        // empty the input box
        iElem.value = "";
    }
}


/**
 * Function that contains most of the localization text assignments.
 */
const setupLocalization = function () {
    const setLocText = (id, loc) => {
        document.getElementById(id).textContent = browser.i18n.getMessage(loc);
    };

    // Title
    setLocText("settings_title", "extensionName");
    setLocText("settings_subtitle", "settingsSubtitle");

    // Consent Preference Text
    setLocText("cprefs_legend", "optionsHeaderConsent");
    setLocText("cprefs_desc","consentDescription");
    setLocText("nec_title","catNecessaryTitle");
    setLocText("nec_desc","catNecessaryDesc");
    setLocText("func_title","catFunctionalityTitle");
    setLocText("func_desc","catFunctionalityDesc");
    setLocText("anal_title","catAnalyticsTitle");
    setLocText("anal_desc","catAnalyticsDesc");
    setLocText("advert_title","catAdvertisingTitle");
    setLocText("advert_desc","catAdvertisingDesc");
    setLocText("submit_prefs","buttonUpdatePolicy");
    setLocText("submit_text","buttonSuccessMsg");

    // Additional Options
    setLocText("extra_opts_legend","headerAdditionalOptions");
    setLocText("extra_opts_desc","additionalOptionsDesc");
    setLocText("debug_title", "enableDebugMode");
    setLocText("debug_desc", "debugDescription");
    setLocText("classify_title", "currentCookieEnforceTitle");
    setLocText("classify_desc", "currentCookieEnforceDescription");
    setLocText("classify_button", "currentCookieEnforceButton");
    setLocText("apply_text", "currentCookieEnforceMsg");

    // Website exception text
    setLocText("wheader_title", "globalExceptionsHeader");
    setLocText("wheader_desc", "globalExceptionsDescription");
    document.getElementById("website_excepts_input").placeholder = browser.i18n.getMessage("exceptionPlaceholderText");
    setLocText("website_excepts_submit", "addButton");

    // Functionality exceptions
    setLocText("fheader_title", "functionalExceptionsHeader");
    setLocText("fheader_desc", "functionalExceptionsDescription");
    document.getElementById("func_excepts_input").placeholder = browser.i18n.getMessage("exceptionPlaceholderText");
    setLocText("func_excepts_submit", "addButton");

    // Analytics exceptions
    setLocText("anheader_title", "analyticsExceptionsHeader");
    setLocText("anheader_desc", "analyticsExceptionsDescription");
    document.getElementById("analytics_excepts_input").placeholder = browser.i18n.getMessage("exceptionPlaceholderText");
    setLocText("analytics_excepts_submit", "addButton");

    // Advertising exceptions
    setLocText("adheader_title", "advertExceptionsHeader");
    setLocText("adheader_desc", "advertExceptionsDescription");
    document.getElementById("advert_excepts_input").placeholder = browser.i18n.getMessage("exceptionPlaceholderText");
    setLocText("advert_excepts_submit", "addButton");

    // Statistics Stuff
    setLocText("stats_title", "categoryStatisticsHeader");
    setLocText("stats_desc", "categoryStatisticsDesc");

}

/**
 * This function is executed when opening the settings page.
 */
const setupSettingsPage = async function() {

    setupLocalization();

    let restoreExceptionList = async function (storageID, listID) {
        let storedExc = await getExceptionsList(storageID);
        let numEntries = storedExc.length;
        for (let i = 0; i < numEntries; i++) {
            appendExceptionToList(storedExc[i], listID, storageID);
        }
    }
    restoreExceptionList("cblk_exglobal", "website_exceptions");
    restoreExceptionList("cblk_exfunc", "functional_exceptions");
    restoreExceptionList("cblk_exanal", "analytics_exceptions");
    restoreExceptionList("cblk_exadvert", "advertising_exceptions");

    let policy = await getUserPolicy();
    document.getElementById("nec_checkbox").checked = policy[0];
    document.getElementById("func_checkbox").checked = policy[1];
    document.getElementById("anal_checkbox").checked = policy[2];
    document.getElementById("advert_checkbox").checked = policy[3];

    let debugState = await getDebugState();
    document.getElementById("debug_checkbox").checked = debugState;

    // Statistics
    let sending = browser.runtime.sendMessage({"get_stats": true});
    sending.then((msg) => {
        let stats = msg.response;
        document.getElementById("num_necessary").textContent = browser.i18n.getMessage("statsNecessary", stats[0]);
        document.getElementById("num_functional").textContent = browser.i18n.getMessage("statsFunctional", stats[1]);
        document.getElementById("num_analytics").textContent = browser.i18n.getMessage("statsAnalytics", stats[2]);
        document.getElementById("num_advertising").textContent = browser.i18n.getMessage("statsAdvertising", stats[3]);
        document.getElementById("num_uncat").textContent = browser.i18n.getMessage("statsWhitelist", stats[4]);
    });


}


/**
 * The user policy is a fixed-size array of 4 booleans.
 * @param {Object} event Unused
 */
const updateUserPolicy = async function(event) {
    let cN = document.getElementById("nec_checkbox").checked;
    let cF = document.getElementById("func_checkbox").checked;
    let cAn = document.getElementById("anal_checkbox").checked;
    let cAd = document.getElementById("advert_checkbox").checked;

    await setUserPolicy([cN, cF, cAn, cAd]);
    document.getElementById("submit_text").hidden = false;
}

/**
 * Event for clicking the debug checkbox
 */
const toggleDebugging = async function() {
    let debugStatus = document.getElementById("debug_checkbox").checked;
    await setDebugState(debugStatus);
}

/**
 * Runs the classification on all current browser cookies
 */
const classifyAllCurrentCookies = async function() {
    let sending = browser.runtime.sendMessage({"classify_all": true});
    sending.then((msg) => {
        console.debug(msg.response);
        document.getElementById("apply_text").hidden = false;
    });
}

/**
 * Log the storage area that changed, then for each item changed,
 * log its old value and its new value.
 * @param {Object} changes Object containing the storage changes.
 * @param {String} area String for the storage area.
 */
const logStorageChange = function(changes, area) {
    console.log("Change in storage area: " + area);

    let changedItems = Object.keys(changes);

    for (let item of changedItems) {
      console.log(item + " has changed:");
      console.log("Old value: ");
      console.log(changes[item].oldValue);
      console.log("New value: ");
      console.log(changes[item].newValue);
    }
}
browser.storage.onChanged.addListener(logStorageChange);

// Listeners
document.addEventListener("DOMContentLoaded", setupSettingsPage);

document.querySelector("#submit_prefs").addEventListener("click", updateUserPolicy);
document.querySelector("#debug_checkbox").addEventListener("click", toggleDebugging);
document.querySelector("#classify_button").addEventListener("click", classifyAllCurrentCookies);


document.querySelector("#website_excepts_submit").addEventListener("click", (e) => {
    e.preventDefault();
    handleExceptionSubmit("#website_excepts_input", "cblk_exglobal", "website_exceptions");
});

document.querySelector("#func_excepts_submit").addEventListener("click", (e) => {
    e.preventDefault();
    handleExceptionSubmit("#func_excepts_input", "cblk_exfunc", "functional_exceptions");
});

document.querySelector("#analytics_excepts_submit").addEventListener("click", (e) => {
    e.preventDefault();
    handleExceptionSubmit("#analytics_excepts_input", "cblk_exanal", "analytics_exceptions");
});

document.querySelector("#advert_excepts_submit").addEventListener("click", (e) => {
    e.preventDefault();
    handleExceptionSubmit("#advert_excepts_input", "cblk_exadvert", "advertising_exceptions");
});


/**
 * Helper function for setting up enter events on the text input fields.
 * @param {String} inputFieldID Identity of the input field.
 * @param {String} buttonID Identity of the button to click.
 */
const addEnterListener = function(inputFieldID, buttonID) {
    document.getElementById(inputFieldID).addEventListener("keydown", function(event) {
        if (!event.repeat && event.key === "Enter") {
            event.preventDefault();
            document.getElementById(buttonID).click();
        }
    });
}

addEnterListener("website_excepts_input", "website_excepts_submit");
addEnterListener("func_excepts_input", "func_excepts_submit");
addEnterListener("analytics_excepts_input", "analytics_excepts_submit");
addEnterListener("advert_excepts_input", "advert_excepts_submit");