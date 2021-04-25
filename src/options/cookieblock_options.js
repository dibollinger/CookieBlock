// Author: Dino Bollinger
// License: MIT

/** Permissiveness Slider Stuff */
const nfslider = document.getElementById("nfslider");
const sliderValDisplay = document.getElementById("slider_value");

/**
 * Remove an item from a dynamically generated exception list.
 * @param {String} listItem List item to be removed.
 * @param {String} storageID Extension storage id for exception list.
 * @param {String} removedDomain
 */
 const removeExceptionFromList = async function(removedDomain, listItem, storageID) {
    let exlist = listItem.parentElement;

    // remove the internal stored string (async with promise)
    domainList = await getStorageValue(browser.storage.sync, storageID);
    let index = domainList.indexOf(removedDomain);
    domainList.splice(index, 1)

    // update storage
    setStorageValue(domainList, browser.storage.sync, storageID);

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
    button.textContent = "X";
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
    let iElem = document.getElementById(inputID);
    if (iElem.value != null && iElem.value != "")
    {
        let domainOrURL = (' ' + iElem.value).slice(1);
        let sanitizedDomain = undefined;
        try {
            sanitizedDomain = urlToUniformDomain(new URL(domainOrURL).hostname);
        } catch(error) {
            sanitizedDomain = urlToUniformDomain(domainOrURL);
        }

        let domainList = await getStorageValue(browser.storage.sync, storageID);
        domainList.push(domainOrURL);
        setStorageValue(domainList, browser.storage.sync, storageID);

        appendExceptionToList(sanitizedDomain, listID, storageID);

        // empty the input box
        iElem.value = "";
    }
}

/**
 * Helper to enable the necessary checkbox
 * @param {Boolean} pauseState
 */
 const enableNecessaryCheckboxIfPaused = async function(pauseState) {
    let nCB = document.getElementById("nec_checkbox");
    nCB.disabled = !pauseState;
    nCB.style.opacity = pauseState ? "1.0" : "0.5";
    nCB.style.filter = pauseState ? "grayscale(0%)" : "grayscale(100%)";
    if (!pauseState) {
        let policy = await getStorageValue(browser.storage.sync, "cblk_userpolicy")
        if (policy[0] !== true){
            policy[0] = true;
            setStorageValue(policy, browser.storage.sync, "cblk_userpolicy");
        }
    }
}

/**
 * Function that contains most of the localization text assignments.
 */
const setupLocalization = function () {
    // Title
    setStaticLocaleText("settings_title", "extensionName");
    setStaticLocaleText("settings_subtitle", "settingsSubtitle");

    // Consent Preference Text
    setStaticLocaleText("cprefs_legend", "optionsHeaderConsent");
    setStaticLocaleText("cprefs_desc","consentDescription");
    setStaticLocaleText("nec_title","catNecessaryTitle");
    setStaticLocaleText("nec_desc","catNecessaryDesc");
    setStaticLocaleText("func_title","catFunctionalityTitle");
    setStaticLocaleText("func_desc","catFunctionalityDesc");
    setStaticLocaleText("anal_title","catAnalyticsTitle");
    setStaticLocaleText("anal_desc","catAnalyticsDesc");
    setStaticLocaleText("advert_title","catAdvertisingTitle");
    setStaticLocaleText("advert_desc","catAdvertisingDesc");

    // Additional Options
    setStaticLocaleText("slider_title", "sliderTitle");
    setStaticLocaleText("slider_desc", "sliderDescription");

    setStaticLocaleText("extra_opts_legend","headerAdditionalOptions");
    setStaticLocaleText("extra_opts_desc","additionalOptionsDesc");
    setStaticLocaleText("pause_title", "pauseCookieRemoval");
    setStaticLocaleText("pause_desc", "pauseDescription");
    setStaticLocaleText("classify_title", "currentCookieEnforceTitle");
    setStaticLocaleText("classify_desc", "currentCookieEnforceDescription");
    setStaticLocaleText("classify_button", "currentCookieEnforceButton");
    setStaticLocaleText("classify_applytext", "currentCookieEnforceMsg");

    setStaticLocaleText("default_title", "defaultTitle");
    setStaticLocaleText("default_desc", "defaultDescription");
    setStaticLocaleText("default_button", "defaultButton");
    setStaticLocaleText("default_applytext", "defaultApplyText");

    setStaticLocaleText("clear_title", "clearDataTitle");
    setStaticLocaleText("clear_desc", "clearDataDescription");
    setStaticLocaleText("clear_button", "clearDataButton");
    setStaticLocaleText("clear_applytext", "clearDataText");

    // Website exception text
    setStaticLocaleText("wheader_title", "globalExceptionsHeader");
    setStaticLocaleText("wheader_desc", "globalExceptionsDescription");
    document.getElementById("website_excepts_input").placeholder = browser.i18n.getMessage("exceptionPlaceholderText");
    setStaticLocaleText("website_excepts_submit", "addButton");

    // Functionality exceptions
    setStaticLocaleText("fheader_title", "functionalExceptionsHeader");
    setStaticLocaleText("fheader_desc", "functionalExceptionsDescription");
    document.getElementById("func_excepts_input").placeholder = browser.i18n.getMessage("exceptionPlaceholderText");
    setStaticLocaleText("func_excepts_submit", "addButton");

    // Analytics exceptions
    setStaticLocaleText("anheader_title", "analyticsExceptionsHeader");
    setStaticLocaleText("anheader_desc", "analyticsExceptionsDescription");
    document.getElementById("analytics_excepts_input").placeholder = browser.i18n.getMessage("exceptionPlaceholderText");
    setStaticLocaleText("analytics_excepts_submit", "addButton");

    // Advertising exceptions
    setStaticLocaleText("adheader_title", "advertExceptionsHeader");
    setStaticLocaleText("adheader_desc", "advertExceptionsDescription");
    document.getElementById("advert_excepts_input").placeholder = browser.i18n.getMessage("exceptionPlaceholderText");
    setStaticLocaleText("advert_excepts_submit", "addButton");

    // Statistics Stuff
    setStaticLocaleText("stats_title", "categoryStatisticsHeader");
    setStaticLocaleText("stats_desc", "categoryStatisticsDesc");

}

/**
 * This function is executed when opening the settings page.
 */
const setupSettingsPage = async function() {

    setupLocalization();

    let restoreExceptionList = async function (storageID, listID) {
        let storedExc = await getStorageValue(browser.storage.sync, storageID);
        let numEntries = storedExc.length;
        for (let i = 0; i < numEntries; i++) {
            appendExceptionToList(storedExc[i], listID, storageID);
        }
    }
    restoreExceptionList("cblk_exglobal", "website_exceptions");
    restoreExceptionList("cblk_exfunc", "functional_exceptions");
    restoreExceptionList("cblk_exanal", "analytics_exceptions");
    restoreExceptionList("cblk_exadvert", "advertising_exceptions");

    let policy = await getStorageValue(browser.storage.sync, "cblk_userpolicy");
    document.getElementById("nec_checkbox").checked = policy[0];
    document.getElementById("func_checkbox").checked = policy[1];
    document.getElementById("anal_checkbox").checked = policy[2];
    document.getElementById("advert_checkbox").checked = policy[3];

    let pauseState = await getStorageValue(browser.storage.local, "cblk_pause");
    document.getElementById("pause_checkbox").checked = pauseState;

    enableNecessaryCheckboxIfPaused(pauseState);

    let permScale = await getStorageValue(browser.storage.sync, "cblk_pscale");
    nfslider.value = permScale;
    sliderValDisplay.innerHTML = permScale;

    // Statistics
    let sending = browser.runtime.sendMessage({"get_stats": true});
    sending.then((msg) => {
        let stats = msg.response;
        setStaticLocaleText("num_necessary", "statsNecessary", [stats[0]]);
        setStaticLocaleText("num_functional", "statsFunctional", [stats[1]]);
        setStaticLocaleText("num_analytics", "statsAnalytics", [stats[2]]);
        setStaticLocaleText("num_advertising", "statsAdvertising", [stats[3]]);
        setStaticLocaleText("num_uncat", "statsWhitelist", [stats[4]]);
    });

    document.getElementById("extra_settings").hidden = !enableExtraOptions;
}


/**
 * Log the storage area that changed, then for each item changed,
 * log its old value and its new value.
 * @param {Object} changes Object containing the storage changes.
 * @param {String} area String for the storage area.
 */
const logStorageChange = function(changes, area) {
    let emptyAndRestoreList = async function (storedExc, storageID, listID) {
        let e = document.getElementById(listID);
        let child = e.lastElementChild;
        while (child) {
            e.removeChild(child);
            child = e.lastElementChild;
        }

        let numEntries = storedExc.length;
        for (let i = 0; i < numEntries; i++) {
            appendExceptionToList(storedExc[i], listID, storageID);
        }
    }

    let changedItems = Object.keys(changes);
    console.debug(`Changes for area '${area}' in: ${changedItems}`);
    if (area === "sync") {
        if (changedItems.includes("cblk_userpolicy")) {
            newPolicy = changes["cblk_userpolicy"].newValue;
            document.getElementById("nec_checkbox").checked = newPolicy[0];
            document.getElementById("func_checkbox").checked = newPolicy[1];
            document.getElementById("anal_checkbox").checked = newPolicy[2];
            document.getElementById("advert_checkbox").checked = newPolicy[3];
        }

        if (changedItems.includes("cblk_exglobal")) {
            emptyAndRestoreList(changes["cblk_exglobal"].newValue, "cblk_exglobal", "website_exceptions");
        }

        if (changedItems.includes("cblk_pscale")) {
            nfslider.value = changes["cblk_pscale"].newValue;
            sliderValDisplay.innerHTML = changes["cblk_pscale"].newValue;
        }
    } else if (area === "local") {
        if (changedItems.includes("cblk_pause")){
            let pauseState = changes["cblk_pause"].newValue;
            document.getElementById("pause_checkbox").checked = pauseState;
            enableNecessaryCheckboxIfPaused(pauseState);
        }

        if (changedItems.includes("cblk_counter")) {
            stats = changes["cblk_counter"].newValue;
            setStaticLocaleText("num_necessary", "statsNecessary", [stats[0]]);
            setStaticLocaleText("num_functional", "statsFunctional", [stats[1]]);
            setStaticLocaleText("num_analytics", "statsAnalytics", [stats[2]]);
            setStaticLocaleText("num_advertising", "statsAdvertising", [stats[3]]);
            setStaticLocaleText("num_uncat", "statsWhitelist", [stats[4]]);
        }
    }
}
browser.storage.onChanged.addListener(logStorageChange);

// Listeners
document.addEventListener("DOMContentLoaded", setupSettingsPage);

/**
 * Helper for adding consent toggle listeners
 */
 const addPrefClickListener = function (checkboxID, idx) {
    let cb = document.getElementById(checkboxID);
    cb.addEventListener("click", async (event) => {
        policy = await getStorageValue(browser.storage.sync, "cblk_userpolicy");
        policy[idx] = cb.checked;
        setStorageValue(policy, browser.storage.sync, "cblk_userpolicy");
    });
}

addPrefClickListener("nec_checkbox", 0);
addPrefClickListener("func_checkbox", 1);
addPrefClickListener("anal_checkbox", 2);
addPrefClickListener("advert_checkbox", 3);

// debug checkbox
document.getElementById("pause_checkbox").addEventListener("click", async () => {
    let pauseStatus = document.getElementById("pause_checkbox").checked;
    setStorageValue(pauseStatus, browser.storage.local, "cblk_pause");
});

// classify all cookies button
document.getElementById("classify_button").addEventListener("click", async () => {
    setStaticLocaleText("classify_applytext", "currentCookieProgressMsg");
    document.getElementById("classify_applytext").hidden = false;
    let sending = browser.runtime.sendMessage({"classify_all": true});
    sending.then((msg) => {
        console.debug(msg.response);
        setStaticLocaleText("classify_applytext", "currentCookieEnforceMsg");
    }).catch((err) => {
        console.error(err);
        setStaticLocaleText("classify_applytext", "applyErrorText");
    });
});

// reset defaults button
document.getElementById("default_button").addEventListener("click", () => {
    getExtensionFile(browser.extension.getURL("ext_data/default_config.json"), "json", (defaultConfig) => {
        overrideDefaults(defaultConfig);
        document.getElementById("default_applytext").hidden = false;
    });
});

// reset storage button
document.getElementById("clear_button").addEventListener("click", () => {
    let sending = browser.runtime.sendMessage({"reset_storage": true});
    sending.then((msg) => {
        console.debug(msg.response);
        setStaticLocaleText("clear_applytext", "clearDataText");
    }).catch((err) => {
        console.error(err);
        setStaticLocaleText("clear_applytext", "applyErrorText");
    });
    document.getElementById("clear_applytext").hidden = false;
});


/**
 * Helper for adding exception add click listeners.
 * @param {String} buttonID
 * @param {String} inputID
 * @param {String} storageID
 * @param {String} listID
*/
const addExcClickListener = function (buttonID, inputID, storageID, listID) {
    document.getElementById(buttonID).addEventListener("click", (e) => {
        e.preventDefault();
        handleExceptionSubmit(inputID, storageID, listID);
    });
}

addExcClickListener("website_excepts_submit", "website_excepts_input", "cblk_exglobal", "website_exceptions");
addExcClickListener("func_excepts_submit", "func_excepts_input", "cblk_exfunc", "functional_exceptions");
addExcClickListener("analytics_excepts_submit", "analytics_excepts_input", "cblk_exanal", "analytics_exceptions");
addExcClickListener("advert_excepts_submit", "advert_excepts_input", "cblk_exadvert", "advertising_exceptions");

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


nfslider.oninput = function() {;
    sliderValDisplay.innerHTML = this.value;
}

nfslider.addEventListener("mouseup", function(event) {
    setStorageValue(this.value, browser.storage.sync, "cblk_pscale");
});
