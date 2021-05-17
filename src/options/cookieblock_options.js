//-------------------------------------------------------------------------------
/*
Copyright (C) 2021 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------


// HTML elements
const histCheckbox = document.getElementById("history-consent-checkbox");
const pauseCheckbox = document.getElementById("pause_checkbox");
const nfslider = document.getElementById("nfslider");
const sliderValDisplay = document.getElementById("slider_value");
const clearButton = document.getElementById("clear_button");
const defaultButton = document.getElementById("default_button");
const classifyButton = document.getElementById("classify_button");
const necessaryCheckbox = document.getElementById("nec_checkbox");
const functionalityCheckbox = document.getElementById("func_checkbox");
const analyticsCheckbox = document.getElementById("anal_checkbox");
const advertisingCheckbox = document.getElementById("advert_checkbox");
const statisticsSection = document.getElementById("stats-div");
const jsonButton = document.getElementById("json_button");
const necessaryStats = document.getElementById("li_n");
const functionalStats = document.getElementById("li_f");
const analyticsStats = document.getElementById("li_an");
const advertisingStats = document.getElementById("li_ad");

const cconfigButton = document.getElementById("ud-button");
const internalCheckbox = document.getElementById("kc-checkbox");

// Characters allowed in a domain -- if regex does not match, the domain contains invalid characters
const validDomainCharsRegex = new RegExp("[a-zA-Z0-9-.]+\\.[a-zA-Z0-9-.]+");
// const validPathRegex = new RegExp("^http(s)?://.*");

/**
 * Remove an item from a dynamically generated exception list.
 * @param {String} removedDomain Domain that needs to be removed.
 * @param {String} listItem List item to be removed.
 * @param {String} storageID Extension storage id for exception list.
 */
 const removeItemFromList = async function(removedDomain, listItem, storageID) {
    let exlist = listItem.parentElement;

    // remove the internal stored string (async with promise)
    let domainList = await getStorageValue(chrome.storage.sync, storageID);
    let index = domainList.indexOf(removedDomain);
    domainList.splice(index, 1)

    // update storage
    setStorageValue(domainList, chrome.storage.sync, storageID);

    // finally, remove the element from the visible list
    exlist.removeChild(listItem);
}


/**
 * Append an item to a dynamically generated exception list.
 * @param {String} addDomain Domain to add to the storage.
 * @param {String} listID HTML List identity
 * @param {String} storageID Extension storage id for exception list.
 */
const appendItemToList = async function(addDomain, listID, storageID) {
    let node = document.createElement("li")

    // button has the remove event set up directly
    let button = document.createElement("button");
    button.textContent = "X";
    button.addEventListener("click", () => { removeItemFromList(addDomain, node, storageID) });

    let textdiv = document.createElement("div");
    let textnode = document.createTextNode(addDomain);

    textdiv.appendChild(textnode);
    textdiv.class = "text_content";

    node.appendChild(button);
    node.appendChild(textnode);
    document.getElementById(listID).appendChild(node);
}



/**
 * Helper to enable the necessary checkbox
 * @param {Boolean} pauseState
 */
 const enableNecessaryCheckboxIfPaused = async function(pauseState) {
    necessaryCheckbox.disabled = !pauseState;
    necessaryCheckbox.style.opacity = pauseState ? "1.0" : "0.5";
    if (!pauseState) {
        let policy = await getStorageValue(chrome.storage.sync, "cblk_userpolicy")
        if (policy[0] !== true){
            policy[0] = true;
            setStorageValue(policy, chrome.storage.sync, "cblk_userpolicy");
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

    // Description
    setStaticLocaleText("options-greet","optionsGreeting");
    setStaticLocaleText("options-desc1","firstTimeDescPG1");
    setStaticLocaleText("options-desc2","firstTimeDescPG2");
    setStaticLocaleText("feedback-pg1","feedbackPG1");
    setStaticLocaleText("feedback-pg2","feedbackPG2");
    setStaticLocaleText("feedback-pg3","feedbackPG3");
    setStaticLocaleText("feedback-survey","feedbackFormURL");
    document.getElementById("feedback-survey").href = chrome.i18n.getMessage("feedbackFormURL");

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
    setStaticLocaleText("history-consent-title", "historyConsentTitle");
    setStaticLocaleText("history-consent-desc", "historyConsentDesc");

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
    document.getElementById("website_excepts_input").placeholder = chrome.i18n.getMessage("exceptionPlaceholderText");
    setStaticLocaleText("website_excepts_submit", "addButton");

    // Functionality exceptions
    setStaticLocaleText("fheader_title", "functionalExceptionsHeader");
    setStaticLocaleText("fheader_desc", "functionalExceptionsDescription");
    document.getElementById("func_excepts_input").placeholder = chrome.i18n.getMessage("exceptionPlaceholderText");
    setStaticLocaleText("func_excepts_submit", "addButton");

    // Analytics exceptions
    setStaticLocaleText("anheader_title", "analyticsExceptionsHeader");
    setStaticLocaleText("anheader_desc", "analyticsExceptionsDescription");
    document.getElementById("analytics_excepts_input").placeholder = chrome.i18n.getMessage("exceptionPlaceholderText");
    setStaticLocaleText("analytics_excepts_submit", "addButton");

    // Advertising exceptions
    setStaticLocaleText("adheader_title", "advertExceptionsHeader");
    setStaticLocaleText("adheader_desc", "advertExceptionsDescription");
    document.getElementById("advert_excepts_input").placeholder = chrome.i18n.getMessage("exceptionPlaceholderText");
    setStaticLocaleText("advert_excepts_submit", "addButton");

    // Predefined Cookie List
    setStaticLocaleText("predef-title", "predefTitle");
    setStaticLocaleText("predef-desc", "predefDesc");
    document.getElementById("predef-input").placeholder = chrome.i18n.getMessage("predefPlaceholder");
    setStaticLocaleText("predef-submit", "addButton");
    setStaticLocaleText("kc-checkbox-title", "predefIntegratedText");

    // User-defined Cookies Page
    setStaticLocaleText("ud-title", "udTitle");
    setStaticLocaleText("ud-desc", "udDescription");
    setStaticLocaleText("ud-button", "udButton");

    // Statistics Stuff
    setStaticLocaleText("stats_title", "categoryStatisticsHeader");
    setStaticLocaleText("stats_desc", "categoryStatisticsDesc");
    setStaticLocaleText("json_button", "cookieHistoryButtonLabel");
}


/**
 * Send a message to background script to retrieve the label stats.
 */
const getLabelStatsFromBackground = function () {
    chrome.runtime.sendMessage({"get_stats": true}, (msg) => {
        let stats = msg.response;
        setStaticLocaleText("num_necessary", "statsNecessary", [stats[0]]);
        setStaticLocaleText("num_functional", "statsFunctional", [stats[1]]);
        setStaticLocaleText("num_analytics", "statsAnalytics", [stats[2]]);
        setStaticLocaleText("num_advertising", "statsAdvertising", [stats[3]]);
    });
}


/**
 * This function is executed when opening the settings page.
 */
const setupSettingsPage = async function() {

    setupLocalization();

    let restoreExceptionList = async function (storageID, listID) {
        let storedExc = await getStorageValue(chrome.storage.sync, storageID);
        let numEntries = storedExc.length;
        for (let i = 0; i < numEntries; i++) {
            appendItemToList(storedExc[i], listID, storageID);
        }
    }
    restoreExceptionList("cblk_exglobal", "website_exceptions");
    restoreExceptionList("cblk_exfunc", "functional_exceptions");
    restoreExceptionList("cblk_exanal", "analytics_exceptions");
    restoreExceptionList("cblk_exadvert", "advertising_exceptions");
    restoreExceptionList("cblk_knowncookies", "predef-paths");

    let hconsent = await getStorageValue(chrome.storage.sync, "cblk_hconsent");
    histCheckbox.checked = hconsent;
    statisticsSection.hidden = !hconsent;

    let policy = await getStorageValue(chrome.storage.sync, "cblk_userpolicy");
    necessaryCheckbox.checked = policy[0];
    functionalityCheckbox.checked = policy[1];
    analyticsCheckbox.checked = policy[2];
    advertisingCheckbox.checked = policy[3];

    let pauseState = await getStorageValue(chrome.storage.local, "cblk_pause");
    pauseCheckbox.checked = pauseState;
    enableNecessaryCheckboxIfPaused(pauseState);

    let permScale = await getStorageValue(chrome.storage.sync, "cblk_pscale");
    nfslider.value = permScale;
    sliderValDisplay.textContent = permScale;

    internalCheckbox.checked = await getStorageValue(chrome.storage.sync, "cblk_useinternal");

    getLabelStatsFromBackground();

    document.getElementById("extra_settings").hidden = !enableExtraOptions;
}

document.addEventListener("DOMContentLoaded", setupSettingsPage);


/**
 * Whenever storage.local or storage.sync updates, reflect this in the selection
 * inside the options menu.
 * @param {Object} changes Stores the objects that were altered.
 * @param {Object} area Storage area that was changed
 */
const updateSelectionsOnStorageChanged = function(changes, area) {

    // Empty the exception list and restore it to the new state.
    let emptyAndRestoreList = async function (storedExc, storageID, listID) {
        let e = document.getElementById(listID);
        let child = e.lastElementChild;
        while (child) {
            e.removeChild(child);
            child = e.lastElementChild;
        }

        let numEntries = storedExc.length;
        for (let i = 0; i < numEntries; i++) {
            appendItemToList(storedExc[i], listID, storageID);
        }
    }

    let changedItems = Object.keys(changes);
    //console.debug(`Changes for area '${area}' in: ${changedItems}`);
    if (area === "sync") {
        // update the consent checkboxes
        if (changedItems.includes("cblk_userpolicy")) {
            newPolicy = changes["cblk_userpolicy"].newValue;
            necessaryCheckbox.checked = newPolicy[0];
            functionalityCheckbox.checked = newPolicy[1];
            analyticsCheckbox.checked = newPolicy[2];
            advertisingCheckbox.checked = newPolicy[3];
        }

        // update the exception list
        if (changedItems.includes("cblk_exglobal")) {
            emptyAndRestoreList(changes["cblk_exglobal"].newValue, "cblk_exglobal", "website_exceptions");
        }

        // update the necessary bias scale
        if (changedItems.includes("cblk_pscale")) {
            nfslider.value = changes["cblk_pscale"].newValue;
            sliderValDisplay.textContent = changes["cblk_pscale"].newValue;
        }

        // update the history consent toggle
        if (changedItems.includes("cblk_hconsent")) {
            histCheckbox.checked = changes["cblk_hconsent"].newValue;
            statisticsSection.hidden = !changes["cblk_hconsent"].newValue;
        }
    } else if (area === "local") {
        // update the pause button
        if (changedItems.includes("cblk_pause")){
            pauseCheckbox.checked = changes["cblk_pause"].newValue;
            enableNecessaryCheckboxIfPaused(changes["cblk_pause"].newValue);
        }
    }
}

chrome.storage.onChanged.addListener(updateSelectionsOnStorageChanged);


/**
 * Helper for adding consent toggle listeners
 */
 const addPrefClickListener = function (cb, idx) {
    cb.addEventListener("click", async (ev) => {
        policy = await getStorageValue(chrome.storage.sync, "cblk_userpolicy");
        policy[idx] = cb.checked;
        setStorageValue(policy, chrome.storage.sync, "cblk_userpolicy");
    });
}
addPrefClickListener(necessaryCheckbox, 0);
addPrefClickListener(functionalityCheckbox, 1);
addPrefClickListener(analyticsCheckbox, 2);
addPrefClickListener(advertisingCheckbox, 3);


// classify all cookies button
classifyButton.addEventListener("click", async () => {
    setStaticLocaleText("classify_applytext", "currentCookieProgressMsg");
    chrome.runtime.sendMessage({"classify_all": true}, (msg) => {
        document.getElementById("classify_applytext").hidden = false;
        if (chrome.runtime.lastError){
            console.error(chrome.runtime.lastError);
            setStaticLocaleText("classify_applytext", "applyErrorText");
        } else{
            console.debug(msg.response);
            setStaticLocaleText("classify_applytext", "currentCookieEnforceMsg");
        }
    });
});


// reset defaults button
defaultButton.addEventListener("click", () => {
    chrome.runtime.sendMessage({"reset_defaults": true}, (msg) => {
        document.getElementById("default_applytext").hidden = false;
        if (chrome.runtime.lastError){
            console.error(chrome.runtime.lastError);
            setStaticLocaleText("default_applytext", "applyErrorText");
        } else {
            console.debug(msg.response);
            setStaticLocaleText("default_applytext", "defaultApplyText");
        }
    });
});


// reset storage button
clearButton.addEventListener("click", () => {
    chrome.runtime.sendMessage({"reset_storage": true}, (msg) => {
        if (chrome.runtime.lastError) {
            console.error(err);
            setStaticLocaleText("clear_applytext", "applyErrorText");
        } else {
            console.debug(msg.response);
            setStaticLocaleText("clear_applytext", "clearDataText");
            getLabelStatsFromBackground();
        }
        document.getElementById("clear_applytext").hidden = false;
    });
});


/**
 * Handle the mouse click event to submit a custom domain exception to the list.
 * @param {String} buttonID   Identity of the button that will be clicked.
 * @param {String} inputID    Identity of the input box.
 * @param {String} storageID  Storage identity for the exception list.
 * @param {String} listID     Identity of the list to append the exception to.
 * @param {String} errorID    Error box identity, if it needs to be displayed.
 */
const addExcClickListener = function (buttonID, inputID, storageID, listID, errorID) {
    document.getElementById(buttonID).addEventListener("click", async (e) => {
        e.preventDefault();
        let iElem = document.getElementById(inputID);
        let inputDomain = iElem.value;
        let errorElem = document.getElementById(errorID);
        if (validDomainCharsRegex.test(inputDomain)) {
            let domainOrURL = (' ' + inputDomain).slice(1);

            let sanitizedDomain = cleanDomain(domainOrURL);

            let domainList = await getStorageValue(chrome.storage.sync, storageID);
            if (!domainList.includes(sanitizedDomain)) {
                domainList.push(sanitizedDomain);
                setStorageValue(domainList, chrome.storage.sync, storageID);
                appendItemToList(sanitizedDomain, listID, storageID);
                iElem.value = "";
                iElem.style.color = "black";
                errorElem.hidden = true;
            } else {
                setStaticLocaleText(errorID, "inputErrorDuplicate");
                iElem.style.color = "red";
                errorElem.hidden = false;
            }
        } else {
            console.info("User entered invalid characters for domain string.");
            setStaticLocaleText(errorID, "inputErrorInvalid");
            iElem.style.color = "red";
            errorElem.hidden = false;
        }
    });
}

addExcClickListener("website_excepts_submit", "website_excepts_input", "cblk_exglobal", "website_exceptions", "wexcepts-error");
addExcClickListener("func_excepts_submit", "func_excepts_input", "cblk_exfunc", "functional_exceptions", "func-error");
addExcClickListener("analytics_excepts_submit", "analytics_excepts_input", "cblk_exanal", "analytics_exceptions", "analytics-error");
addExcClickListener("advert_excepts_submit", "advert_excepts_input", "cblk_exadvert", "advertising_exceptions", "advert-error");

/**
 * Helper function for setting up enter events on the text input fields.
 * @param {String} inputFieldID Identity of the input field.
 * @param {String} buttonID Identity of the button to click.
 */
const addEnterListener = function(inputFieldID, buttonID) {
    document.getElementById(inputFieldID).addEventListener("keydown", (ev) => {
        if (!ev.repeat && ev.key === "Enter") {
            ev.preventDefault();
            document.getElementById(buttonID).click();
        }
    });
}

addEnterListener("website_excepts_input", "website_excepts_submit");
addEnterListener("func_excepts_input", "func_excepts_submit");
addEnterListener("analytics_excepts_input", "analytics_excepts_submit");
addEnterListener("advert_excepts_input", "advert_excepts_submit");

// slider
nfslider.oninput = function() {;
    sliderValDisplay.textContent = this.value;
}
nfslider.addEventListener("mouseup", function(ev) {
    setStorageValue( this.value, chrome.storage.sync, "cblk_pscale");
});

// history consent checkbox
histCheckbox.addEventListener("click", (ev) => {
    setStorageValue( histCheckbox.checked, chrome.storage.sync, "cblk_hconsent");
});

// pause checkbox
pauseCheckbox.addEventListener("click", (ev) => {
    setStorageValue( pauseCheckbox.checked, chrome.storage.local, "cblk_pause");
});

const message_openJSON = (inMSG) => {
    chrome.runtime.sendMessage({"open_json": inMSG}, (msg) => {
        if (msg.lastError) {
            console.error("Could not open the resulting JSON file!");
        } else {
            let tab = window.open(inMSG + ".json", "_blank");
            tab.document.write('<pre id="json_body"></pre>');
            tab.document.getElementById("json_body").textContent = JSON.stringify(msg.response, null, 4);
            tab.document.close();
        }
    });
}

cconfigButton.addEventListener("click", (ev) => {
    chrome.tabs.create({"active": true, "url": "/options/cookieblock_cconfig.html"});
});

// listeners to open JSON documents in new tabs
jsonButton.addEventListener("click", (ev) => { message_openJSON("full"); });
necessaryStats.addEventListener("click", (ev) => { message_openJSON("necessary"); });
functionalStats.addEventListener("click", (ev) => { message_openJSON("functional"); });
analyticsStats.addEventListener("click", (ev) => { message_openJSON("analytics"); });
advertisingStats.addEventListener("click", (ev) => { message_openJSON("advertising"); });

// Update stats in 5 second intervals
setInterval( async () => { getLabelStatsFromBackground(); }, 5_000);


/**
 * Handle the mouse click event to submit path to a potential known cookies JSON.
 * @param {String} buttonID   Identity of the button that will be clicked.
 * @param {String} inputID    Identity of the input box.
 * @param {String} storageID  Storage identity for the path list.
 * @param {String} listID     Identity of the list to append the exception to.
 * @param {String} errorID    Error box identity, if it needs to be displayed.
 */
document.getElementById("predef-submit").addEventListener("click", async (e) => {
    let handleError = (errorType) => {
        console.info("User entered invalid url for cookies path.");
        setStaticLocaleText("predef-error", errorType);
        iElem.style.color = "red";
        errorElem.hidden = false;
    }

    e.preventDefault();
    let iElem = document.getElementById("predef-input");
    let inputPath = iElem.value;
    let errorElem = document.getElementById("predef-error");

    let pathList = await getStorageValue(chrome.storage.sync, "cblk_knowncookies");
    let pathString = (' ' + inputPath).slice(1);

    if (pathList.includes(pathString)) {
        handleError("inputErrorDuplicate");
    } else {
        try {
            new URL(pathString);
            getExtensionFile(pathString, "json", (result) => {
                if (typeof result === "object" && result !== null && ("name_match" in result || "domain_match" in result || "domain_regex" in result)) {
                    pathList.push(pathString);
                    setStorageValue(pathList, chrome.storage.sync, "cblk_knowncookies");
                    appendItemToList(pathString, "predef-paths", "cblk_knowncookies");
                    iElem.value = "";
                    iElem.style.color = "black";
                    errorElem.hidden = true;
                } else {
                    console.log(`Retrieved file was not a JSON object.`);
                    handleError("inputErrorNoJSON");
                }
             }, (errorCode) => {
                console.log(`Could not retrieve file, error code: ${errorCode}`);
                handleError("inputErrorNoResolve");
            })
        } catch(error) {
            handleError("inputErrorNoResolve");
        }
    }
});

addEnterListener("predef-input", "predef-submit");

// internal list checkbox
internalCheckbox.addEventListener("click", (ev) => {
    setStorageValue( internalCheckbox.checked, chrome.storage.sync, "cblk_useinternal");
});