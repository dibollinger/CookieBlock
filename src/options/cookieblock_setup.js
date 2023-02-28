//-------------------------------------------------------------------------------
/*
Copyright (C) 2021-2022 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------

const histCheckbox = document.getElementById("history-consent-checkbox");
const necessaryCheckbox = document.getElementById("nec_checkbox");
const functionalityCheckbox = document.getElementById("func_checkbox");
const analyticsCheckbox = document.getElementById("anal_checkbox");
const advertisingCheckbox = document.getElementById("advert_checkbox");

/**
 * Function that contains the localization text assignments.
 */
 const setupLocalization = function () {
    setStaticLocaleText("init_title", "extensionName");
    setStaticLocaleText("init_subtitle", "firstTimeSubtitle");

    setStaticLocaleText("history-consent-title", "historyConsentTitle");
    setStaticLocaleText("history-consent-desc", "historyConsentDesc");
    setStaticLocaleText("history-why", "historyWhy");
    setStaticLocaleText("history-consent-desc-detailed", "historyConsentDescDetailed");

    setStaticLocaleText("setup_greet", "firstTimeGreeting");
    setStaticLocaleText("setup_desc1","firstTimeDescPG1");
    setStaticLocaleText("setup_desc2","firstTimeDescPG2");
    setStaticLocaleText("setup_desc3","firstTimeDescPG3");

    setStaticLocaleText("cprefs_legend", "setupHeaderPreferences");
    setStaticLocaleText("cprefs_desc","consentDescription");
    setStaticLocaleText("nec_title","catNecessaryTitle");
    setStaticLocaleText("nec_desc","catNecessaryDesc");
    setStaticLocaleText("func_title","catFunctionalityTitle");
    setStaticLocaleText("func_desc","catFunctionalityDesc");
    setStaticLocaleText("anal_title","catAnalyticsTitle");
    setStaticLocaleText("anal_desc","catAnalyticsDesc");
    setStaticLocaleText("advert_title","catAdvertisingTitle");
    setStaticLocaleText("advert_desc","catAdvertisingDesc");

    setStaticLocaleText("classify_title", "currentCookieEnforceTitle");
    setStaticLocaleText("classify_desc", "currentCookieEnforceDescriptionSetup");
    setStaticLocaleText("set_policy","buttonExitSetup");

}

/**
 * This function is executed when opening the first time setup.
 */
const setupInitPage = async function() {
    setupLocalization();

    necessaryCheckbox.checked = true;
    functionalityCheckbox.checked = true;
    analyticsCheckbox.checked = false;
    advertisingCheckbox.checked = false;
    histCheckbox.checked = true;

    // switch recommended store links according to browser name for Firefox, Chrome, Edge, Opera and other:
    // if browser is Firefox:
    if (navigator.userAgent.toLowerCase().indexOf('firefox') > -1) {
        document.getElementById("setup_link_isdcac").href = "https://addons.mozilla.org/firefox/addon/istilldontcareaboutcookies/";
        document.getElementById("setup_link_ublock").href = "https://addons.mozilla.org/firefox/addon/ublock-origin/";
    } else if (navigator.userAgent.toLowerCase().indexOf('edge') > -1) {
        // no I still don't care about cookies - point to Chrome store
        document.getElementById("setup_link_isdcac").href = "https://chrome.google.com/webstore/detail/i-still-dont-care-about-c/edibdbjcniadpccecjdfdjjppcpchdlm";
        document.getElementById("setup_link_ublock").href = "https://microsoftedge.microsoft.com/addons/detail/ublock-origin/odfafepnkmbhccpbejgmiehpchacaeak";
    } else if (navigator.userAgent.toLowerCase().indexOf('opera') > -1) {
        // no I still don't care about cookies - point to Chrome store
        document.getElementById("setup_link_isdcac").href = "https://chrome.google.com/webstore/detail/i-still-dont-care-about-c/edibdbjcniadpccecjdfdjjppcpchdlm";
        document.getElementById("setup_link_ublock").href = "https://addons.opera.com/en/extensions/details/ublock/";
    } else {
        // use Chrome store as default
        document.getElementById("setup_link_isdcac").href = "https://chrome.google.com/webstore/detail/i-still-dont-care-about-c/edibdbjcniadpccecjdfdjjppcpchdlm";
        document.getElementById("setup_link_ublock").href = "https://chrome.google.com/webstore/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm";
    }

}

document.addEventListener("DOMContentLoaded", setupInitPage);


/**
 * Update the toggles relevant to the setup page, based on changes in the local and sync storage.
 * @param {Object} changes Object containing the changes.
 * @param {Object} area Storage area that changed
 */
const updateSelectionOnChange = function(changes, area) {
    let changedItems = Object.keys(changes);
    if (area === "sync") {
        // update the consent checkboxes
        if (changedItems.includes("cblk_userpolicy")) {
            newPolicy = changes["cblk_userpolicy"].newValue;
            necessaryCheckbox.checked = newPolicy[0];
            functionalityCheckbox.checked = newPolicy[1];
            analyticsCheckbox.checked = newPolicy[2];
            advertisingCheckbox.checked = newPolicy[3];
        }

        // update the history consent toggle
        if (changedItems.includes("cblk_hconsent")) {
            histCheckbox.checked = changes["cblk_hconsent"].newValue;
        }
    }
}
chrome.storage.onChanged.addListener(updateSelectionOnChange);


/**
 * Helper for adding click listeners.
 */
 const addPrefClickListener = function (checkboxID, idx) {
    let cb = document.getElementById(checkboxID);
    cb.addEventListener("click", async (event) => {
        policy = await getStorageValue(chrome.storage.sync, "cblk_userpolicy");
        policy[idx] = cb.checked;
        setStorageValue(policy, chrome.storage.sync, "cblk_userpolicy");
    });
}

addPrefClickListener("nec_checkbox", 0);
addPrefClickListener("func_checkbox", 1);
addPrefClickListener("anal_checkbox", 2);
addPrefClickListener("advert_checkbox", 3);

// Set policy button
document.getElementById("set_policy").addEventListener("click", (ev) => {
    document.getElementById("apply_text").hidden = false;
    chrome.runtime.sendMessage({"classify_all": true}, (msg) => {
        setStaticLocaleText("apply_text", "currentCookieEnforceMsg");
        console.log(`Process completed with message: ${msg}.`);

        // close once done
        //chrome.tabs.getCurrent(function(tab) {
        //    chrome.tabs.remove(tab.id, () => {});
        //})
    });
});

// consent checkbox
histCheckbox.addEventListener("click", (ev) => {
    setStorageValue(histCheckbox.checked, chrome.storage.sync, "cblk_hconsent");
});
