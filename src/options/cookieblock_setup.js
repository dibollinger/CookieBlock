// Author: Dino Bollinger
// License: MIT

// Script that controls the first-time setup of the extension

/**
 * Function that contains the localization text assignments.
 */
 const setupLocalization = function () {
    setStaticLocaleText("init_title", "extensionName");
    setStaticLocaleText("init_subtitle", "firstTimeSubtitle");

    setStaticLocaleText("general-options-legend", "headerAdditionalOptions");
    setStaticLocaleText("general-options-desc", "additionalOptionsDesc");

    setStaticLocaleText("history-consent-title", "historyConsentTitle");
    setStaticLocaleText("history-consent-desc", "historyConsentDesc");

    setStaticLocaleText("setup_greet", "firstTimeGreeting");
    setStaticLocaleText("setup_desc1","firstTimeDescPG1");
    setStaticLocaleText("setup_desc2","firstTimeDescPG2");
    setStaticLocaleText("setup_desc3","firstTimeDescPG3");

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

    setStaticLocaleText("pause_title", "pauseCookieRemoval");
    setStaticLocaleText("pause_desc", "pauseDescription");

    setStaticLocaleText("classify_title", "currentCookieEnforceTitle");
    setStaticLocaleText("classify_desc", "currentCookieEnforceDescriptionSetup");
    setStaticLocaleText("set_policy","buttonExitSetup");

}

/**
 * This function is executed when opening the first time setup.
 */
const setupInitPage = async function() {

    setupLocalization();

    document.getElementById("nec_checkbox").checked = true;
    document.getElementById("func_checkbox").checked = false;
    document.getElementById("anal_checkbox").checked = false;
    document.getElementById("advert_checkbox").checked = false;
    document.getElementById("pause_checkbox").checked = false;
    document.getElementById("history-consent-checkbox").checked = false;

    // pause stuff
    document.getElementById("pause-div").hidden = !enableExtraOptions;
}

document.addEventListener("DOMContentLoaded", setupInitPage);

/**
 * Log the storage area that changed, then for each item changed,
 * log its old value and its new value.
 * @param {Object} changes Object containing the storage changes.
 * @param {String} area String for the storage area.
 */
 const updateSelectionOnChange = function(changes, area) {
    let changedItems = Object.keys(changes);
    if (area === "sync") {
        if (changedItems.includes("cblk_userpolicy")) {
            newPolicy = changes["cblk_userpolicy"].newValue;
            document.getElementById("nec_checkbox").checked = newPolicy[0];
            document.getElementById("func_checkbox").checked = newPolicy[1];
            document.getElementById("anal_checkbox").checked = newPolicy[2];
            document.getElementById("advert_checkbox").checked = newPolicy[3];

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
        chrome.tabs.getCurrent(function(tab) {
            chrome.tabs.remove(tab.id, () => {});
        })
    });
});

// pause checkbox
const pauseCheckbox = document.getElementById("pause_checkbox");
pauseCheckbox.addEventListener("click", (ev) => {
    setStorageValue(pauseCheckbox.checked, chrome.storage.local, "cblk_pause");
});

// consent checkbox
const histCheckbox = document.getElementById("history-consent-checkbox");
histCheckbox.addEventListener("click", (ev) => {
    setStorageValue(histCheckbox.checked, chrome.storage.sync, "cblk_hconsent");
});
