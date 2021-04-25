// Author: Dino Bollinger
// License: MIT

// Script that controls the first-time setup of the extension

/**
 * Toggle the pause state
 */
const togglePause = async function() {
    let pauseStatus = document.getElementById("pause_checkbox").checked;
    await setPauseState(pauseStatus);
}

/**
 * Function that contains the localization text assignments.
 */
 const setupLocalization = function () {
    setStaticLocaleText("init_title", "extensionName");
    setStaticLocaleText("init_subtitle", "firstTimeSubtitle");

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

    // pause stuff
    document.getElementById("pause-div").hidden = isReleaseVersion;
}

/**
 * Button to update the settings.
 */
const updateAndClassify = async function() {

    document.getElementById("apply_text").hidden = false;
    setStaticLocaleText("apply_text", "currentCookieProgressMsg");
    let sending = browser.runtime.sendMessage({"classify_all": true});
    sending.then((msg) => {
        console.log(`Process completed with message: ${msg}.`);
        setStaticLocaleText("apply_text", "currentCookieEnforceMsg");
    });

    await sending;

    // close once done
    browser.tabs.getCurrent(function(tab) {
        browser.tabs.remove(tab.id, () => {});
    })
}

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
browser.storage.onChanged.addListener(updateSelectionOnChange);

/**
 * Helper for adding click listeners.
 */
 const addPrefClickListener = function (checkboxID, idx) {
    let cb = document.getElementById(checkboxID);
    cb.addEventListener("click", async (event) => {
        policy = await getUserPolicy();
        policy[idx] = cb.checked;
        setUserPolicy(policy);
    });
}

addPrefClickListener("nec_checkbox", 0);
addPrefClickListener("func_checkbox", 1);
addPrefClickListener("anal_checkbox", 2);
addPrefClickListener("advert_checkbox", 3);


// Listeners
document.addEventListener("DOMContentLoaded", setupInitPage);
document.querySelector("#pause_checkbox").addEventListener("click", togglePause);
document.querySelector("#set_policy").addEventListener("click", updateAndClassify);
