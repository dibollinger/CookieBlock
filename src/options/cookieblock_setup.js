// Author: Dino Bollinger
// License: MIT

// Script that controls the first-time setup of the extension

/**
 * Toggle the debug state
 */
const toggleDebug = async function() {
    let debugStatus = document.getElementById("debug_checkbox").checked;
    await setDebugState(debugStatus);
}

/**
 * Function that contains the localization text assignments.
 */
 const setupLocalization = function () {
    const setLocText = (id, loc) => {
        document.getElementById(id).textContent = browser.i18n.getMessage(loc);
    };

    setLocText("init_title", "extensionName");
    setLocText("init_subtitle", "firstTimeSubtitle");

    setLocText("setup_greet", "firstTimeGreeting");
    setLocText("setup_desc","firstTimeDesc");

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

    setLocText("debug_title", "enableDebugMode");
    setLocText("debug_desc", "debugDescription");

    setLocText("set_policy","buttonExitSetup");
}

/**
 * This function is executed when opening the first time setup.
 */
const setupInitPage = async function() {

    setupLocalization();

    let policy = await getUserPolicy();
    document.getElementById("nec_checkbox").checked = policy[0];
    document.getElementById("func_checkbox").checked = policy[1];
    document.getElementById("anal_checkbox").checked = policy[2];
    document.getElementById("advert_checkbox").checked = policy[3];

    let debugState = await getDebugState();
    document.getElementById("debug_checkbox").checked = debugState;
}

/**
 * Button to update the settings.
 */
const updateAndClassify = async function() {
    let cN = document.getElementById("nec_checkbox").checked;
    let cF = document.getElementById("func_checkbox").checked;
    let cAn = document.getElementById("anal_checkbox").checked;
    let cAd = document.getElementById("advert_checkbox").checked;
    await setUserPolicy([cN, cF, cAn, cAd]);

    let sending = browser.runtime.sendMessage({"classify_all": true});
    sending.then((msg) => {console.log("Process completed.")});

    // close tab
    browser.tabs.getCurrent(function(tab) {
        browser.tabs.remove(tab.id, () => {});
    });
}

// Listeners
document.addEventListener("DOMContentLoaded", setupInitPage);
document.querySelector("#debug_checkbox").addEventListener("click", toggleDebug);
document.querySelector("#set_policy").addEventListener("click", updateAndClassify);
