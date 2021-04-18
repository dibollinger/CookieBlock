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

document.querySelector("#debug_checkbox").addEventListener("click", toggleDebug);
document.querySelector("#set_policy").addEventListener("click", updateAndClassify);
