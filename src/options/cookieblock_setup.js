// Author: Dino Bollinger
// License: MIT

// Script that controls the first-time setup of the extension

/**
 * Toggle the debug state
 */
const toggleDebug = function() {
    let debugStatus = document.getElementById("debug_checkbox").checked;
    await setDebugState(debugStatus);
}

/**
 * Button to update the settings.
 */
const updateAndClassify = async function() {
    let cN = true;
    //let cN = document.getElementById("nec_checkbox").checked;
    let cF = document.getElementById("func_checkbox").checked;
    let cAn = document.getElementById("anal_checkbox").checked;
    let cAd = document.getElementById("advert_checkbox").checked;
    await setUserPolicy([cN, cF, cAn, cAd]);

    // Disabled for now
    /*let allCookies = await browser.cookies.getAll({});
    for (let cookieDat of allCookies) {
        let ckey = cookieDat.name + ";" + cookieDat.domain + ";" + cookieDat.path;
        // TODO: Need to pass a message to the background script
        //enforcePolicy(ckey, cookieDat);
    }*/

    // close tab
    browser.tabs.getCurrent(function(tab) {
        browser.tabs.remove(tab.id, () => {});
    });
}

document.querySelector("#debug_checkbox").addEventListener("click", toggleDebug);
document.querySelector("#set_policy").addEventListener("click", updateAndClassify);
