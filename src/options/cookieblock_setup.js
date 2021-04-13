// Author: Dino Bollinger
// License: MIT

// Script that controls the first-time setup of the extension


const enableDebugging = function() {
    let debugStatus = document.getElementById("debug_checkbox").checked;
    console.log("Debug Status: " + debugStatus);
    browser.storage.local.set({ "cblk_debug": debugStatus});
}

const updateAndClassify = function() {
    console.log("Update and Classify Executed");

    let rejectFunctional = document.getElementById("func_checkbox").checked;
    let rejectAnalytical = document.getElementById("anal_checkbox").checked;
    let rejectAdvertising = document.getElementById("advert_checkbox").checked;

    browser.storage.sync.set({
        cblk_userpolicy: [false, rejectFunctional, rejectAnalytical, rejectAdvertising]
    }).then( () => {
        // Disabled for now
        /*let allCookies = browser.cookies.getAll({});

        allCookies.then((cookies) => {
          for (let cookieDat of cookies){
            let ckey = cookieDat.name + ";" + cookieDat.domain + ";" + cookieDat.firstPartyDomain + ";" + cookieDat.path;

            enforcePolicy(ckey, cookieDat);
          }
        });*/
    });
    browser.tabs.getCurrent(function(tab) {
        browser.tabs.remove(tab.id, function() { });
    });
}

document.querySelector("#debug_checkbox").addEventListener("click", enableDebugging);
document.querySelector("#set_policy").addEventListener("click", updateAndClassify);
