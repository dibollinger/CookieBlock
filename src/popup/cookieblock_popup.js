// Author: Dino Bollinger
// License: MIT

import { urlToUniformDomain } from '/modules/utils.js';

const addText = "Add Site Exception";
const removeText = "Remove Site Exception";

/**
 * Hide the error text message.
 */
const hideErrorBox = function() {
    document.getElementById("desc-box").hidden = false;
    document.getElementById("error-box").hidden = true;
}

/**
 * Display the error text box.
 * @param {String} error Internal error.
 * @param {String} msg Message to show.
 */
const showErrorBox = function(error, msg) {
    document.getElementById("desc-box").hidden = true;
    let errorBox = document.getElementById("error-box");
    errorBox.hidden = false;
    errorBox.textContent = msg;
    console.error(`An error occurred: ${error}`);
}

/**
 * Updates the "Add Exception" button when the popup is opened.
 * Disables the button if on a browser-internal page. Changes the text if exception already present.
 */
const popupSetup = function() {

    let exceptionButton = document.getElementById("add-exception");

    browser.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        let currentURL = tabs[0].url
        if (currentURL.match(/^(moz-extension:|about:|chrome-extension:|chrome:)/)){
            exceptionButton.disabled = true;
            exceptionButton.style.opacity = "0.5";
        }

        let sanitizedDomain = urlToUniformDomain(new URL(currentURL).hostname);

        if (sanitizedDomain){
            browser.storage.sync.get("cblk_exglobal").then((r) => {
                console.assert(r["cblk_exglobal"] !== undefined, "Global exception array was not initialized!");
                if (r["cblk_exglobal"].includes(sanitizedDomain)){
                    exceptionButton.textContent = removeText;
                } else {
                    exceptionButton.textContent = addText;
                }
            });
        }
    });
};


/**
 * Add the exception on click and update the button text once done.
 */
const addGlobalException = function() {
    hideErrorBox();
    browser.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        let currentURL = tabs[0].url

        // safety
        if (currentURL.match(/^(moz-extension:|about:|chrome-extension:|chrome:)/)){
            return;
        }

        let sanitizedDomain = urlToUniformDomain(new URL(currentURL).hostname);
        browser.storage.sync.get("cblk_exglobal").then((r) => {
            let domain_list = r["cblk_exglobal"];
            console.assert(domain_list !== undefined, "Global exception array was not initialized!");

            if (domain_list.includes(sanitizedDomain)){
                let index = domain_list.indexOf(sanitizedDomain);
                if (index > -1) {
                    domain_list.splice(index, 1);
                } else {
                    console.error("Could somehow not find the domain in the array?!")
                }
                browser.storage.sync.set({"cblk_exglobal": domain_list}).then(
                    () => document.getElementById("add-exception").textContent = addText
                    , (error) => showErrorBox(error, "Removing Site Exception Failed!")
                );
            } else {
                domain_list.push(sanitizedDomain);
                browser.storage.sync.set({"cblk_exglobal": domain_list}).then(
                    () => document.getElementById("add-exception").textContent = removeText
                    , (error) => showErrorBox(error, "Adding Site Exception Failed!")
                );
            }
        }, (error) => showErrorBox(error, "Something went wrong!"));
    });
}

// On click, get the current tab URL and add it to the global exceptions
document.querySelector("#add-exception").addEventListener("click", addGlobalException);

// Open extension options page
document.querySelector("#options").addEventListener("click", () => {
    browser.runtime.openOptionsPage();
    window.close();
});

// setup when popup is opened
document.addEventListener("DOMContentLoaded", popupSetup);