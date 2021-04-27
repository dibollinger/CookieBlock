// Author: Dino Bollinger
// License: MIT

const addText = chrome.i18n.getMessage("popupButtonAdd");
const removeText = chrome.i18n.getMessage("popupButtonRemove");

const ignoredPages = /^(view-source:|moz-extension:|about:|chrome-extension:|chrome:)/;

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
    console.error(`An error occurred: ${error}`);
    document.getElementById("desc-box").hidden = true;
    let errorBox = document.getElementById("error-box");
    errorBox.hidden = false;
    errorBox.textContent = msg;
}


/**
 * Updates the "Add Exception" button when the popup is opened.
 * Disables the button if on a browser-internal page. Changes the text if exception already present.
 * Also performs localization
 */
const popupSetup = async function() {

    setStaticLocaleText("popup-title", "extensionName");
    setStaticLocaleText("pause-desc", "pauseCookieRemoval");
    setStaticLocaleText("desc-box", "popupText");
    setStaticLocaleText("options", "popupButtonOptions");

    let pauseState = await getStorageValue(chrome.storage.local, "cblk_pause");
    document.getElementById("pause-check").checked = pauseState;

    let exceptionButton = document.getElementById("add-exception");

    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        let currentURL = tabs[0].url;
        exceptionButton.textContent = addText;
        if (currentURL.match(ignoredPages)){
            exceptionButton.disabled = true;
            exceptionButton.style.opacity = "0.5";
        } else {
            let sanitizedDomain = urlToUniformDomain(new URL(currentURL).hostname);
            if (sanitizedDomain) {
                let exglobal = await getStorageValue(chrome.storage.sync, "cblk_exglobal");
                if (exglobal.includes(sanitizedDomain)){
                    exceptionButton.textContent = removeText;
                }
            }
        }
    });
};


/**
 * Add the exception on click and update the button text once done.
 */
const addGlobalException = async function() {
    hideErrorBox();
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        let currentURL = tabs[0].url

        // ignore the following types of pages
        if (currentURL.match(ignoredPages)){
            console.warn("Tried to add an exception to an invalid URL.")
            return;
        }

        let potentialErrMsg = chrome.i18n.getMessage("popupErrorTextGeneric");
        let sanitizedDomain = urlToUniformDomain(new URL(currentURL).hostname);
        try {
            let domainList = await getStorageValue(chrome.storage.sync, "cblk_exglobal");
            if (domainList.includes(sanitizedDomain)){
                potentialErrMsg = chrome.i18n.getMessage("popupErrorTextRemove");
                let index = domainList.indexOf(sanitizedDomain);
                if (index > -1) {
                    domainList.splice(index, 1);
                } else {
                    throw new Error("Could somehow not find the domain in the array?!");
                }
                document.getElementById("add-exception").textContent = addText;
            } else {
                potentialErrMsg = chrome.i18n.getMessage("popupErrorTextAdd");
                domainList.push(sanitizedDomain);
                document.getElementById("add-exception").textContent = removeText;
            }
            await setStorageValue(domainList, chrome.storage.sync, "cblk_exglobal");
        } catch (error) {
            showErrorBox(error, potentialErrMsg)
        }
    });
}

// pause checkbox
document.getElementById("pause-check").addEventListener("click", async () => {
    let pauseStatus = document.getElementById("pause-check").checked;
    await setStorageValue(pauseStatus, chrome.storage.local, "cblk_pause");
});

// On click, get the current tab URL and add it to the global exceptions
document.querySelector("#add-exception").addEventListener("click", addGlobalException);

// Open extension options page
document.querySelector("#options").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
    window.close();
});

// setup when popup is opened
document.addEventListener("DOMContentLoaded", popupSetup);