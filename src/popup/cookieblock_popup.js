//-------------------------------------------------------------------------------
/*
Copyright (C) 2021-2022 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------

const pauseCheckbox = document.getElementById("pause-check");
const configButton = document.getElementById("config");
const exceptionButton = document.getElementById("add-exception");
const popupLogo = document.getElementById("popup-logo");

const classifyButton = document.getElementById("classify");

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
    setStaticLocaleText("pause-checkbox", "pauseCookieRemoval");
    setStaticLocaleText("pause-checkbox-tooltip", "pauseDescription");
    setStaticLocaleText("desc-box", "popupText");
    setStaticLocaleText("config", "popupButtonConfig");
    setStaticLocaleText("add-exception-tooltip", "popupButtonAddTooltip");
    setStaticLocaleText("options", "popupButtonOptions");
    setStaticLocaleText("classify", "popupButtonClassify");

    if (await getStorageValue(chrome.storage.sync, "cblk_hconsent")){
        chrome.runtime.sendMessage({"get_popup_stats": true}, (msg) => {
            let [blocked_today, cookies_today, blocked_total, cookies_total] = msg.response;
            
            cookies_today = Math.max(cookies_today, 1);
            cookies_total = Math.max(cookies_total, 1);
    
            setStaticLocaleText("blocked-stats", "popupStats",
                                 [blocked_today,
                                  Math.round(100*blocked_today/cookies_today),
                                  blocked_total,
                                  Math.round(100*blocked_total/cookies_total)]);
        });
    } else {
        setStaticLocaleText("blocked-stats", "popupStatsDisabled");
    }

    if (!await getStorageValue(chrome.storage.sync, "cblk_hconsent")){
        configButton.disabled = true;
        configButton.style.opacity = "0.5";
    }

    pauseCheckbox.checked = await getStorageValue(chrome.storage.local, "cblk_pause");
    popupLogo.src = pauseCheckbox.checked ? "/icons/gs-cookieblock-96.png" : "/icons/cookieblock-96.png";

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

/**
 * Update the toggles relevant to the setup page, based on changes in the local and sync storage.
 * @param {Object} changes Object containing the changes.
 * @param {Object} area Storage area that changed
 */
 const updateSelectionOnChange = function(changes, area) {
    let changedItems = Object.keys(changes);
    if (area === "local") {
        if (changedItems.includes("cblk_pause")){
            pauseCheckbox.checked = changes["cblk_pause"].newValue;
        }
    }
}
chrome.storage.onChanged.addListener(updateSelectionOnChange);


// pause checkbox
pauseCheckbox.addEventListener("click", async () => {
    let pauseStatus = pauseCheckbox.checked;
    setStorageValue(pauseStatus, chrome.storage.local, "cblk_pause");
    chrome.browserAction.setIcon(pauseStatus ? grayScaleIcon : defaultIcon);
    popupLogo.src = pauseStatus ? "/icons/gs-cookieblock-96.png" : "/icons/cookieblock-96.png";
});

// On click, get the current tab URL and add it to the global exceptions
document.querySelector("#add-exception").addEventListener("click", addGlobalException);

// Open extension options page
document.querySelector("#config").addEventListener("click", () => {
    chrome.tabs.create({"active": true, "url": "/options/cookieblock_cconfig.html"});
    window.close();
});

// Open extension options page
document.querySelector("#options").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
    window.close();
});

// setup when popup is opened
document.addEventListener("DOMContentLoaded", popupSetup);


// classify all cookies button
classifyButton.addEventListener("click", async () => {
    chrome.runtime.sendMessage({"classify_all": true}, (msg) => {
        if (chrome.runtime.lastError){
            console.error(chrome.runtime.lastError);
            setStaticLocaleText("error-box", "popupButtonClassify_ERROR")
            document.getElementById("error-box").hidden = false;
            document.getElementById("desc-box").hidden = true;
        } else{
            console.debug(msg.response);
            setStaticLocaleText("desc-box", "popupButtonClassify_OK")
        }
        classifyButton.disabled = true;
    });
});