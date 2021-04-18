// Author: Dino Bollinger
// License: MIT

const addText = "Add Site Exception";
const removeText = "Remove Site Exception";

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
 */
const popupSetup = async function() {

    let exceptionButton = document.getElementById("add-exception");

    browser.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        let currentURL = tabs[0].url
        if (currentURL.match(ignoredPages)){
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
const addGlobalException = async function() {
    hideErrorBox();
    browser.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        let currentURL = tabs[0].url

        // ignore the following types of pages
        if (currentURL.match(ignoredPages)){
            console.warn("Tried to add an exception to an invalid URL.")
            return;
        }

        let potentialErrMsg = "Something went wrong!";
        let sanitizedDomain = urlToUniformDomain(new URL(currentURL).hostname);
        try {
            let domainList = await getExceptionsList("cblk_exglobal");
            if (domainList.includes(sanitizedDomain)){
                potentialErrMsg = "Removing exception failed!";
                let index = domainList.indexOf(sanitizedDomain);
                if (index > -1) {
                    domainList.splice(index, 1);
                } else {
                    throw new Error("Could somehow not find the domain in the array?!");
                }
                await browser.storage.sync.set({"cblk_exglobal": domainList});
                document.getElementById("add-exception").textContent = addText;
            } else {
                potentialErrMsg = "Adding exception failed!";
                domainList.push(sanitizedDomain);
                await browser.storage.sync.set({"cblk_exglobal": domainList});
                document.getElementById("add-exception").textContent = removeText;
            }
        } catch (error) {
            showErrorBox(error, potentialErrMsg)
        }
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