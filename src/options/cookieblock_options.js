// Author: Dino Bollinger
// License: MIT


/**
 * Remove an item from a dynamically generated exception list.
 * @param {String} listItem List item to be removed.
 * @param {String} storageID Extension storage id for exception list.
 * @param {String} removedDomain
 */
 const removeExceptionFromList = async function(removedDomain, listItem, storageID) {
    let exlist = listItem.parentElement;

    // remove the internal stored string (async with promise)
    domainList = await getExceptionsList(storageID);
    let index = domainList.indexOf(removedDomain);
    domainList.splice(index, 1)

    // update storage
    let to_store = {};
    to_store[storageID] = domainList;
    browser.storage.sync.set(to_store);

    // finally, remove the element from the visible list
    exlist.removeChild(listItem);
}


/**
 * Append an item to a dynamically generated exception list.
 * @param {String} exceptionDomain Domain to add an exception for.
 * @param {String} listID HTML List identity
 * @param {String} storageID Extension storage id for exception list.
 */
const appendExceptionToList = async function(exceptionDomain, listID, storageID) {
    let node = document.createElement("li")

    // button has the remove event set up directly
    let button = document.createElement("button");
    button.textContent = "x";
    button.addEventListener("click", () => { removeExceptionFromList(exceptionDomain, node, storageID) });

    let textdiv = document.createElement("div");
    let textnode = document.createTextNode(exceptionDomain);

    textdiv.appendChild(textnode);
    textdiv.class = "text_content";

    node.appendChild(button);
    node.appendChild(textnode);
    document.getElementById(listID).appendChild(node);
}



/**
 * Handle the mouse click event to submit a custom domain exception to the list.
 * @param {String} inputID    Identity of the input box.
 * @param {String} storageID  Storage identity for the exception list.
 * @param {String} listID     Identity of the list to append the exception to.
 */
const handleExceptionSubmit = async function(inputID, storageID, listID) {
    let iElem = document.querySelector(inputID);
    if (iElem.value != null && iElem.value != "")
    {
        let domainOrURL = (' ' + iElem.value).slice(1);
        let sanitizedDomain = undefined;
        try {
            sanitizedDomain = urlToUniformDomain(new URL(domainOrURL).hostname);
        } catch(error) {
            sanitizedDomain = urlToUniformDomain(domainOrURL);
        }

        let domain_list = await getExceptionsList(storageID);
        domain_list.push(domainOrURL);

        let to_store = {};
        to_store[storageID] = domain_list;
        browser.storage.sync.set(to_store);

        appendExceptionToList(sanitizedDomain, listID, storageID);

        // empty the input box
        iElem.value = "";
    }
}


/**
 * This function is executed when opening the settings page.
 */
const setupSettingsPage = async function() {
    let restoreExceptionList = async function (storageID, listID) {
        let storedExc = await getExceptionsList(storageID);
        let numEntries = storedExc.length;
        for (let i = 0; i < numEntries; i++) {
            appendExceptionToList(storedExc[i], listID, storageID);
        }
    }
    restoreExceptionList("cblk_exglobal", "website_exceptions");
    restoreExceptionList("cblk_exfunc", "functional_exceptions");
    restoreExceptionList("cblk_exanal", "analytics_exceptions");
    restoreExceptionList("cblk_exadvert", "advertising_exceptions");

    let policy = await getUserPolicy();
    document.getElementById("nec_checkbox").checked = policy[0];
    document.getElementById("func_checkbox").checked = policy[1];
    document.getElementById("anal_checkbox").checked = policy[2];
    document.getElementById("advert_checkbox").checked = policy[3];

    let debugState = await getDebugState();
    document.getElementById("debug_checkbox").checked = debugState;

    let stats = await getStatsCounter();
    document.getElementById("num_necessary").textContent += `${stats[0]} Necessary`
    document.getElementById("num_functional").textContent += `${stats[1]} Functional`
    document.getElementById("num_analytics").textContent += `${stats[2]} Performance/Analytics`
    document.getElementById("num_advertising").textContent += `${stats[3]} Advertisement/Tracking`
    document.getElementById("num_uncat").textContent += `${stats[4]} from Whitelist`
}


/**
 * The user policy is a fixed-size array of 4 booleans.
 * @param {Object} event Unused
 */
const updateUserPolicy = async function(event) {
    let cN = document.getElementById("nec_checkbox").checked;
    let cF = document.getElementById("func_checkbox").checked;
    let cAn = document.getElementById("anal_checkbox").checked;
    let cAd = document.getElementById("advert_checkbox").checked;

    browser.storage.sync.set( { "cblk_userpolicy": [cN, cF, cAn, cAd] } );
    document.getElementById("submit_text").hidden = false;
}

/**
 * Event for clicking the debug checkbox
 */
const toggleDebugging = async function() {
    let debugStatus = document.getElementById("debug_checkbox").checked;
    browser.storage.local.set({ "cblk_debug": debugStatus});
}

/**
 * Runs the classification on all current browser cookies
 */
const classifyAllCurrentCookies = async function() {
    let allCookies = await browser.cookies.getAll({});
    for (let cookieDat of allCookies){
        let ckey = cookieDat.name + ";" + cookieDat.domain + ";" + cookieDat.path;
        //TODO: Replace with a message event that is received by the background script.
        //enforcePolicy(ckey, cookieDat);
    }
    document.getElementById("apply_text").hidden = false;
}

/**
 * Log the storage area that changed, then for each item changed,
 * log its old value and its new value.
 * @param {Object} changes Object containing the storage changes.
 * @param {String} area String for the storage area.
 */
const logStorageChange = function(changes, area) {
    console.log("Change in storage area: " + area);

    let changedItems = Object.keys(changes);

    for (let item of changedItems) {
      console.log(item + " has changed:");
      console.log("Old value: ");
      console.log(changes[item].oldValue);
      console.log("New value: ");
      console.log(changes[item].newValue);
    }
}
browser.storage.onChanged.addListener(logStorageChange);

// Listeners
document.addEventListener("DOMContentLoaded", setupSettingsPage);

document.querySelector("#submit_prefs").addEventListener("click", updateUserPolicy);
document.querySelector("#debug_checkbox").addEventListener("click", toggleDebugging);
document.querySelector("#classify_all").addEventListener("click", classifyAllCurrentCookies);


document.querySelector("#website_excepts_submit").addEventListener("click", (e) => {
    e.preventDefault();
    handleExceptionSubmit("#website_excepts_input", "cblk_exglobal", "website_exceptions");
});

document.querySelector("#func_excepts_submit").addEventListener("click", (e) => {
    e.preventDefault();
    handleExceptionSubmit("#func_excepts_input", "cblk_exfunc", "functional_exceptions");
});

document.querySelector("#analytics_excepts_submit").addEventListener("click", (e) => {
    e.preventDefault();
    handleExceptionSubmit("#analytics_excepts_input", "cblk_exanal", "analytics_exceptions");
});

document.querySelector("#advert_excepts_submit").addEventListener("click", (e) => {
    e.preventDefault();
    handleExceptionSubmit("#advert_excepts_input", "cblk_exadvert", "advertising_exceptions");
});
