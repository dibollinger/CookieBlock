// Author: Dino Bollinger
// License: MIT
// Script that controls the preferences section of the extension

const onError = function(error) {
    console.error(`error: ${error}`);
}

// to be executed when opening the preferences screen
const restoreOptions = function() {

    function restoreExceptionList(storageID, listID){
        let fexceptions = browser.storage.sync.get(storageID);
        fexceptions.then((r) => {
            let storedExc = r[storageID]
            if (storedExc !== undefined) {
                let numEntries = storedExc.length;
                for (let i = 0; i < numEntries; i++) {
                    appendExceptionToList(storedExc[i], listID, storageID);
                }
            }
        }, onError);
    }

    browser.storage.sync.get("cblk_userpolicy").then((r) => {
        console.assert(r.cblk_userpolicy !== undefined, "User policy is undefined!")
        document.getElementById("func_checkbox").checked = r.cblk_userpolicy[1];
        document.getElementById("anal_checkbox").checked = r.cblk_userpolicy[2];
        document.getElementById("advert_checkbox").checked = r.cblk_userpolicy[3];
    }, onError);

    restoreExceptionList("cblk_exglobal", "website_exceptions");
    restoreExceptionList("cblk_exfunc", "functional_exceptions");
    restoreExceptionList("cblk_exanal", "analytics_exceptions");
    restoreExceptionList("cblk_exadvert", "advertising_exceptions");

    browser.storage.local.get("cblk_debug").then((r) => {
        console.assert(r.cblk_debug !== undefined, "Debug mode toggle is undefined!")
        document.getElementById("debug_checkbox").checked = r["cblk_debug"] || false;
    }, onError);


    let counts = browser.storage.local.get(["cblk_counter"]);
    counts.then((r) => {
        document.getElementById("num_necessary").textContent += `${r["cblk_counter"][0] || 0}    Necessary`
        document.getElementById("num_functional").textContent += `${r["cblk_counter"][1] || 0}    Functional`
        document.getElementById("num_analytics").textContent += `${r["cblk_counter"][2] || 0}    Performance/Analytics`
        document.getElementById("num_advertising").textContent += `${r["cblk_counter"][3] || 0}    Advertisement/Tracking`
        document.getElementById("num_uncat").textContent += `${r["cblk_counter"][4] || 0}    Skipped`
    }, onError);
}


// user policy is a fixed-size array of 4 booleans (necessary is always false)
function updateUserPolicy(e) {
    console.log("Updated Policy")
    let rejectFunctional = document.getElementById("func_checkbox").checked;
    let rejectAnalytical = document.getElementById("anal_checkbox").checked;
    let rejectAdvertising = document.getElementById("advert_checkbox").checked;

    browser.storage.sync.set({
        cblk_userpolicy: [false, rejectFunctional, rejectAnalytical, rejectAdvertising]
    });
    document.getElementById("submit_text").hidden = false;
}

// remove an item from a dynamically generated exception list
function removeListItem(listItem, storageID, removed_domain) {
    let exlist = listItem.parentElement;

    // remove the internal stored string
    let fexceptions = browser.storage.sync.get(storageID);
    fexceptions.then((r) => {
        let domain_list = r[storageID];
        if (domain_list !== undefined) {
            let index = domain_list.indexOf(removed_domain);
            domain_list.splice(index, 1)

            let to_store = {};
            to_store[storageID] = domain_list;
            browser.storage.sync.set(to_store);
        }
        else {
            console.error(`Error: Domain list for '${storageID}' empty.`)
        }
    }, onError);

    // finally, remove the element from the visible list
    exlist.removeChild(listItem);
}

// append an item to a dynamically generated exception list
function appendExceptionToList(exception_domain, list_id, storageID) {
    let node = document.createElement("li")

    // button has the remove event set up directly
    let button = document.createElement("button");
    button.textContent = "X";
    button.addEventListener("click", () => {removeListItem(node, storageID, exception_domain)});

    let textdiv = document.createElement("div");
    let textnode = document.createTextNode(exception_domain);

    textdiv.appendChild(textnode);
    textdiv.class = "text_content";

    node.appendChild(button);
    node.appendChild(textnode);
    document.getElementById(list_id).appendChild(node);
}

//
function handleExceptionSubmit(input_id, storageID, listID){
    let iElem = document.querySelector(input_id);

    if (iElem.value != null && iElem.value != "")
    {
        let domainOrURL = (' ' + iElem.value).slice(1);
        let sanitizedDomain = undefined;
        try {
            sanitizedDomain = urlToUniformDomain(new URL(domainOrURL).hostname);
        } catch(error) {
            sanitizedDomain = urlToUniformDomain(domainOrURL);
        }

        appendExceptionToList(sanitizedDomain, listID, storageID);

        let fexceptions = browser.storage.sync.get(storageID);
        fexceptions.then((r) => {
            let domain_list = r[storageID];

            if (domain_list === undefined) {
                domain_list = [];
            }
            domain_list.push(domainOrURL);

            let to_store = {};
            to_store[storageID] = domain_list;
            browser.storage.sync.set(to_store);
        }, (error) => {
            console.error(`An Error occurred ${error}`);
        });

        // empty the input box
        iElem.value = "";
    }
}

const enableDebugging = function() {
    let debugStatus = document.getElementById("debug_checkbox").checked;
    console.log("Debug Status: " + debugStatus);
    browser.storage.local.set({ "cblk_debug": debugStatus});
}


/**
 * Runs the classification on all current browser cookies
 */
const classifyAllCurrentCookies = function() {
    console.log("Classified all current cookies");
    let allCookies = browser.cookies.getAll({});

    allCookies.then((cookies) => {
      for (let cookieDat of cookies){
        let ckey = cookieDat.name + ";" + cookieDat.domain + ";" + cookieDat.firstPartyDomain + ";" + cookieDat.path;

        enforcePolicy(ckey, cookieDat);

      }
    });
    document.getElementById("apply_text").hidden = false;
}


// Listeners
document.addEventListener("DOMContentLoaded", restoreOptions);
document.querySelector("#submit_prefs").addEventListener("click", updateUserPolicy);
document.querySelector("#debug_checkbox").addEventListener("click", enableDebugging);
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
