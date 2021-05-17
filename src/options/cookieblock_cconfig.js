//-------------------------------------------------------------------------------
/*
Copyright (C) 2021 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------


const categories = ["classOptionEmpty", "classOption0", "classOption1", "classOption2", "classOption3"];

const constructCookieListEntry = function(cookies, listID) {
    let domainCompanionEntry = document.createElement("li");
    let subList = document.createElement("ul");
    for (let c of Object.values(cookies)) {
        let subListItem = document.createElement("li");

        let domainDiv = document.createElement("div");
        domainDiv.className = "cookie-name";
        domainDiv.textContent = c.name;
        subListItem.appendChild(domainDiv);

        let selection = document.createElement("select");
        selection.className = "cat-selector";

        for (let i = 0; i < categories.length; i++){
            let option = document.createElement("option");
            option.value = i - 1;
            if (c.current_label === i - 1) {
                option.selected = true;
            }
            option.textContent = chrome.i18n.getMessage(categories[i]);
            selection.add(option);
        }
        subListItem.appendChild(selection);

        let button = document.createElement("button");
        button.className = "item-button";
        button.textContent = chrome.i18n.getMessage("configButtonRemove");;
        subListItem.appendChild(button);

        subList.appendChild(subListItem);
    }
    domainCompanionEntry.appendChild(subList);
    document.getElementById(listID).appendChild(domainCompanionEntry);
    domainCompanionEntry.style.display = "none";

    return domainCompanionEntry;
}


const hideToggle = function(elem) {
    if (elem.style.display === "none") {
        elem.style.display = "";
    } else {
        elem.style.display = "none";

    }
}

const constructDomainListEntry = function(domainPath, cookies, listID) {

    // First construct the domain entry
    let listEntry = document.createElement("li");
    let domainDiv = document.createElement("div");
    domainDiv.className = "domain-entry";
    domainDiv.style.fontWeight = "bold";
    domainDiv.textContent = domainPath;

    let optionFalse = document.createElement("option");
    optionFalse.value = false;
    optionFalse.textContent = chrome.i18n.getMessage("configDropdownFalse")

    let optionTrue = document.createElement("option");
    optionTrue.value = true;
    optionTrue.textContent = chrome.i18n.getMessage("configDropdownTrue");

    let selection = document.createElement("select");
    selection.className = "exception-selector";
    selection.add(optionFalse);
    selection.add(optionTrue);
    //selection.addEventListener("click", () => { removeItemFromList(addDomain, node, storageID) });

    let button = document.createElement("button");
    button.className = "item-button";
    button.textContent = chrome.i18n.getMessage("configButtonRemoveAll");;
    //button.addEventListener("click", () => { removeItemFromList(addDomain, node, storageID) });

    listEntry.appendChild(domainDiv);
    listEntry.appendChild(selection);
    listEntry.appendChild(button);
    document.getElementById(listID).appendChild(listEntry);

    let companionEntry = constructCookieListEntry(cookies, listID);
    domainDiv.addEventListener("click", () => { hideToggle(companionEntry) });
}

var cookieHistory = undefined;

const placeholderListItem = document.getElementById("li-placeholder");

const setupConfigPage = function() {
    // Text
    setStaticLocaleText("cconfig-title", "extensionName");
    setStaticLocaleText("cconfig-subtitle", "cookieConfigSubtitle");
    setStaticLocaleText("cconfig-desc-title", "cookieConfigDescTitle");
    setStaticLocaleText("cconfig-desc-pg1", "cookieConfigDescPG1");
    setStaticLocaleText("cconfig-desc-pg2", "cookieConfigDescPG2");
    setStaticLocaleText("cconfig-list-title", "cookieConfigListTitle");
    setStaticLocaleText("cconfig-expand-desc", "configExpandDesc");
    setStaticLocaleText("export-button", "configExportButton");


    // Request a snapshot of the entire cookie history
    chrome.runtime.sendMessage({"open_json": "full"}, (msg) => {
        if (msg.lastError) {
            console.error("Could not open the JSON file!");
        } else {
            cookieHistory = msg.response;
        }

        if (cookieHistory !== undefined && cookieHistory.constructor === Object) {
            let allDomains = Object.keys(cookieHistory);
            if (allDomains.length > 0){
                placeholderListItem.style.display = "none";
                let sortedDomains = Array.from(allDomains).sort();
                for (let d of sortedDomains) {
                    let sanitizedDomain = urlToUniformDomain(d);
                    for (let path of Object.keys(cookieHistory[d])){
                        constructDomainListEntry(sanitizedDomain + path, cookieHistory[d][path], "domain-list");
                    }
                }
            } else {
                placeholderListItem.style.display = "";
                setStaticLocaleText("li-placeholder", "configNoCookies");
            }
        } else {
            placeholderListItem.style.display = "";
            setStaticLocaleText("li-placeholder", "configLoadError");
            placeholderListItem.style.color = "red";
        }

    });
}


document.addEventListener("DOMContentLoaded", setupConfigPage);
