//-------------------------------------------------------------------------------
/*
Copyright (C) 2021 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------


const categories = ["classOptionEmpty", "classOption0", "classOption1", "classOption2", "classOption3"];
var cookieHistory = undefined;
const placeholderListItem = document.getElementById("li-placeholder");

const domainListElem = document.getElementById("domain-list");

const sentinelTimestamp = 9999999999999;

const updateLabel = function(cookie, dropdownElement) {
    dropdownElement.style.color = "black";
    dropdownElement.style.opacity = "100%";
    cookie.current_label = dropdownElement.value;
    cookie.label_ts = sentinelTimestamp;

    chrome.runtime.sendMessage({"update_label": {
        "name" : cookie.name,
        "domain": cookie.domain,
        "path": cookie.path,
        "current_label": parseInt(dropdownElement.value),
        "label_ts": sentinelTimestamp
    }}, (msg) => {
        console.info(msg.response);
    });
}

const constructCookieListEntry = function(cookies) {
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
        if (c.label_ts < sentinelTimestamp){
            selection.style.color = "gray";
            selection.style.opacity = "80%";
        } else {
            selection.style.color = "black";
            selection.style.opacity = "100%";
        }

        for (let i = 0; i < categories.length; i++){
            let option = document.createElement("option");
            option.value = i - 1;
            if (c.current_label === i - 1) {
                option.selected = true;
            }
            option.textContent = chrome.i18n.getMessage(categories[i]);
            selection.add(option);
        }
        selection.addEventListener("change", (event) => { updateLabel(c, event.target); });
        subListItem.appendChild(selection);

        let button = document.createElement("button");
        button.className = "item-button";
        button.textContent = chrome.i18n.getMessage("configButtonRemove");;
        subListItem.appendChild(button);

        subList.appendChild(subListItem);
    }
    domainCompanionEntry.appendChild(subList);

    return domainCompanionEntry;
}


const hideToggle = function(elem) {
    if (elem.style.display === "none") {
        elem.style.display = "";
    } else {
        elem.style.display = "none";

    }
}

const changeExceptionStatus = async function(domain, selectText) {
    let domainList = await getStorageValue(chrome.storage.sync, "cblk_exglobal");
    if (selectText === "true") {
        if (!domainList.includes(domain)){
            domainList.push(domain);
            setStorageValue(domainList, chrome.storage.sync, "cblk_exglobal");
        }
    } else if (selectText === "false") {
        if (domainList.includes(domain)){
            let index = domainList.indexOf(domain);
            domainList.splice(index, 1);
            setStorageValue(domainList, chrome.storage.sync, "cblk_exglobal");
        }
    } else {
        console.error(`Javascript is being stupid: ${selectText}`)
    }
}

const constructDomainListEntry = function(domain, path, cookies) {

    // First construct the domain entry
    let listEntry = document.createElement("li");
    let domainDiv = document.createElement("div");
    domainDiv.className = "domain-entry";
    domainDiv.style.fontWeight = "bold";
    domainDiv.textContent = domain + path;

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
    selection.addEventListener("change", (event) => { changeExceptionStatus(domain, event.target.value) });
    (async () => {
        let domainList = await getStorageValue(chrome.storage.sync, "cblk_exglobal");
        if (domainList.includes(domain)){
            optionTrue.selected = true;
        } else {
            optionFalse.selected = true;
        }
    })();

    let button = document.createElement("button");
    button.className = "item-button";
    button.textContent = chrome.i18n.getMessage("configButtonRemoveAll");;
    //button.addEventListener("click", () => { removeItemFromList(addDomain, node, storageID) });

    listEntry.appendChild(domainDiv);
    listEntry.appendChild(selection);
    listEntry.appendChild(button);

    domainListElem.appendChild(listEntry);

    let placeholder = document.createElement("li");
    placeholder.style.display = "none";
    domainListElem.appendChild(placeholder);

    let objectCache = { "placeholder": placeholder, "listEntry": null };
    domainDiv.addEventListener("click", () => {
        if (!objectCache.listEntry) {
            objectCache.listEntry = constructCookieListEntry(cookies);
        }

        if (domainListElem.contains(objectCache.listEntry)) {
            objectCache.listEntry.replaceWith(objectCache.placeholder);
        } else {
            objectCache.placeholder.replaceWith(objectCache.listEntry);
        }
    });
}

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
                    let sanitizedDomain = d;
                    for (let path of Object.keys(cookieHistory[d])){
                        constructDomainListEntry(sanitizedDomain, path, cookieHistory[d][path]);
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
