//-------------------------------------------------------------------------------
/*
Copyright (C) 2021-2022 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------


const categories = ["classOptionEmpty", "classOption0", "classOption1", "classOption2", "classOption3"];
var cookieHistory = undefined;
const domainListElem = document.getElementById("domain-list");
const sentinelTimestamp = 9999999999999;

const refreshButton = document.getElementById("refresh-button");
const exportButton = document.getElementById("export-button");

const buttonsArray = [];

const existsCookie = async function(cookie) {
    return new Promise((resolve, reject) => {
        chrome.cookies.get({
            "name": cookie.name,
            "url": "https://" + domainRemoveNoise(cookie.domain) + cookie.path,
            "storeId": cookie.storeId
        }, (result) => {
            resolve(result !== null);
        });
    });
}

const refreshButtons = async function() {
    for (let o of buttonsArray){
        if (await existsCookie(o.c)){
            o.b.textContent = chrome.i18n.getMessage("configButtonRemove");
        } else {
            o.b.textContent = chrome.i18n.getMessage("configButtonRestore");
        }
    }
}


const removeSingleCookie = async function(c) {
    return new Promise((resolve, reject) => {
        chrome.cookies.remove({
            "name": c.name,
            "url": "https://" + domainRemoveNoise(c.domain) + c.path,
            "storeId": c.storeId
        }, (remResultHTTPS) => {
            if (remResultHTTPS === null){
                chrome.cookies.remove({
                    "name": c.name,
                    "url": "http://" + domainRemoveNoise(c.domain) + c.path,
                    "storeId": c.storeId
                }, (remResultHTTP) => {
                    resolve(remResultHTTP !== null);
                });
            } else {
                resolve(true);
            }
        });
    });
}

const restoreSingleCookie = async function(c) {
    let lastUpdate = c.variable_data[c.variable_data.length - 1]

    let maybeExpiry;
    if ((! "expirationDate" in lastUpdate) || lastUpdate.session) {
        maybeExpiry = null;
    } else if (lastUpdate.expirationDate - Math.floor(Date.now() / 1000) < 0) {
        console.info(`Cookie ${c.name} already expired! Converting to session cookie...`)
        maybeExpiry = null;
    } else {
        maybeExpiry = lastUpdate.expirationDate;
    }

    return new Promise((resolve, reject) => {
        chrome.cookies.set({
            "name": c.name,
            "domain": c.domain,
            "path": c.path,
            "httpOnly": lastUpdate.http_only,
            "sameSite": lastUpdate.sameSite,
            "secure": lastUpdate.secure,
            "value": lastUpdate.value,
            "expirationDate": maybeExpiry,
            "url": "https://" + domainRemoveNoise(c.domain) + c.path,
            "storeId": c.storeId
        }, (result) => {
            if (chrome.runtime.lastError){
                console.error("Failed to restore cookie: " + chrome.runtime.lastError);
                resolve(false);
            } else {
                resolve(result !== null);
            }
        });
    });
}


const removeManyCookies = async function(cookies) {
    for (let c of Object.values(cookies)) {
        await removeSingleCookie(c);
    }
    refreshButtons();
}


const removeOrRestoreCookie = async function(c, button) {
    let success;
    if (await existsCookie(c)){
        success = await removeSingleCookie(c);
        if (success){
            button.textContent = chrome.i18n.getMessage("configButtonRestore");
        } else {
            console.error(`Failed to remove cookie: ${c.name}`)
        }
    } else {
        success = await restoreSingleCookie(c);
        if (success){
            button.textContent = chrome.i18n.getMessage("configButtonRemove");
        } else {
            console.error(`Failed to restore cookie: ${c.name}`)
        }
    }
}


const updateLabel = function(cookie, dropdownElement) {
    dropdownElement.style.color = "black";
    dropdownElement.style.opacity = "100%";
    cookie.current_label = parseInt(dropdownElement.value);
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
        let buttonDiv = document.createElement("div");
        buttonDiv.style = "display: flex; align-items:center;"
        subListItem.appendChild(domainDiv);
        subListItem.appendChild(buttonDiv);

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
        selection.addEventListener("change", (ev) => { updateLabel(c, ev.target); });
        buttonDiv.appendChild(selection);

        let button = document.createElement("button");
        button.className = "item-button";
        buttonDiv.appendChild(button);
        (async () => {
            if (await existsCookie(c)){
                button.textContent = chrome.i18n.getMessage("configButtonRemove");
            } else {
                button.textContent = chrome.i18n.getMessage("configButtonRestore");
            }
        })();
        button.addEventListener("click", (ev) => { removeOrRestoreCookie(c, button) });
        buttonsArray.push({"c": c, "b": button});


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
    let sanitizedDomain = urlToUniformDomain(domain);
    let domainList = await getStorageValue(chrome.storage.sync, "cblk_exglobal");
    if (selectText === "true") {
        if (!domainList.includes(sanitizedDomain)){
            domainList.push(sanitizedDomain);
            setStorageValue(domainList, chrome.storage.sync, "cblk_exglobal");
        }
    } else if (selectText === "false") {
        if (domainList.includes(sanitizedDomain)){
            let index = domainList.indexOf(sanitizedDomain);
            domainList.splice(index, 1);
            setStorageValue(domainList, chrome.storage.sync, "cblk_exglobal");
        }
    } else {
        console.error(`Javascript is being stupid: ${selectText}`)
    }
}

const constructPlaceholderEntry = function() {
    let listEntry = document.createElement("li");
    listEntry.id = "li-placeholder";
    listEntry.hidden = true;
    domainListElem.appendChild(listEntry);
    return listEntry;
}

const constructDomainListEntry = function(domain, path, cookies) {
    let listEntry = document.createElement("li");
    let domainDiv = document.createElement("div");
    domainDiv.className = "domain-entry";
    domainDiv.style.fontWeight = "bold";
    domainDiv.textContent = domain + path;

    let buttonDiv = document.createElement("div");
    buttonDiv.style = "display: flex;align-items:center;height: 4em;";

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
    button.addEventListener("click", async () => {
        await removeManyCookies(cookies);
        await refreshButtons();
    });

    buttonDiv.appendChild(selection);
    buttonDiv.appendChild(button);
    listEntry.appendChild(domainDiv);
    listEntry.appendChild(buttonDiv);

    listEntry.style="vertical-align: middle;";
    domainListElem.appendChild(listEntry);

    let placeholder = document.createElement("li");
    placeholder.style.display = "none";
    domainListElem.appendChild(placeholder);

    let objectCache = { "placeholder": placeholder, "listEntry": null };
    let onclickDomainEntry = function()
    {
        if (!objectCache.listEntry) {
            objectCache.listEntry = constructCookieListEntry(cookies);
        }

        if (domainListElem.contains(objectCache.listEntry)) {
            objectCache.listEntry.replaceWith(objectCache.placeholder);
        } else {
            objectCache.placeholder.replaceWith(objectCache.listEntry);
        }
    }
    domainDiv.addEventListener("click", onclickDomainEntry);
}


const exportCustomLabels = function () {
    let exportJSON = {"domain_match": {}};
    let domainMatch = exportJSON["domain_match"];
    for (d of Object.keys(cookieHistory)){
        for (p of Object.keys(cookieHistory[d])){
            for (c of Object.values(cookieHistory[d][p])){
                if (c.label_ts === sentinelTimestamp && c.current_label !== -1) {
                    let sanitizedDomain = cleanDomain(c.domain);
                    domainMatch[sanitizedDomain] = domainMatch[sanitizedDomain] || {};
                    domainMatch[sanitizedDomain][c.name] = c.current_label;
                }
            }
        }
    }

    let tab = window.open("export.json", "_blank");
    tab.document.write('<pre id="json_body"></pre>');
    tab.document.getElementById("json_body").textContent = JSON.stringify(exportJSON, null, 4);
    tab.document.close();
}

const refreshCookieHistory = function() {

    let child = domainListElem.lastElementChild;
    while (child) {
        domainListElem.removeChild(child);
        child = domainListElem.lastElementChild;
    }

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
                let sortedDomains = Array.from(allDomains).sort();
                for (let d of sortedDomains) {
                    let sanitizedDomain = d;
                    for (let path of Object.keys(cookieHistory[d])){
                        constructDomainListEntry(sanitizedDomain, path, cookieHistory[d][path]);
                    }
                }
            } else {
                let placeholderListItem = constructPlaceholderEntry();
                placeholderListItem.style.display = "";
                setStaticLocaleText("li-placeholder", "configNoCookies");
            }
        } else {
            let placeholderListItem = constructPlaceholderEntry();
            placeholderListItem.style.display = "";
            setStaticLocaleText("li-placeholder", "configLoadError");
            placeholderListItem.style.color = "red";
        }

    });
}


const setupConfigPage = function() {
    setStaticLocaleText("cconfig-title", "extensionName");
    setStaticLocaleText("cconfig-subtitle", "cookieConfigSubtitle");
    setStaticLocaleText("cconfig-desc-title", "cookieConfigDescTitle");
    setStaticLocaleText("cconfig-desc-pg1", "cookieConfigDescPG1");
    setStaticLocaleText("cconfig-desc-pg2", "cookieConfigDescPG2");
    setStaticLocaleText("cconfig-list-title", "cookieConfigListTitle");
    setStaticLocaleText("cconfig-expand-desc", "configExpandDesc");
    setStaticLocaleText("refresh-button", "configButtonRefresh");
    setStaticLocaleText("export-button", "configButtonExport");

    refreshCookieHistory();
}


document.addEventListener("DOMContentLoaded", setupConfigPage);

refreshButton.addEventListener("click", () => { refreshCookieHistory(); });

exportButton.addEventListener("click", () => { exportCustomLabels(); });

setInterval(function() {
    refreshButtons();
}, 1000);