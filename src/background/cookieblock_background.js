// Author: Dino Bollinger
// License: MIT

import { enforcePolicy } from "../modules/enforcer.js";
import { getLocalData } from "/modules/utils.js";

// storage keys for each type of domain exception (global, functionality, analytics, advertising)
const exceptionKeys = ["cblk_exglobal", "cblk_exfunc", "cblk_exanal", "cblk_exadvert"]


/**
 * Callback function that executes once the configuration has been retrieved.
 * @param {Object} resp  Default configuration
 */
const initCallback = function(defaultConfig) {

  // initialize debug mode setting
  browser.storage.local.get("cblk_debug").then((r) => {
    if (r["cblk_debug"] === undefined) {
      browser.storage.local.set({"cblk_debug": false});
    } else {
      console.assert(typeof r["cblk_debug"] === "boolean", "Stored debug mode value wasn't a boolean!");
    }
  }, (error) => {
    console.error(`An error occurred: ${error}`);
  });


  // setup the whitelists
  browser.storage.sync.get(exceptionKeys).then((r) => {

    if (r["cblk_exglobal"] === undefined) {
      browser.storage.sync.set({"cblk_exglobal": []});
    }

    if (r["cblk_exfunc"] === undefined) {
      browser.storage.sync.set({"cblk_exfunc": []});
    }

    if (r["cblk_exanal"] === undefined) {
      browser.storage.sync.set({"cblk_exanal": []});
    }

    if (r["cblk_exadvert"] === undefined) {
      browser.storage.sync.set({"cblk_exadvert": []});
    }

  }, (error) => {
    console.error(`An error occurred: ${error}`);
  });


  // set up counters
  browser.storage.local.get("cblk_counter").then((r) => {
    if (r["cblk_counter"] === undefined)
      browser.storage.local.set({"cblk_counter": [0,0,0,0,0]});
  }, (error) => {
    console.error(`An error occurred: ${error}`);
  });


  // if the user policy is undefined, initialize it from defaults
  browser.storage.sync.get("cblk_userpolicy").then((r) => {
    if (r["cblk_userpolicy"] === undefined) {
      browser.storage.sync.set({
        "cblk_userpolicy": [defaultConfig["default_policy"]["block_necessary"],
                             defaultConfig["default_policy"]["block_functional"],
                             defaultConfig["default_policy"]["block_analytics"],
                             defaultConfig["default_policy"]["block_advertising"]]
      });
    }
  }, (error) => {
    console.error(`An error occurred while retrieving user policy: ${error}`);
  });


  // initialize the extension cookie storage
  browser.storage.local.get("cblk_storage").then((r) => {
    if (r["cblk_storage"] === undefined) {
      browser.storage.local.set({ "cblk_storage": {} });
    }
  }, (error) => {
    console.error(`An error occurred while retrieving cookie store: ${error}`);
  });
}



/**
* Listener that is executed any time a cookie is added, updated or removed.
* Classifies the cookie and rejects it based on user policy.
* @param {Object} changeInfo  Contains the cookie itself, and cause info.
*/
const cookieChangeListener = function(changeInfo) {

    if (changeInfo.removed) {
        // do nothing in this case
        return;
    }

    // construct the key for keeping track of cookie updates
    let cookieDat = changeInfo.cookie;
    let ckey = cookieDat.name + ";" + cookieDat.domain + ";" + cookieDat.firstPartyDomain + ";" + cookieDat.path;

    enforcePolicy(ckey, cookieDat);
};


/**
 * Listener function that opens the first time setup when the extension is installed.
 * @param {Object} details Contains the reason for the change.
 */
const firstTimeSetup = function(details) {
  if (details.reason === "install") {
    browser.tabs.create({"active": true, "url": "/options/cookieblock_setup.html"});
  }
}


/** Init + Listener **/
// Assumption: Callback is faster than we receive any cookies.
getLocalData(browser.extension.getURL("ext_data/config.json"), "json", initCallback);
browser.cookies.onChanged.addListener(cookieChangeListener);


// Check if extension was just installed. If so, open a new tab with setup instructions
browser.runtime.onInstalled.addListener(firstTimeSetup)