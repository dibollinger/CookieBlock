//-------------------------------------------------------------------------------
/*
Copyright (C) 2021-2022 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------

// Manifest V3 entry point for Chromium-based browsers, which run the background as a service worker.
// Firefox does not support service workers for extensions, and instead loads the same scripts
// as a non-persistent background page, through "background.scripts" in the manifest.
// Keep this list in sync with that manifest entry.
importScripts(
    "/modules/third_party/lz-string.js",
    "/modules/third_party/levenshtein.js",
    "/modules/third_party/difflib-browser.js",
    "/modules/globals.js",
    "/modules/extractor.js",
    "/modules/predictor.js",
    "/background/cookieblock_background.js"
);
