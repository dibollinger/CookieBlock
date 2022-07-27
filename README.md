# CookieBlock Browser Extension

CookieBlock is a browser extension that automatically enforces your GDPR consent preferences for cookies. It classifies cookies on-the-fly into four distinct categories, and deletes those that the user did not consent to.

This can help enforce user privacy without having to rely on the website hosting the cookies.


## Table of Contents

* [Description](#description)
* [Download Links](#download-links)
* [Feedback](#feedback)
* [Build Instructions](#build-instructions)
* [How It Works](#how-it-works)
* [Known Issues](#known-issues)
* [Repository Contents](#repository-contents)
* [Credits](#credits)
* [License](#license)

## Description

__CookieBlock__ is an extension that allows the user to apply their cookie consent preferences to any website, no matter if the website has a cookie banner. The user specifies their consent options once when the extension is first installed, and then CookieBlock will try to remove any cookies that do not align with the user's policy as they are being created.

This is intended to ensure that the privacy of the user is preserved. One can reject any of the following categories:
* Functionality Cookies
* Analytical/Statistics Cookies
* Advertising/Tracking Cookies

Note that CookieBlock does not handle the cookie banner itself. In order to remove these annoying banners, we recommend using the Consent-O-Matic extension:

* https://github.com/cavi-au/Consent-O-Matic

## Download Links

CookieBlock is compatible with both Firefox and Chromium-based browsers, and it is available on the following addon stores:
 * [Firefox Extension](https://addons.mozilla.org/en-US/firefox/addon/cookieblock/)
 * [Chrome Extension](https://chrome.google.com/webstore/detail/cookieblock/fbhiolckidkciamgcobkokpelckgnnol)
 * [Edge Extension](https://microsoftedge.microsoft.com/addons/detail/cookieblock/mnfolmjlccppcgdeinhidialajfiopcc)
 * [Opera Extension](https://addons.opera.com/en/extensions/details/cookieblock/)
 * Safari does not support cookie processing, so we cannot port CookieBlock to Safari. More info [here](https://github.com/dibollinger/CookieBlock/issues/4).

## Feedback

If you would like to submit feedback, or report websites that break because of the addon, you can open an issue on this Github page, or alternatively use [this Google Forms document](https://forms.gle/tL21ruvPZq2q218P8).


## Build Instructions

No requirements outside of what is contained in this repository is needed to build CookieBlock. Simply pack the contents of the subfolder `src` into a zip file, and you can install it into your browser.

Alternatively, you can also install __npm__ and use the [web-ext](https://github.com/mozilla/web-ext) command-line tool, with the command `web-ext build`.

### Reproducing the Model Files

The model files are constructed in the following process:
1. Scrape so-called Consent Management Platforms for cookie labels, using a [web crawler](https://github.com/dibollinger/CookieBlock-Consent-Crawler).
2. Extract from the resulting database the training cookies into a JSON format (a script for this is included in the above link).
3. Use the [feature extractor](nodejs-feature-extractor/cli.js) to transform the cookies JSON into a sparse LibSVM matrix representation.
4. Provide this LibSVM with the associated class weights as input to the  XGBoost classifier implementation found in [this repository](https://github.com/dibollinger/CookieBlock-Consent-Classifier).
5. Execute a secondary script to transform the XGBoost model into a minified JSON tree structure. This script produces the four model files `forest_class0.json` to `forest_class3.json`.

## How It Works

The policy enforcement process is a background script that executes every time a cookie event is raised in the browser. If this event indicates that a cookie was added or updates, the extension will proceed to store the cookie in a local history
of cookie updates, and then perform a classification for that cookie.

The category for each cookie is predicted using a forest of decision trees model trained via the XGBoost classifier, and a set of feature extraction steps. First, the cookie is turned into a numerical vector, which is then provided as an input to the forest of trees. This produces a score for each class, and the best score is the class that gets assigned to the cookie.

Available cookie categories are:
* __Strictly Necessary__
* __Functionality__
* __Analytics__
* __Advertising/Tracking__

Granularity is intentionally kept low to make the decision as simple as possible for the user. Note that "strictly necessary" cookies cannot be rejected, as this is the class of cookies that is required to make the website work. Without them, essential services such as logins would stop working.

An offline variant of the feature extractor can be found in the subfolder `nodejs-feature-extractor/`. This feature extractor was used to extract the features for the training data set.

For the classifier implementation, see:

https://github.com/dibollinger/CookieBlock-Consent-Classifier


## Known Issues

The classifier is not completely accurate. It may occur that certain functions on some sites are broken because essential cookies get misclassified. This is hard to resolve without gathering more cookie data to train on. As such, the approach has its limits.

To resolve these problems, we maintain a list of known cookie categories. This is a JSON file storing cookie labels for known cookie identifiers. If a cookie is contained in this file. the prediction is skipped, and the known class is applied.

By reporting broken websites, you can help us keep an updated list of cookie exceptions. This makes the extension more useable for everyone while also keeping a high level of privacy.

## Repository Contents

* `nodejs-feature-extractor/`:  Contains the NodeJS feature extractor. Used to extract features with the same JavaScript code as the extension.
    - `/modules/`: Contains code used to perform the feature extraction and prediction.
    - `/outputs/`: Output directory for the feature extraction.
    - `/training_data/`: Path for cookie data in json format, used for extracting features.
    - `/validation_data/`: Path for cookie features in libsvm format, used for prediction and verifying model accuracy.
    - `/cli.js`: Command-line script used to run the feature extraction.
* `logo/`: Contains the original CookieBlock logo files.
* `src/`: Source code for the CookieBlock extension.
    - `_locales/`: JSON files with locale strings, for translation.
    - `background/`: JavaScript code and HTML for the extension background process.
    - `ext_data/`: All external data required to perform the feature extraction and class label prediction.
        - `model/`: Extracted CART prediction tree forests, one for each class of cookies.
        - `resources/`: Resources used with the feature extraction.
        - `default_config.json`: Defines default storage values used in the extension.
        - `features.json`: Defines how the feature extraction operates, and which individual feature are enabled.
        - `known_cookies.json`: Defines default categorizations for some known cookies.
    - `icons/`: Browser extension icons.
    - `modules/`: Contains scripts that handle certain aspects of the feature extraction and prediction.
        - `third_party/`: Third party code libraries.
    - `options/`: Contains the options and first time setup page of the extension.
    - `popup/`: Contains code for the extension popup.
    - `credits.txt`: Links to the third-party libraries and credits to the respective authors.
    - `LICENSE`: License of the extension.


## Credits

* CookieBlock logo designed by Charmaine Coates.
* Czech translation provided by Karel Kubicek.
* Japanese translation provided by Shitennouji.
* Spanish translation provided by @6ig6oy.
* Machine-provided localization performed using DeepL.

### Libraries

CookieBlock includes code from the following libraries and projects:

* [__Difflib JS__](https://github.com/qiao/difflib.js/)
  - Ported by Xueqiao Xu <xueqiaoxu@gmail.com>
  - Licensed under: PSF LICENSE FOR PYTHON 2.7.2
* [__Levenshtein__](https://github.com/gf3/Levenshtein)
  - Copyright (c) Gianni Chiappetta
  - Unlicensed: https://unlicense.org/
* [__LZ-String__](https://github.com/pieroxy/lz-string/)
  - Copyright (c) 2013 pieroxy
  - Released under the MIT License
* [__Consent-O-Matic__](https://github.com/cavi-au/Consent-O-Matic)
  - CSS and HTML code used as basis for the interface.
  - Copyright (c) 2020 Janus Bager Kristensen, Rolf Bagge, CAVI
  - Released under the MIT License

### Thesis

This repository was created as part of the master thesis __"Analyzing Cookies Compliance with the GDPR"__,
which can be found at:

https://www.research-collection.ethz.ch/handle/20.500.11850/477333

as well as the paper __"Automating Cookie Consent and GDPR Violation Detection"__, which can be found at:

https://karelkubicek.github.io/post/cookieblock.html

__Thesis Supervision and co-authors:__
* Karel Kubicek
* Dr. Carlos Cotrini
* Prof. Dr. David Basin
* Information Security Group at ETH Zürich

See also the following repositories for other components that were developed as part of the thesis:

* [OpenWPM-based Consent Crawler](https://github.com/dibollinger/CookieBlock-Consent-Crawler)
* [Cookie Consent Classifier](https://github.com/dibollinger/CookieBlock-Consent-Classifier)
* [Violation Detection](https://github.com/dibollinger/CookieBlock-Other-Scripts)
* [Prototype Consent Crawler](https://github.com/dibollinger/CookieBlock-Crawler-Prototype)
* [Collected Data](https://doi.org/10.5281/zenodo.5838646)


## License

__Copyright © 2021 Dino Bollinger, Department of Computer Science at ETH Zürich, Information Security Group__

MIT License, see included LICENSE file
