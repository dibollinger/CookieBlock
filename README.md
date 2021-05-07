# CookieBlock

Repository for the CookieBlock browser extension, which automatically enforces user privacy policy on browser cookies.

It is compatible with both Firefox and Chromium-based browsers.

## Description

__CookieBlock__ is an extension that allows the user to apply their cookie consent preferences to any website, no matter if the website has a cookie banner. The user specifies their consent options once when the extension is first installed, and then CookieBlock will try to remove any cookies that do not align with the user's policy as they are being created.

It offers the following features:
* Automatic classification of cookies into distinct purpose categories.
* Enforcement of a user's privacy policy by filtering cookie categories that have been rejected by the user.
* A choice of which consent categories to block, with an informative description being provided for each category.
* Defining website exceptions, such that all cookies that arrive through that website are accepted.

This is intended to ensure that the privacy of the user is preserved. One can reject any of the following categories:
* Functionality Cookies
* Analytical/Statistics Cookies
* Advertising/Tracking Cookies

Note that CookieBlock does not handle the cookie banner itself. In order to remove these annoying banners, we recommend using the Consent-O-Matic extension, or similar addons:

* https://github.com/cavi-au/Consent-O-Matic


## Links to browser stores

 * Chrome: https://chrome.google.com/webstore/detail/cookieblock/fbhiolckidkciamgcobkokpelckgnnol
 * Edge: https://microsoftedge.microsoft.com/addons/detail/cookieblock/mnfolmjlccppcgdeinhidialajfiopcc
 * Firefox: https://addons.mozilla.org/en-US/firefox/addon/cookieblock/
 * Opera: https://addons.opera.com/en/extensions/details/cookieblock/


## Repository Contents

* `nodejs-feature-extractor/`:  Contains the NodeJS feature extractor. Used to extract features with the same JavaScript code as the extension.
    - `/modules/`: Contains code used to perform the feature extraction and prediction.
    - `/outputs/`: Output directory for the feature extraction.
    - `/training_data/`: Path for cookie data in json format, used for extracting features.
    - `/validation_data/`: Path for cookie features in libsvm format, used for prediction and verifying model accuracy.
    - `/cli.js`: Command-line script used to run the feature extraction.
* `logo/`: Contains the original CookieBlock logo files.
* `src/`: Source code for the CookieBlock extension.
    - `/_locales/`: JSON files with locale strings, for translation.
    - `/_background/`: JavaScript code and HTML for the extension background process.
    - `/ext_data/`: All external data required to perform the feature extraction and class label prediction.
        - `/model/`: Extracted CART prediction tree forests, one for each class of cookies.
        - `/resources/`: Resources used with the feature extraction.
        - `/default_config.json`: Defines default storage values used in the extension.
        - `/features.json`: Defines how the feature extraction operates, and which individual feature are enabled.
        - `/known_cookies.json`: Defines default categorizations for some known cookies.
    - `/icons/`: Browser extension icons.
    - `/modules/`: Contains scripts that handle certain aspects of the feature extraction and prediction.
        - `/third_party/`: Third party code libraries.
    - `/options/`: Contains the options and first time setup page of the extension.
    - `/popup/`: Contains code for the extension popup.
    - `credits.txt`: Links to the third-party libraries and credits to the respective authors.
    - `LICENSE`: License of the extension.

# Credits and License

CookieBlock is released under the MIT License, see included LICENSE file.

Includes code from the following:

* __Difflib JS__: https://github.com/qiao/difflib.js/
  - Ported by Xueqiao Xu <xueqiaoxu@gmail.com>
  - Licensed under: PSF LICENSE FOR PYTHON 2.7.2
* __Levenshtein__: https://github.com/gf3/Levenshtein
  - Copyright (c) Gianni Chiappetta
  - Unlicensed: https://unlicense.org/
* __LZ-String__: https://github.com/pieroxy/lz-string/
  - Copyright (c) 2013 pieroxy
  - Released under the MIT License
* __Consent-O-Matic__: https://github.com/cavi-au/Consent-O-Matic
  - CSS and HTML code used as basis for the interface.
  - Copyright (c) 2020 Janus Bager Kristensen, Rolf Bagge, CAVI
  - Released under the MIT License

## Logo Design

Huge thanks go to CCoates for designing the awesome CookieBlock logo!

----

This extension was created as part of the master thesis *"Analyzing Cookies Compliance with the GDPR*.
See also the following repositories for other components that were developed as part of the thesis:

__Related Repositories:__
* CookieBlock: https://github.com/dibollinger/CookieBlock
* Prototype Crawler: https://github.com/dibollinger/CookieBlock-Crawler-Prototype
* Final Crawler: https://github.com/dibollinger/CookieBlock-Consent-Crawler
* Cookie Classifier: https://github.com/dibollinger/CookieBlock-Consent-Classifier
* Violation Detection & More: https://github.com/dibollinger/CookieBlock-Other-Scripts
* Collected Data: https://drive.google.com/drive/folders/1P2ikGlnb3Kbb-FhxrGYUPvGpvHeHy5ao

__Thesis Supervision and Assistance:__
* Karel Kubicek
* Dr. Carlos Cotrini
* Prof. Dr. David Basin
* The Institute of Information Security at ETH Zürich
