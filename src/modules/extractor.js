// Author: Dino Bollinger
// License: MIT

// Loaded in from a JSON file, stores the configuration on which features to extract from a cookie
var feature_config;

// The following variables store objects that serve as lookup tables for the feature extraction
var top_names;
var top_domains;
var pattern_names;
var name_tokens;
var iabeurope_vendors;
var content_terms;

// Regular expression patterns needed for the feature extraction
const alphaRegex = new RegExp("^[A-Za-z]+$");
const numRegex = new RegExp("^[0-9]+$");
const hexRegex = new RegExp("^[0-9A-Fa-f]+$")
const alnumRegex = new RegExp("^[A-Za-z0-9]+$");
const idRegex = new RegExp("(id|ident)", 'i');
const truthValueRegex = new RegExp("\\b(true|false|yes|no|0|1|on|off)\\b", 'i');
const codeIdentRegex = new RegExp("^[A-Za-z0-9_]+$", 'i');
const alphaAnyRegex = new RegExp("[A-Za-z]");
const uuidRegex = new RegExp("[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}", 'i');
const httpRegex = new RegExp("http(s)?://.*\.");
const wwwRegex  = new RegExp("www(2-9)?\..*\.");

// csv separators
const separators = ",|#:;&._-";

// Recognize Unix timestamps around range of collection
let _tsd = parseInt(`${Date.now()}`.slice(0,2));
const unixTimestampRegex = new RegExp(`\\b(${_tsd-1}|${_tsd}|${_tsd+1})[0-9]{8}([0-9]{3})?\\b`);

// Date related Feature Extraction patterns
const patternYearMonthDay = new RegExp("(19[7-9][0-9]|20[0-3][0-9]|[0-9][0-9])-[01][0-9]-[0-3][0-9]");
const patternDayMonthYear = new RegExp("[0-3][0-9]-[01][0-9]-(19[7-9][0-9]|20[0-3][0-9]|[0-9][0-9])");
const patternMonthDayYear = new RegExp("[01][0-9]-[0-3][0-9]-(19[7-9][0-9]|20[0-3][0-9])");
const patternAlpha3DaysEng = new RegExp("(Mon|Tue|Wed|Thu|Fri|Sat|Sun)", 'i');
const patternAlpha3MonthsEng = new RegExp("(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)", 'i');
const patternFullDaysEng = new RegExp("(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)", 'i');
const patternFullMonthsEng = new RegExp("(January|February|March|April|May|June|July|August|September|October|November|December)", 'i');


/**
 * Checks if given flag (by key) differs between cookie updates.
 * If so, return True, else False. May iterate over all updates.
 * @param {Array} cookieUpdates    Cookie update array
 * @param {String} flag            Key for the flag to check between updates
 * @return                         True if differs between at least 1 update.
 */
const checkFlagChanged = function(cookieUpdates, flag) {
    for (let i = 0; i < cookieUpdates.length - 1; i++) {
        if (cookieUpdates[i][flag] != cookieUpdates[i+1][flag])
            return true;
    }
    return false;
}

/**
 * Compute the mean and standard deviation of the given entries.
 * @param {Array} entries   Array of numbers.
 * @return {Object}         Object storing mean and stddev.
 */
const computeMeanAndStdev = function(entries) {
    if (entries.length == 0) {
        return { "mean": null, "stdev": null };
    }
    else if (entries.length == 1) {
        return { "mean": entries[0], "stdev": null };
    }
    else {
        let mean = entries.reduce((cursum, v) => cursum + v, 0) / entries.length;
        let stdev = Math.sqrt(entries.reduce((cursum, v) => cursum + Math.pow(v - mean, 2), 0) / (entries.length - 1));
        return { "mean": mean, "stdev": stdev }
    }
}

/**
 * Compute the Shannon Entropy for the given string,
 * @param {String} cookieValue  Cookie value string
 * @return {Number}             Shannon entropy.
 */
const computeEntropy = function(cookieValue) {
    let stringSize = cookieValue.length;

    let occurrences = {};
    for (let i = 0; i < stringSize; i++) {
        let curr_char = cookieValue.charAt(i);
        let count = occurrences[curr_char];
        if (count === undefined) {
            occurrences[curr_char] = 1;
        } else {
            occurrences[curr_char] += 1;
        }
    }

    let entropy = 0;
    for (let char_count of Object.values(occurrences)){
        let ratio = char_count / stringSize;
        entropy -= ratio * Math.log2(ratio);
    }

    return entropy;
}

/**
 * Determine the best separator out of a string of possible separators.
 * Decision criterion is maximum number of occurrences.
 * @param {String} cookieContent    Content string to analyze.
 * @param {String} validDelimiters  String of valid delimiters.
 * @param {Number} minSep           Minimum number of separators.
 */
const chooseBestSeparator = function(cookieContent, validSeparators, minSep) {
    let maxoccs = minSep;
    let bestIndex = -1;
    let chosenSeparator = null;
    for (let i = 0; i < validSeparators.length; i++) {
        let r = validSeparators[i];
        // need to escape the following
        if (r === "." || r === "|"){
            r = "\\" + r;
        }
        let numoccs = (cookieContent.match(RegExp(r, 'g')) || []).length;
        if (numoccs > maxoccs){
            chosenSeparator = validSeparators[i];
            bestIndex = i;
            maxoccs = numoccs;
        }
    }
    return {"sep": chosenSeparator, "count": maxoccs, "index": bestIndex};
}

/**
 * Try to remove URL encoding from the given input string.
 * If the encoding is invalid and would cause an error, simply output the input string.
 * @param  {String} str   Input string to maybe decode.
 * @return {String}       Possibly decoded string.
 */
const maybeRemoveURLEncoding = function(str) {
    let decodedValue = undefined;
    try {
        decodedValue = decodeURIComponent(str);
    } catch (error) {
        decodedValue = str;
    }
    return decodedValue;
}


/**
 * Check if the given cookie content contains a date string
 * @param {String} cookieContent   Cookie content with URL encoding removed
 * @return {Boolean}               True if the content contains a date string.
 */
const maybeDateContent = function(cookieContent) {
    return patternYearMonthDay.test(cookieContent)
            || patternDayMonthYear.test(cookieContent)
            || patternMonthDayYear.test(cookieContent)
            || ((patternAlpha3DaysEng.test(cookieContent) || patternFullDaysEng.test(cookieContent))
                && (patternAlpha3MonthsEng.test(cookieContent) || patternFullMonthsEng.test(cookieContent)))
}


// Object that stores all the feature setup functions. These initialize the objects for the above variables.
// Which functions are executed on startup is determined by the feature config.
const setupFunctions = {
    "setup_top_names": (source, vector_size, args) => {
        top_names = {};
        getExtensionFile(chrome.extension.getURL(source), "text", (resp) => {
            let lines = resp.split('\n');
            if (lines.length < vector_size){
                console.warn("Warning: Top cookie names resource is exhausted!");
            }
            for (let i = 0; i < Math.min(lines.length, vector_size); i++) {
                let l = lines[i];
                if (lines[i]) {
                    top_names[l.split(',')[1]] = i;
                }
            }
        });
    },
    "setup_top_domains": (source, vector_size, args) => {
        top_domains = {};
        getExtensionFile(chrome.extension.getURL(source), "text", (resp) => {
            let lines = resp.split('\n');
            if (lines.length < vector_size){
                console.warn("Warning: Top domain names resource is exhausted!");
            }
            for (let i = 0; i < Math.min(lines.length, vector_size); i++) {
                let l = lines[i];
                if (lines[i]) {
                    top_domains[l.split(',')[1]] = i;
                }
            }
        });
    },
    "setup_name_features": (source, vector_size, args) => {
        name_tokens = [];
        getExtensionFile(chrome.extension.getURL(source), "text", (resp) => {
            let lines = resp.split('\n');
            if (lines.length < vector_size){
                console.warn("Warning: Name tokens resource is exhausted!");
            }
            for (let i = 0; i < Math.min(lines.length, vector_size); i++) {
                let l = lines[i];
                if (lines[i]) {
                    name_tokens.push(new RegExp(l.split(',')[1]));
                }
            }
        });
    },
    "setup_content_terms": (source, vector_size, args) => {
        content_terms = [];
        getExtensionFile(chrome.extension.getURL(source), "text", (resp) => {
            let lines = resp.split('\n');
            if (lines.length < vector_size){
                console.warn("Warning: Content terms resource is exhausted!");
            }
            for (let i = 0; i < Math.min(lines.length, vector_size); i++) {
                let l = lines[i];
                if (lines[i]) {
                    content_terms.push(new RegExp(l.split(',')[1], 'i'));
                }
            }
        });
    },
    "setup_pattern_names": (source, vector_size, args) => {
        pattern_names = [];
        getExtensionFile(chrome.extension.getURL(source), "text", (resp) => {
            let lines = resp.split('\n');
            if (lines.length < vector_size){
                console.warn("Warning: Pattern names resource is exhausted!");
            }
            for (let i = 0; i < Math.min(lines.length, vector_size); i++) {
                let l = lines[i];
                if (lines[i]) {
                    pattern_names.push(new RegExp(l.split(',')[3]));
                }
            }
        });
    },
    "setup_iabeurope_vendors": (source, vector_size, args) => {
        iabeurope_vendors = new Set();
        getExtensionFile(chrome.extension.getURL(source), "text", (resp) => {
            let lines = resp.split('\n');
            for (let i = 0; i < lines.length; i++) {
                if (lines[i]) {
                    iabeurope_vendors.add(urlToUniformDomain(lines[i]));
                }
            }
        });
    }
};


/**
* Callback function for when the config is loaded.
* Sets up the configuration variable and executes the setup functions defined in features.json
* @param {Object} fconfig   Configuration object, which defines the features to be extracted.
*/
const setupFeatureResourcesCallback = function(fconfig) {
    feature_config = fconfig;

    let maybeRunSetup = function(featArray) {
        for (const entry of featArray) {
            if (entry["enabled"] && "setup" in entry) {
                setupFunctions[entry['setup']](entry["source"], entry["vector_size"], entry["args"])
            }
        }
    };

    maybeRunSetup(feature_config["per_cookie_features"]);
    maybeRunSetup(feature_config["per_update_features"]);
    maybeRunSetup(feature_config["per_diff_features"]);
};

// retrieve the configuration
getExtensionFile(chrome.extension.getURL("ext_data/features.json"), "json", setupFeatureResourcesCallback);


// Features extracted for each unique cookie
const perCookieFeatures = {
    "feature_top_names": (sparse, curr_idx, cookie_data, args) => {
        if (cookie_data["name"] in top_names) {
            let rank = top_names[cookie_data["name"]];
            sparse[curr_idx + rank] = 1.0;
        }
    },
    "feature_top_domains": (sparse, curr_idx, cookie_data, args) => {
        let transf_domain = urlToUniformDomain(cookie_data["domain"]);
        if (transf_domain in top_domains) {
            let rank = top_domains[transf_domain];
            sparse[curr_idx + rank] = 1.0;
        }
    },
    "feature_pattern_names":  (sparse, curr_idx, cookie_data, args) => {
        for (let i = 0; i < pattern_names.length; i++) {
            if (pattern_names[i].test(cookie_data["name"])) {
                sparse[curr_idx + i] = 1.0;
            }
        }
    },
    "feature_name_tokens":  (sparse, curr_idx, cookie_data, args) => {
        for (let i = 0; i < name_tokens.length; i++){
            if (name_tokens[i].test(cookie_data["name"])) {
                sparse[curr_idx + i] = 1.0;
            }
        }
    },
    "feature_iab_vendor":  (sparse, curr_idx, cookie_data, args) => {
        let transf_domain = urlToUniformDomain(cookie_data["domain"]);
        if (iabeurope_vendors.has(transf_domain)) {
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_domain_period":  (sparse, curr_idx, cookie_data, args) => {
        if (cookie_data["domain"].startsWith(".")) {
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_is_third_party":  (sparse, curr_idx, cookie_data, args) => {
        let cookie_domain = urlToUniformDomain(cookie_data["domain"]);
        let website_domain = urlToUniformDomain(cookie_data["first_party_domain"]);
        if (!(cookie_domain.includes(website_domain))){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_non_root_path":  (sparse, curr_idx, cookie_data, args) => {
        if (cookie_data["path"].normalize() !== "/"){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_update_count":  (sparse, curr_idx, cookie_data, args) => {
        sparse[curr_idx] = cookie_data["variable_data"].length;
    },
    "feature_http_only_changed":  (sparse, curr_idx, cookie_data, args) => {
        if (checkFlagChanged(cookie_data["variable_data"], "http_only")){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_host_only_changed":  (sparse, curr_idx, cookie_data, args) => {
        if (checkFlagChanged(cookie_data["variable_data"], "host_only")){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_secure_changed":  (sparse, curr_idx, cookie_data, args) => {
        if (checkFlagChanged(cookie_data["variable_data"], "secure")){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_same_site_changed":  (sparse, curr_idx, cookie_data, args) => {
        if (checkFlagChanged(cookie_data["variable_data"], "same_site")){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_is_session_changed":  (sparse, curr_idx, cookie_data, args) => {
        if (checkFlagChanged(cookie_data["variable_data"], "session")){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_gestalt_mean_and_stddev":  (sparse, curr_idx, cookie_data, args) => {
        let values = [];
        let cookieUpdates = cookie_data["variable_data"];
        for (let i = 0; i < cookieUpdates.length - 1; i++) {
            let s = new difflib.SequenceMatcher(null, cookieUpdates[i]["value"], cookieUpdates[i+1]["value"]);
            values.push(s.ratio());
        }

        let result = computeMeanAndStdev(values)
        if (values.length > 0){
            sparse[curr_idx] = result["mean"];
            sparse[curr_idx + 1] = (values.length > 1) ? result["stdev"] : 0.0;
        }
    },
    "feature_levenshtein_mean_and_stddev":  (sparse, curr_idx, cookie_data, args) => {
        let values = [];
        let cookieUpdates = cookie_data["variable_data"];
        for (let i = 0; i < cookieUpdates.length - 1; i++) {
            let dist = Levenshtein(cookieUpdates[i]["value"], cookieUpdates[i+1]["value"])
            values.push(dist);
        }

        let result = computeMeanAndStdev(values)
        if (values.length > 0){
            sparse[curr_idx] = result["mean"];
            sparse[curr_idx + 1] = (values.length > 1) ? result["stdev"] : 0.0;
        }
    },
    "feature_content_length_mean_and_stddev":  (sparse, curr_idx, cookie_data, args) => {
        let contentLengths = [];
        let cookieUpdates = cookie_data["variable_data"];
        for (let i = 0; i < cookieUpdates.length; i++) {
            let decodedValue = maybeRemoveURLEncoding(cookieUpdates[i]["value"]);
            contentLengths.push(decodedValue.length);
        }

        let result = computeMeanAndStdev(contentLengths)
        if (contentLengths.length > 0) {
            sparse[curr_idx] = result["mean"];
            sparse[curr_idx + 1] = (contentLengths.length > 1) ? result["stdev"] : 0.0;
        }
    },
    "feature_compressed_length_mean_and_stddev":  (sparse, curr_idx, cookie_data, args) => {
        let values = [];
        let cookieUpdates = cookie_data["variable_data"];
        for (let i = 0; i < cookieUpdates.length; i++) {
            let decodedValue = maybeRemoveURLEncoding(cookieUpdates[i]["value"]);
            let compressed = LZString.compressToUTF16(decodedValue);
            values.push(compressed.length);
        }

        let result = computeMeanAndStdev(values)
        if (values.length > 0) {
            sparse[curr_idx] = result["mean"];
            sparse[curr_idx + 1] = (values.length > 1) ? result["stdev"] : 0.0;
        }
    },
    "feature_entropy_mean_and_stddev":  (sparse, curr_idx, cookie_data, args) => {
        let entropies = [];
        let cookieUpdates = cookie_data["variable_data"];
        for (let i = 0; i < cookieUpdates.length; i++) {
            let decodedValue = maybeRemoveURLEncoding(cookieUpdates[i]["value"]);
            entropies.push(computeEntropy(decodedValue));
        }

        let result = computeMeanAndStdev(entropies)
        if (entropies.length > 0) {
            sparse[curr_idx] = result["mean"];
            sparse[curr_idx + 1] = (entropies.length > 1) ? result["stdev"] : 0.0;
        }
    },
    "feature_expiry_changed":  (sparse, curr_idx, cookie_data, args) => {
        // 1 day of time difference
        let cookieUpdates = cookie_data["variable_data"];
        for (let i = 0; i < cookieUpdates.length - 1; i++) {
            let abs_diff = Math.abs(cookieUpdates[i]["expiry"] - cookieUpdates[i+1]["expiry"]);
            if (abs_diff >= 3600 * 24){
                sparse[curr_idx] = 1.0;
                break;
            }
        }
    },
    "feature_http_only_first_update": (sparse, curr_idx, cookie_data, args) => {
        if (cookie_data["variable_data"][0]["http_only"]){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_host_only_first_update":  (sparse, curr_idx, cookie_data, args) => {
        if (cookie_data["variable_data"][0]["host_only"]){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_secure_first_update":  (sparse, curr_idx, cookie_data, args) => {
        if (cookie_data["variable_data"][0]["secure"]){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_session_first_update":  (sparse, curr_idx, cookie_data, args) => {
        if (cookie_data["variable_data"][0]["session"]){
            sparse[curr_idx] = 1.0;
        }
    },
    "feature_same_site_first_update":  (sparse, curr_idx, cookie_data, args) => {
        let sflag = cookie_data["variable_data"][0]["same_site"];
        if (sflag === "no_restriction"){
            sparse[curr_idx] = 1.0;
        } else if (sflag === "lax" || sflag === "unspecified"){
            sparse[curr_idx + 1] = 1.0;
        } else if (sflag === "strict"){
            sparse[curr_idx + 2] = 1.0;
        } else {
            console.warn("Unrecognized same_site value! Value: " + sflag);
        }
    },
    "feature_expiry_first_update":  (sparse, curr_idx, cookie_data, args) => {
        sparse[curr_idx] = cookie_data["variable_data"][0]["expiry"];
    },
    "feature_content_changed":  (sparse, curr_idx, cookie_data, args) => {
        if (checkFlagChanged(cookie_data["variable_data"], "value")) {
            sparse[curr_idx] = 1.0;
        }
    }
}


// Features extracted for each update in a cookie
// Data is only missing if update doesn't exist.
const perUpdateFeatures = {
    "feature_http_only": (sparse, curr_idx, var_data, args) => {
        sparse[curr_idx] = var_data["http_only"] ? 1.0 : -1.0;
    },
    "feature_host_only": (sparse, curr_idx, var_data, args) => {
        sparse[curr_idx] = var_data["host_only"] ? 1.0 : -1.0;
    },
    "feature_secure": (sparse, curr_idx, var_data, args) => {
        sparse[curr_idx] = var_data["secure"] ? 1.0 : -1.0;
    },
    "feature_session": (sparse, curr_idx, var_data, args) => {
        sparse[curr_idx] = var_data["session"] ? 1.0 : -1.0;
    },
    "feature_same_site": (sparse, curr_idx, var_data, args) => {
        let sflag = var_data["same_site"];
        let eone = -1.0; let etwo = -1.0; let ethree = -1.0;
        if (sflag === "no_restriction"){
            eone = 1.0;
        } else if (sflag === "lax" || sflag === "unspecified"){
            etwo = 1.0;
        } else if (sflag === "strict"){
            ethree = 1.0;
        } else {
            console.warn("Unrecognized same_site value! Value: " + sflag)
        }
        sparse[curr_idx] = eone;
        sparse[curr_idx + 1] = etwo;
        sparse[curr_idx + 2] = ethree;
    },
    "feature_expiry": (sparse, curr_idx, var_data, args) => {
        sparse[curr_idx] = var_data["expiry"];
    },
    "feature_expiry_extra": (sparse, curr_idx, var_data, args) => {
        sparse[curr_idx] = (var_data["expiry"] < 3600) ? 1.0 : -1.0;
        sparse[curr_idx + 1] = (3600 <= var_data["expiry"] && var_data["expiry"] < 3600 * 12) ? 1.0 : -1.0;
        sparse[curr_idx + 2] = (3600 * 12 <= var_data["expiry"] && var_data["expiry"] < 3600 * 24) ? 1.0 : -1.0;
        sparse[curr_idx + 3] = (3600 * 24 <= var_data["expiry"] && var_data["expiry"] < 3600 * 24 * 7) ? 1.0 : -1.0;
        sparse[curr_idx + 4] = (3600 * 24 * 7 <= var_data["expiry"] && var_data["expiry"] < 3600 * 24 * 30) ? 1.0 : -1.0;
        sparse[curr_idx + 5] = (3600 * 24 * 30 <= var_data["expiry"] && var_data["expiry"] < 3600 * 24 * 30 * 6) ? 1.0 : -1.0;
        sparse[curr_idx + 6] = (3600 * 24 * 30 * 6 <= var_data["expiry"] && var_data["expiry"] < 3600 * 24 * 30 * 18) ? 1.0 : -1.0;
        sparse[curr_idx + 7] = (3600 * 24 * 30 * 18 <= var_data["expiry"]) ? 1.0 : -1.0;
    },
    "feature_content_length": (sparse, curr_idx, var_data, args) => {
        let decodedValue = maybeRemoveURLEncoding(var_data["value"]);
        sparse[curr_idx] = decodedValue.length;
    },
    "feature_compressed_content": (sparse, curr_idx, var_data, args) => {
        let compressed = LZString.compress(var_data["value"]);
        let compSize = compressed.length;

        sparse[curr_idx] = compSize;
        let reduction = var_data["value"].length - compSize;
        sparse[curr_idx + 1] = reduction;
    },
    "feature_shannon_entropy": (sparse, curr_idx, var_data, args) => {
        let decodedValue = maybeRemoveURLEncoding(var_data["value"]);
        sparse[curr_idx] = computeEntropy(decodedValue);
    },
    "feature_url_encoding": (sparse, curr_idx, var_data, args) => {
        let cookie_content = var_data["value"];
        let decoded_content = maybeRemoveURLEncoding(cookie_content);
        sparse[curr_idx] = (cookie_content !== decoded_content) ? 1.0 : -1.0;
    },
    "feature_delimiter_separated": (sparse, curr_idx, var_data, args) => {
        let vector_length = separators.length;

        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        let result = chooseBestSeparator(cookieContent, separators, args["min_seps"]);

        for (let i = 0; i < vector_length; i++) {
            sparse[curr_idx + i] = -1;
        }

        if (result["sep"] !== null) {
            sparse[curr_idx + result["index"]] = result["count"] + 1;
        }
    },
    "feature_base64_encoded": (sparse, curr_idx, var_data, args) => {
        let decoded = undefined;
        try {
            decoded = atob(var_data["value"]);
            sparse[curr_idx] = 1.0;
        } catch(error){
            sparse[curr_idx] = -1.0;
        }
    },
    "feature_contains_javascript_object": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);

        try {
            JSON.parse(cookieContent);
            sparse[curr_idx] = 1.0;
        } catch(error){
            try{
                decoded = atob(var_data["value"]);
                JSON.parse(decoded);
                sparse[curr_idx] = 1.0;
            } catch(serror){
                sparse[curr_idx] = -1.0;
            }
        }
    },
    "feature_english_terms_in_content": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);

        for (let i = 0; i < content_terms.length; i++){
            sparse[curr_idx + i] = content_terms[i].test(cookieContent) ? 1.0 : -1.0;
        }
    },
    "feature_csv_content": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        let result = chooseBestSeparator(cookieContent, separators, args["min_seps"]);

        let containsBool = false;
        let containsNum = false;
        let containsAlpha = false;
        let containsAlnum = false;
        let containsHex = false;

        if (result["sep"]) {
            let csv_split = cookieContent.split(result["sep"]);
            for (let entry of csv_split) {
                containsNum |= numRegex.test(entry);
                containsHex |= hexRegex.test(entry);
                containsAlpha |= alphaRegex.test(entry);
                containsAlnum |= alnumRegex.test(entry);
                containsBool |= truthValueRegex.test(entry);
            }
        }
        sparse[curr_idx] = containsNum ? 1.0 : -1.0;
        sparse[curr_idx + 1] = containsHex ? 1.0 : -1.0;
        sparse[curr_idx + 2] = containsAlpha ? 1.0 : -1.0;
        sparse[curr_idx + 3] = containsAlnum ? 1.0 : -1.0;
        sparse[curr_idx + 4] = containsBool ? 1.0 : -1.0;
    },
    "feature_js_content": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);

        let jsobj = undefined;
        try {
            jsobj = JSON.parse(cookieContent);
        } catch(error){
            try{
                decoded = atob(var_data["value"]);
                jsobj = JSON.parse(decoded);
            } catch(serror){}
        }

        let foundIdentifier = false;
        let containsBool = false;
        let containsNum = false;
        let containsString = false;
        let containsAlpha = false;
        let containsAlnum = false;
        let containsSubobject = false;
        let containsList = false;
        let containsNull = false;
        let containsHex = false;

        let checkContent = function(value) {
            if (typeof value === 'object'){
                if (Array.isArray(value)){
                    containsList = true;
                } else if (value !== null){
                    containsSubobject = true;
                } else {
                    containsNull = true;
                }
            } else if (typeof value === "string") {
                containsString = true;

                let entry = value;
                containsNum |= numRegex.test(entry);
                containsHex |= hexRegex.test(entry);
                containsAlpha |= alphaRegex.test(entry);
                containsAlnum |= alnumRegex.test(entry);
                containsBool |= truthValueRegex.test(entry);
            } else if (typeof value === "number") {
                containsNum = true;
            } else if (typeof value === "boolean") {
                containsBool = true;
            } else {
                console.warn("Unexpected object type : " + (typeof value));
            }
        }

        if (typeof jsobj === 'object' && jsobj !== null){
            if(Array.isArray(jsobj)){
                for (let v of jsobj){
                    checkContent(v);
                }
            } else{
                for (let key of Object.keys(jsobj)) {
                    if (idRegex.test(key)){
                        foundIdentifier = true;
                    }
                    checkContent(jsobj[key]);
                }
            }
        }
        else if (jsobj !== undefined && typeof jsobj != "number" && typeof jsobj != "string" && typeof jsobj != "boolean" && jsobj !== null ){
            console.warn("Unexpected type: " + (typeof jsobj))
        }

        sparse[curr_idx] = (jsobj && typeof jsobj === 'object') ? Object.keys(jsobj).length : -1.0;
        sparse[curr_idx + 1] = foundIdentifier ? 1.0 : -1.0;
        sparse[curr_idx + 2] = containsBool ? 1.0 : -1.0;
        sparse[curr_idx + 3] = containsNum ? 1.0 : -1.0;
        sparse[curr_idx + 4] = containsString ? 1.0 : -1.0;
        sparse[curr_idx + 5] = containsAlpha ? 1.0 : -1.0;
        sparse[curr_idx + 6] = containsAlnum ? 1.0 : -1.0;
        sparse[curr_idx + 7] = containsSubobject ? 1.0 : -1.0;
        sparse[curr_idx + 8] = containsList ? 1.0 : -1.0;
        sparse[curr_idx + 9] = containsNull ? 1.0 : -1.0;
        sparse[curr_idx + 10] = containsHex ? 1.0 : -1.0;
    },
    "feature_numerical_content": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        sparse[curr_idx] = numRegex.test(cookieContent) ? 1.0 : -1.0;
    },
    "feature_hex_content": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        sparse[curr_idx] = hexRegex.test(cookieContent) ? 1.0 : -1.0;
    },
    "feature_alpha_content": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        sparse[curr_idx] = alphaRegex.test(cookieContent) ? 1.0 : -1.0;
    },
    "feature_is_identifier": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        sparse[curr_idx] = codeIdentRegex.test(cookieContent) ? 1.0 : -1.0;
    },
    "feature_all_uppercase_content": (sparse, curr_idx, var_data, args) => {
        let cont = maybeRemoveURLEncoding(var_data["value"]);
        // must contain at least one alphabetical character
        sparse[curr_idx] = (alphaAnyRegex.test(cont) && (cont === cont.toUpperCase())) ? 1.0: -1.0;
    },
    "feature_all_lowercase_content": (sparse, curr_idx, var_data, args) => {
        let cont = maybeRemoveURLEncoding(var_data["value"]);
        // must contain at least one alphabetical character
        sparse[curr_idx] = (alphaAnyRegex.test(cont) && (cont === cont.toLowerCase())) ? 1.0: -1.0;
    },
    "feature_empty_content": (sparse, curr_idx, var_data, args) => {
        sparse[curr_idx] = (!var_data["value"]) ? 1.0 : -1.0;
    },
    "feature_boolean_content": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        sparse[curr_idx] = truthValueRegex.test(cookieContent) ? 1.0 : -1.0;
    },
    "feature_timestamp_content": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        sparse[curr_idx] = unixTimestampRegex.test(cookieContent) ? 1.0 : -1.0;
    },
    "feature_date_content": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        sparse[curr_idx] = maybeDateContent(cookieContent) ? 1.0 : -1.0;
    },
    "feature_canonical_uuid": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        let versionOneHot = [-1.0, -1.0, -1.0, -1.0, -1.0, -1.0]

        let matchObj = cookieContent.match(uuidRegex);
        if (matchObj){
            let versionChar = Number.parseInt(matchObj[1]);
            if (versionChar > 0 && versionChar < 6) {
                versionOneHot[versionChar - 1] = 1.0;
            } else {
                versionOneHot[5] = 1.0;
            }
        }
        for (let i = 0; i < versionOneHot.length; i++) {
            sparse[curr_idx + i] = versionOneHot[i];
        }
    },
    "feature_url_content": (sparse, curr_idx, var_data, args) => {
        let cookieContent = maybeRemoveURLEncoding(var_data["value"]);
        sparse[curr_idx] = (httpRegex.test(cookieContent) || wwwRegex.test(cookieContent)) ? 1.0 : -1.0;
    }
}

// Features extracted for difference between updates
const perDiffFeatures = {
    "feature_time_diff": (sparse, curr_idx, prev_data, curr_data, args) => {
        sparse[curr_idx] = curr_data["expiry"] - prev_data["expiry"]
    },
    "feature_gestalt_pattern_ratio": (sparse, curr_idx, prev_data, curr_data, args) => {
        let s = new difflib.SequenceMatcher(null, prev_data["value"], curr_data["value"]);
        sparse[curr_idx] = s.ratio();
    },
    "feature_levenshtein_dist": (sparse, curr_idx, prev_data, curr_data, args) => {
        let dist = Levenshtein(prev_data["value"], curr_data["value"])
        sparse[curr_idx] = dist;
    }
}

/**
* Given an object of cookie data, extract a sparse vector of features.
* The vector hereby takes the form of a key-value store, i.e. a javascript object.
* @param {Object} cookieDat   Object storing the cookie values.
* @return {Object}            An object representing a sparse vector -- keys are indices, values are floats.
*/
const extractFeatures = function(cookieDat) {

    let sparseFeatures = {};
    let curr_idx = 0;
    let cfunc = undefined;
    let var_data = cookieDat["variable_data"]
    let max_updates = Math.min(feature_config["num_updates"], cookieDat["variable_data"].length);
    let max_diffs = Math.min(feature_config["num_diffs"], cookieDat["variable_data"].length - 1);

    // feature extraction for per-cookie features
    for (const entry of feature_config["per_cookie_features"]) {
        if (entry["enabled"]) {
            cfunc = perCookieFeatures[entry['function']];
            cfunc(sparseFeatures, curr_idx, cookieDat, entry["args"]);
            curr_idx += entry["vector_size"];
        }
    }

    // feature extraction for per-update features
    for (const entry of feature_config["per_update_features"]) {
        if (entry["enabled"]) {
            let temp_idx = curr_idx;
            for (let i = 0; i < max_updates ; i++) {
                cfunc = perUpdateFeatures[entry['function']];
                cfunc(sparseFeatures, temp_idx, var_data[i], entry["args"]);

                // remove -1 entries with only one update (distinction between negative entry and missing entry not needed)
                for (let j = temp_idx; j < temp_idx + entry["vector_size"]; j++){
                    if (max_updates === 1 && sparseFeatures[j] === -1) {
                        delete sparseFeatures[j];
                    }
                }
                temp_idx += entry["vector_size"];
            }
            // update it as such to make the size of the vector consistent
            curr_idx += entry["vector_size"] * feature_config["num_updates"];
        }
    }

    // feature extraction for per-diff features
    for (const entry of feature_config["per_diff_features"]) {
        if (entry["enabled"]) {
            let temp_idx = curr_idx;

            for (let i = 0; i < max_diffs ; i++) {
                cfunc = perDiffFeatures[entry['function']];
                cfunc(sparseFeatures, temp_idx, var_data[i], var_data[i+1], entry["args"]);
                temp_idx += entry["vector_size"];
            }

            // update it as such to make the size of the vector consistent
            curr_idx += entry["vector_size"] * (feature_config["num_diffs"]);
        }
    }

    return sparseFeatures;
}
