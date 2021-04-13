// Author: Dino Bollinger
// License: MIT

/**
* Retrieves the data at the given URL with the specified type. Only intended for local extension data access.
* Once the response arrives, a callback is executed with the response object.
* @param {String} url          URL to send the GET request to, intended to be a local extension URL.
* @param {String} dtype        Type of the data. Examples: "json", "text", "binary"
* @param {Function} callback   Callback function that will be executed as soon as the data is available, receives data as first argument.
*/
const getLocalData = function(url, dtype, callback) {
    const req = new XMLHttpRequest();

    req.responseType = dtype;
    req.onreadystatechange = function(event)
    {
        if (this.readyState === XMLHttpRequest.DONE)
        {
            if (this.status === 200) {
                callback(this.response);
            }
            else {
                console.log("Error -- could not retrieve data at (%s): %d (%s)", url, this.status, this.statusText);
            }
        }
    };

    req.open('GET', url, true);
    req.send(null);
};


/**
* Remove URL encoding from the string
* @param  {String} str   Maybe URL encoded string.
* @return {String}       Decoded String.
*/
const escapeString = function(str) {
    if (typeof str != "string") {
        str = String(str);
    }
    return unescape(encodeURIComponent(str));
}


/**
 * Takes a URL or a domain string and transforms it into a uniform format.
 * Examples: {"www.example.com", "https://example.com/", ".example.com"} --> "example.com"
 * @param {String} domain  Domain to clean and bring into uniform format
 * @return {String}        Cleaned domain string.
 */
const urlToUniformDomain = function(url) {
    let new_url = url.trim();
    new_url = new_url.replace(/^http(s)?:\/\//, "");
    new_url = new_url.replace(/^www([0-9])?/, "");
    new_url = new_url.replace(/^\./, "");
    new_url = new_url.replace(/\/$/, "");
    return new_url;
}