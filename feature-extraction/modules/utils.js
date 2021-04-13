// Author: Dino Bollinger
// License: MIT

let fs = require('fs');

/**
* Retrieves the data at the given URL with the specified type. Only intended for local extension data access.
* Once the response arrives, a callback is executed with the response object.
* @param {String} url          URL to send the GET request to, intended to be a local extension URL.
* @param {String} dtype        Type of the data. Examples: "json", "text", "binary"
* @param {Function} callback   Callback function that will be executed as soon as the data is available, receives data as first argument.
*/
const getLocalData = function(url, dtype, callback) {
    if (dtype === "json"){
        let raw_data = fs.readFileSync(url);
        let json_dat = JSON.parse(raw_data);
        callback(json_dat);
    } else if (dtype === "text"){
        let text_data = fs.readFileSync(url, "utf-8");
        callback(text_data);
    } else{
        let raw_data = fs.readFileSync(url);
        callback(raw_data);
    }

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

module.exports = {
    getLocalData: getLocalData,
    escapeString: escapeString
};
