//-------------------------------------------------------------------------------
/*
Copyright (C) 2021-2022 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------

let fs = require('fs');

/**
* Retrieves the data at the given URL with the specified type. Only intended for local extension data access.
* Once the response arrives, a callback is executed with the response object.
* @param {String} url          URL to send the GET request to, intended to be a local extension URL.
* @param {String} dtype        Type of the data. Examples: "json", "text", "binary"
* @param {Function} callback   Callback function that will be executed as soon as the data is available, receives data as first argument.
*/
const getLocalData = function(url, dtype, callback) {
    let read_data;
    try {
        if (dtype === "json"){
            let raw_data = fs.readFileSync(url);
            read_data = JSON.parse(raw_data);
        } else if (dtype === "text"){
            read_data = fs.readFileSync(url, "utf-8");
        } else{
            read_data = fs.readFileSync(url);
        }
        callback(read_data);
    } catch (err) {
        console.error(err.message);
        return 1;
    }
    return 0;
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
