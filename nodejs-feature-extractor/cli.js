#!/usr/bin/env node
//-------------------------------------------------------------------------------
/*
Copyright (C) 2021 Dino Bollinger, ETH Zürich, Information Security Group

This file is part of CookieBlock.

Released under the MIT License, see included LICENSE file.
*/
//-------------------------------------------------------------------------------

/**
 * This command line script can either perform feature extraction, which is necessary to
 * produce a new model for the extension or it can perform predictions on a validation set
 * to gain validation statistics.
 */

let fs = require('fs');
let utils = require("./modules/utils.js");
let extractor = require("./modules/extractor.js");
let predictor = require("./modules/predictor.js");
let process = require('process');

const skippedNamesRegex = new RegExp("(OptanonConsent|CookieConsent)");

const sparseMatrixPath = "./outputs/processed.libsvm";
const classWeightPath = "./outputs/class_weights.txt";
const predictionLogPath = "./outputs/prediction_stats.log";
const featureMapPath = "./outputs/feature_map.txt";


/**
 * Write the feature map to disk
 */
const writeFeatureMapOutput = function(fconfig) {
    let feat_cnt = 0;

    // feature extraction for per-cookie features
    for (let entry of fconfig["per_cookie_features"]) {
        if (entry["enabled"]) {
            for (let i = 0; i < entry["vector_size"]; i++) {
                fs.appendFileSync(featureMapPath, `${feat_cnt + i} ${entry["name"]}-${i} i\n`);
            }
        feat_cnt += entry["vector_size"];
        }
    }

    // feature extraction for per-update features
    for (let entry of fconfig["per_update_features"]) {
        if (entry["enabled"]) {
            for (let u = 0; u < fconfig["num_updates"]; u++){
                for (let i = 0; i < entry["vector_size"]; i++) {
                    fs.appendFileSync(featureMapPath, `${feat_cnt + i} update_${u}_${entry["name"]}-${i} i\n`);
                }
                feat_cnt += entry["vector_size"];
            }
        }
    }

    // feature extraction for per-diff features
    for (let entry of fconfig["per_diff_features"]) {
        if (entry["enabled"]) {
            for (let u = 0; u < fconfig["num_diffs"]; u++){
                for (let i = 0; i < entry["vector_size"]; i++) {
                    fs.appendFileSync(featureMapPath, `${feat_cnt + i} diff_${u}_${entry["name"]}-${i} i\n`);
                }
                feat_cnt += entry["vector_size"];
            }
        }
    }
    console.info("Feature map written to path: " + featureMapPath);
}



// retrieve cmdline arguments
const [,, ... args] = process.argv;


if (args[0] === "extract"){

    console.info("Feature extraction mode selected.")

    // Load the feature extraction datasets
    let datasets = [];
    let ctr = 0;

    // Check if at least second argument present
    if (args.length < 2) {
        console.error("Not enough arguments passed. Need path to at least 1 training data json file.");
        process.exit(1);
    }

    // Read input JSON training data files
    let readStatus;
    json_filepaths = args.slice(1);
    for (let jspath of json_filepaths) {
        console.info("Reading data from input json document at: " + jspath)
        readStatus = utils.getLocalData(jspath, "json", (r) => datasets.push(r));
        if (readStatus) {
            console.error(`Failed to read file at: '${jspath}'`);
            process.exit(1);
        }
    }
    console.info("Input parsing completed.")

    // Overwrite old output files
    console.info("Clearing old outputs.")
    fs.writeFileSync(sparseMatrixPath, "");
    fs.writeFileSync(classWeightPath, "");
    fs.writeFileSync(featureMapPath, "");

    // create the feature map file
    console.info("Writing feature map...")
    utils.getLocalData("../src/ext_data/features.json", "json", writeFeatureMapOutput);

    console.info("Writing class weight file...")
    // first compute the class weights
    let labelCounts = [0,0,0,0];
    for (let d of datasets) {
        for (let [cookieKey, cookieValue] of Object.entries(d)) {
            let categoryLabel = Number.parseInt(cookieValue["label"]);
            labelCounts[categoryLabel] += 1;
        }
    }

    let totalCount = labelCounts.reduce((p,c) => p + c, 0)
    let classWeights = labelCounts.map((v) => totalCount / v)
    for (let c of classWeights){
        fs.appendFileSync(classWeightPath, c + "\n")
    }
    console.info("Class weights written to path: " + classWeightPath);

    console.info("Performing feature extraction...")
    for (let d of datasets) {
        for (const [cookieKey, cookieValue] of Object.entries(d)) {

            let categoryLabel = Number.parseInt(cookieValue["label"]);

            // Skip labels that aren't useful
            if (categoryLabel < 0 || categoryLabel > 3) {
                continue;
            }

            // filter out specific cookie names
            if (skippedNamesRegex.test(cookieValue["name"])){
                continue
            }

            // extract features for this cookie
            let features = extractor.extractFeatures(cookieValue);

            let outputLine = `${categoryLabel}`;
            for (let [idx, val] of Object.entries(features)){
                outputLine = `${outputLine} ${idx}:${val}`;
            }
            outputLine += "\n";
            fs.appendFileSync(sparseMatrixPath, outputLine);

            ctr++;
            if (ctr % 1000 == 0){
                console.info(`Completed: ${ctr}`)
            }

        }
    }
    console.info("Features written to path: " + sparseMatrixPath);
} else if (args[0] === "predict") {

    // Get validation stats
    let validationLibSVM;
    let validationTransformed = [];
    let trueLabels = [];

    // Check if at least second argument present
    if (args.length < 3) {
        console.error("Not enough arguments passed. Requires path to the validation LIBSVM file and permissiveness factor (default 1).");
        process.exit(1);
    }

    // Overwrite old output file
    fs.writeFileSync(predictionLogPath, "");

    // Sequential callback
    console.info("Loading validation LibSVM");
    utils.getLocalData(args[1], "text", (r) => {
        validationLibSVM = r;
        let lines = validationLibSVM.split("\n");

        for (let l of lines){
            if (!l) continue;
            validEntry = {};
            let tokens = l.split(" ");
            trueLabels.push(tokens[0]);
            for (let i = 1; i < tokens.length; i++){
                let kv = tokens[i].split(":");
                validEntry[kv[0]] = Number.parseFloat(kv[1]);
            }
            validationTransformed.push(validEntry);
        }
        console.info("Validation data loaded.");

        let runPredictions = async () => {

            console.info("Computing predictions...");

            let predictedLabels = [];
            for (let j = 0; j < validationTransformed.length; j++) {
                let label = await predictor.predictClass(validationTransformed[j], args[2]);
                predictedLabels.push(label);
                if (j % 5000 == 0) {
                    console.info("Progress: " + j + "/" + validationTransformed.length);
                }
            }
            console.info("Predictions complete.");

            console.assert((trueLabels.length == predictedLabels.length),
                            "Number of true labels %d did not match number of predicted labels %d!",
                            trueLabels.length, predictedLabels.length);


            let rightCount = 0;
            let wrongCount = 0;
            let confusionMatrix = [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]];
            for (let j = 0; j < predictedLabels.length; j++){
                let tl = Number.parseInt(trueLabels[j]);
                let pl = Number.parseInt(predictedLabels[j]);
                confusionMatrix[tl][pl] += 1;
                if (tl === pl){
                    rightCount += 1;
                } else {
                    wrongCount += 1;
                }
            }

            let precisionVector = [0,0,0,0];
            for (let i = 0; i < precisionVector.length; i++) {
                let colsum = 0;
                for (let j = 0; j < precisionVector.length; j++) {
                    colsum += confusionMatrix[j][i];
                }
                precisionVector[i] = confusionMatrix[i][i] / colsum;
            }

            let recallVector = [0,0,0,0];
            for (let i = 0; i < recallVector.length; i++) {
                recallVector[i] = confusionMatrix[i][i] / confusionMatrix[i].reduce((p,c) => p + c);
            }

            let f1ScoreVector = [0,0,0,0];
            for (let i = 0; i < precisionVector.length; i++) {
                f1ScoreVector[i] = 2 * ((precisionVector[i] * recallVector[i]) / (precisionVector[i] + recallVector[i]));
            }

            console.info("Confusion Matrix:")
            console.info(confusionMatrix)

            console.info("Accuracy: " + (100 * (rightCount / (rightCount + wrongCount))) + "%")

            console.info("Precision:")
            console.info(precisionVector)
            console.info("Recall:")
            console.info(recallVector)
            console.info("F1 Score:")
            console.info(f1ScoreVector)
            fs.appendFileSync(predictionLogPath, "Confusion Matrix:\n");
            fs.appendFileSync(predictionLogPath, confusionMatrix[0] + "\n");
            fs.appendFileSync(predictionLogPath, confusionMatrix[1] + "\n");
            fs.appendFileSync(predictionLogPath, confusionMatrix[2] + "\n");
            fs.appendFileSync(predictionLogPath, confusionMatrix[3] + "\n");
            fs.appendFileSync(predictionLogPath, "Accuracy: " + (100 * (rightCount / (rightCount + wrongCount))) + "%\n");
            fs.appendFileSync(predictionLogPath, "Precision: \n");
            fs.appendFileSync(predictionLogPath, precisionVector + "\n");
            fs.appendFileSync(predictionLogPath, "Recall: \n");
            fs.appendFileSync(predictionLogPath, recallVector + "\n");
            fs.appendFileSync(predictionLogPath, "F1 Score: \n");
            fs.appendFileSync(predictionLogPath, f1ScoreVector + "\n");
        }
        runPredictions();
    });

} else {
    console.info("Usage: cli.js (extract <json>... | predict <validation_file>)")
}
