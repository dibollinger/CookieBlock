#!/usr/bin/env node
// Author: Dino Bollinger
// MIT License

// This command line script can either perform feature extraction, which is necessary to produce a new model for the extension.
// or it can perform predictions on a validation set to gain validation statistics.

let fs = require('fs');
let utils = require("./modules/utils.js");
let extractor = require("./modules/feature_extraction.js");
let predictor = require("./modules/predictor.js");

const skippedNamesRegex = new RegExp("(OptanonConsent|CookieConsent)");

// get arguments (I have no idea why the syntax is like this, don't ask me)
const [,, ... args] = process.argv;

const featurePath = "./outputs/processed.libsvm"
const weightPath = "./outputs/class_weights.txt"
const predictionLogPath = "./outputs/prediction_stats.log"

if (args[0] === "extract"){
    // Load the feature extraction datasets
    // TODO: Output feature map
    let datasets = [];
    let ctr = 0;

    // POINT THESE TOWARDS THE TRAINING DATA JSON FILES
    // TODO: Command line input
    utils.getLocalData("CHANGEME", "json", (r) => datasets.push(r));
    utils.getLocalData("CHANGEME", "json", (r) => datasets.push(r));

    // Overwrite old file
    fs.writeFileSync(featurePath, "");
    fs.writeFileSync(weightPath, "");

    // First compute the class weights
    let labelCounts = [0,0,0,0]
    for (let d of datasets) {
        for (const [cookieKey, cookieValue] of Object.entries(d)) {
            let categoryLabel = Number.parseInt(cookieValue["label"]);
            labelCounts[categoryLabel] += 1;
        }
    }
    let totalCount = labelCounts.reduce((p,c) => p + c, 0)
    let classWeights = labelCounts.map((v) => totalCount / v)
    for (let c of classWeights){
        fs.appendFileSync(weightPath, c + "\n")
    }

    for (let d of datasets) {
        // Then extract the features
        for (const [cookieKey, cookieValue] of Object.entries(d)) {

            let categoryLabel = Number.parseInt(cookieValue["label"]);
            // Make sure we only consider desired labels
            if (categoryLabel < 0 || categoryLabel > 3) {
                continue;
            }

            // filter out specific cookie names
            if (skippedNamesRegex.test(cookieValue["name"])){
                continue
            }

            let features = extractor.extractFeatures(cookieValue);

            let outputLine = `${cookieValue["label"]}`;
            for (let [idx, val] of Object.entries(features)){
                outputLine = `${outputLine} ${idx}:${val}`;
            }
            outputLine += "\n";
            fs.appendFileSync(featurePath, outputLine);

            ctr++;
            if (ctr % 1000 == 0){
                console.log(`Completed: ${ctr}`)
            }
        }
    }
} else if (args[0] === "predict") {
    // Get validation stats
    let validationLibSVM = undefined;
    let validationTransformed = [];
    let trueLabels = [];
    fs.writeFileSync(predictionLogPath, "");

    // EDIT ME: NEED TO PROVIDE PATH TO THE VALIDATION LIBSVM FILE, AS OUTPUT BY XGBOOST
    // TODO: Change to command line input
    utils.getLocalData("CHANGEME", "text", (r) => validationLibSVM = r);
    let lines = validationLibSVM.split("\n");
    for (let l of lines){
        if (!l) {
            continue;
        }
        validEntry = {};
        let tokens = l.split(" ");
        trueLabels.push(tokens[0]);
        for (let i = 1; i < tokens.length; i++){
            let kv = tokens[i].split(":");
            validEntry[kv[0]] = Number.parseFloat(kv[1]);
        }
        validationTransformed.push(validEntry);
    }

    let predictedLabels = [];
    for (let j = 0; j < validationTransformed.length; j++) {
        let label = predictor.predictClass(validationTransformed[j]);
        predictedLabels.push(label);
        if (j % 1000 == 0)
            console.log("Progress: " + j + "/" + validationTransformed.length)
    }

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
    for (let i = 0; i < precisionVector.length; i++) {
        recallVector[i] = confusionMatrix[i][i] / confusionMatrix[i].reduce((p,c) => p + c);
    }

    let f1ScoreVector = [0,0,0,0];
    for (let i = 0; i < precisionVector.length; i++) {
        f1ScoreVector[i] = 2 * ((precisionVector[i] * recallVector[i]) / (precisionVector[i] + recallVector[i]));
    }

    console.log("Confusion Matrix:")
    console.log(confusionMatrix)

    console.log("Accuracy: " + (100 * (rightCount / (rightCount + wrongCount))) + "%")

    console.log("Precision:")
    console.log(precisionVector)
    console.log("Recall:")
    console.log(recallVector)
    console.log("F1 Score:")
    console.log(f1ScoreVector)
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
} else {
    console.error("Valid arguments: 'extract' | 'predict'")
}
