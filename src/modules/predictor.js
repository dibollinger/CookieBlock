// Author: Dino Bollinger
// License: MIT

/* Initialization */
var forests = [null, null, null, null];
getLocalData(browser.extension.getURL("ext_data/model/forest_class0.json"), "json", (f) => forests[0] = f);
getLocalData(browser.extension.getURL("ext_data/model/forest_class1.json"), "json", (f) => forests[1] = f);
getLocalData(browser.extension.getURL("ext_data/model/forest_class2.json"), "json", (f) => forests[2] = f);
getLocalData(browser.extension.getURL("ext_data/model/forest_class3.json"), "json", (f) => forests[3] = f);


/* Prediction Functions */

/**
 * Given a tree node and corresponding features, retrieve the weight from the decision tree.
 * Recursive function. Recursion depth is limited to the maximum tree depth in the forest.
 * @param {Object} treeNode: Node or Leaf of the tree, represented by a js object.
 * @param {Object} features:  Features to base decisions on. Any key not found is missing data.
 * @return {Number}           The score resulting from the input features.
 */
const traverseDecisionTree = function(treeNode, features){
    // Example Node: {"f": 470, "c": 0, "u": "l", "l": {}, "r": {}}
    // Example Leaf: {"v": 32.0}
    if ("v" in treeNode){
        return treeNode["v"];
    } else {
        let fidx = treeNode["f"];
        if (!(fidx in features)) {
            return traverseDecisionTree(treeNode[treeNode["u"]], features);
        } else if (features[fidx] < treeNode["c"]) {
            return traverseDecisionTree(treeNode["l"], features);
        } else {
            return traverseDecisionTree(treeNode["r"], features);
        }
    }
}


/**
 * Use the given array of forests to predict the label for the given input features.
 * The forests must be sorted in the same order as the labels are numbered.
 * (e.g. forest corresponding to label "1" must be the second forest in the array)
 * This variant of the predictor only predicts labels for a single instance at a time.
 * @param {Object} classForests:  Forest in the form of a list of dictionaries.
 * @param {Object} features:      Sparse feature dictionary.
 * @return {Object}               Class probabilities and discrete prediction
 */
const forest_predict = function(classForests, features) {
    let classScores = [];
    let totalScore = 0.0;
    for (let i = 0; i < classForests.length; i++) {
        classScores.push(0);
        let forest = classForests[i];
        for (let root of forest){
            classScores[i] += traverseDecisionTree(root, features);
        }
        classScores[i] = Math.exp(classScores[i]);
        totalScore += classScores[i];
    }

    let maxIndex = 0;
    let maxRatio = 0;
    let predProbabilities = [];
    for (let i = 0; i < classScores.length; i++){
        let ratio = classScores[i] / totalScore;
        predProbabilities.push(ratio);
        // TODO: Implement Bayesian Decision Theory function here instead of argmax
        if (ratio > maxRatio){
            maxIndex = i;
            maxRatio = ratio;
        }
    }
    return {"predicted_probabilities": predProbabilities, "prediction": maxIndex};
}



/**
* Predicts the category of the cookie using the given feature object.
* Rather than using XGBoost directly, we perform predictions using the decision tree dump.
* The object represents a sparse vector, with missing features being absent keys.
* @param {Object} features   Cookie features formatted as {"index":value}.
* @return {Number}           The predicted label for the cookie.
*/
const predictClass = function (sparseFeatures){
    let result = forest_predict(forests, sparseFeatures);
    return result["prediction"];
}
