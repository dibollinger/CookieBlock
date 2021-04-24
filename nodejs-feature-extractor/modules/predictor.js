// Author: Dino Bollinger
// License: MIT
let utils = require('./utils.js')

// initialize the forests
var forests = [undefined, undefined, undefined, undefined];
utils.getLocalData("validation_data/model/forest_class0.json", "json", (f) => forests[0] = f);
utils.getLocalData("validation_data/model/forest_class1.json", "json", (f) => forests[1] = f);
utils.getLocalData("validation_data/model/forest_class2.json", "json", (f) => forests[2] = f);
utils.getLocalData("validation_data/model/forest_class3.json", "json", (f) => forests[3] = f);

/**
 * Given a tree node and corresponding features, retrieve the weight from the decision tree.
 * Recursive function. Recursion depth is limited to the maximum tree depth in the forest.
 * > Example Node: {"f": 470, "c": 0, "u": "l", "l": {}, "r": {}}
 * > Example Leaf: {"v": 32.0}
 * @param {Object} treeNode: Node or Leaf of the tree, represented by a js object.
 * @param {Object} features:  Features to base decisions on. Any key not found is missing data.
 * @return {Promise<Number>}           The score resulting from the input features.
 */
 const traverseDecisionTree = function(treeNode, features){
    if ("v" in treeNode) {
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
 * Asynchronous function that produces a total class score from a single forest.
 * @param {Object} forest:   Forest object to traverse.
 * @param {Object} features: Extracted features in sparse object representation. {"index": value}
 * @returns {Promise<Number>}  Total score for the forest.
 */
const getForestScore = async function(forest, features) {
    let treeScores = forest.map((root) => traverseDecisionTree(root, features));
    return treeScores.reduce((total, nv) => {return total + nv}, 0);
}


/**
* Predicts the category of the cookie using the extracted features.
* Rather than using XGBoost directly, we perform predictions using the decision tree dump.
* The object represents a sparse vector, with missing features being absent keys.
* @param {Object} features   Cookie features formatted as {"index": value}.
* @return {Promise<Number>}  The predicted label for the cookie.
*/
const predictClass = async function (features, nfactor = 1){

    let existsUndefined = forests.reduce((total, f) => {return total || (f === undefined)}, false)
    if (existsUndefined) {
        throw new Error("At least one internal forest model was undefined!");
    }

    let forestPromises = [];
    for (let i = 0; i < forests.length; i++) {
        forestPromises.push(getForestScore(forests[i], features));
    }
    let classScores = (await Promise.all(forestPromises)).map(Math.exp);
    let totalScore = classScores.reduce((total,num) => {return total + num}, 0);
    let probabilities = classScores.map((x) => {return x / totalScore});

    // Bayes Decision
    let minIndex = -1;
    let minLoss = undefined;
    let lossWeights = [[0, 1, 1, 1], [nfactor, 0, 1, 1], [nfactor, 1, 0, 1], [nfactor, 1, 1, 0]];

    let cLoss;
    for (let j = 0; j < lossWeights.length; j++){
        cLoss = 0;
        for (let i = 0; i < probabilities.length; i++) {
            cLoss += probabilities[i] * lossWeights[j][i];
        }

        if (minLoss === undefined || cLoss < minLoss){
            minIndex = j;
            minLoss = cLoss;
        }
    }

    return minIndex;
}

module.exports = {
    predictClass: predictClass
};
