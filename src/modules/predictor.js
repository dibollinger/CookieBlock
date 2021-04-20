// Author: Dino Bollinger
// License: MIT

// initialize the forests
var forests = [undefined, undefined, undefined, undefined];
getLocalData(browser.extension.getURL("ext_data/model/forest_class0.json"), "json", (f) => forests[0] = f);
getLocalData(browser.extension.getURL("ext_data/model/forest_class1.json"), "json", (f) => forests[1] = f);
getLocalData(browser.extension.getURL("ext_data/model/forest_class2.json"), "json", (f) => forests[2] = f);
getLocalData(browser.extension.getURL("ext_data/model/forest_class3.json"), "json", (f) => forests[3] = f);


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
const predictClass = async function (features){

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

    // TODO: Implement Bayesian Decision Theory function here instead of argmax
    let maxIndex = 0;
    let maxProb = 0;
    for (let i = 0; i < probabilities.length; i++){
        if (probabilities[i] > maxProb){
            maxIndex = i;
            maxProb = probabilities[i];
        }
    }
    //{"predicted_probabilities": predProbabilities, "prediction": maxIndex};
    return maxIndex;
}
