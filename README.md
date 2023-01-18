# tma_project

This project has two folders:

* **Data:** It has all the csv files used to train the ML
* **Model:** It has all the code files:
  * _Data Transformation_: It has all the data transformations we used to have the csv we wanted
  * _KNN_: It has the KNN algorithm to predict things.
  * _Random Forest_: It has the Random Forest algorithm to predict things
  * _PCA + Random Forest_: PCA is a linear dimensionality reduction technique that transforms a set of correlated 
  variables (p) into a smaller k (k<p) number of uncorrelated variables called principal components. _More info in: [PCA](https://rukshanpramoditha.medium.com/principal-component-analysis-18-questions-answered-4abd72041ccd)_

To try any live monitoring, the script of the algorithm you choose has to be executed with for example: 
`python3 live_monitoring_Random_Forest.py`. These scripts use the `test_data/ready_for_training.csv`, which is the dataset we used
to train our model.

If you want to use a different dataset, this dataset should have a column with the url, and the type of url, for example:
_google.com,benign_. This can be seen too at `datasets/all.csv`. To get all the features we have used to train and to 
predict, the `test_data/apply_feature_engineering.py` has to be executed, but modifying the line 4 with the path of the file.
Once you have all the features, the data the `model/Data_Transformation.ipynb` which basically drops some rows and 
delete some things we saw were not usefull.



Pyshark Manual: https://github.com/KimiNewt/pyshark/tree/293f5ea225ec8281395c83a7773146f707aa53bd
