from sklearn import datasets
from sklearn import svm
import pandas as pd

df = pd.read_csv('data_set/https_dataset.csv')
print df

iris = datasets.load_iris()
digits = datasets.load_digits()
clf = svm.SVC(gamma=0.001, C=100.)
clf.fit(digits.data[:-1], digits.target[:-1])