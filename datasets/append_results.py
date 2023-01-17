import pandas as pd

r1 = pd.read_csv('results.csv')
r2 = pd.read_csv('results_2.csv')

final = pd.concat([r1, r2])

final.to_csv('big_data_set.csv', index=False)