import pandas as pd
import feature_engineering as fe

df = pd.read_csv('../datasets/all.csv')

out = fe.apply(df)

out.to_csv('featured_data.csv', index=False)