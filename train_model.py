import pandas as pd

from sklearn.feature_extraction.text import CountVectorizer

from sklearn.model_selection import train_test_split

from sklearn.naive_bayes import MultinomialNB

import pickle

# LOAD DATA

data = pd.read_csv("urls.csv")

# INPUT

x = data["url"]

# OUTPUT

y = data["label"]

# TEXT TO NUMBERS

cv = CountVectorizer()

x = cv.fit_transform(x)

# TRAIN TEST SPLIT

x_train, x_test, y_train, y_test = train_test_split(
    x,
    y,
    test_size=0.2
)

# MODEL

model = MultinomialNB()

model.fit(x_train, y_train)

# SAVE MODEL

pickle.dump(
    model,
    open("model.pkl", "wb")
)

pickle.dump(
    cv,
    open("vectorizer.pkl", "wb")
)

print("AI MODEL TRAINED SUCCESSFULLY")