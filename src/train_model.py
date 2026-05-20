# train_model.py (updated for real dataset)

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os

# ── STEP A: Load Real Dataset ──────────────────────────────────

def load_data():
    path = os.path.join("data", "emails_real.csv")

    if not os.path.exists(path):
        print("ERROR: emails_real.csv not found.")
        print("Run this first: python src/prepare_dataset.py")
        exit()

    df = pd.read_csv(path)
    df = df.dropna(subset=["label", "text"])

    print(f"Total emails loaded : {len(df)}")
    print(f"Phishing            : {sum(df.label == 'phishing')}")
    print(f"Legitimate          : {sum(df.label == 'legitimate')}")
    return df


# ── STEP B: TF-IDF Feature Extraction ─────────────────────────

def build_features(df):
    vectorizer = TfidfVectorizer(
        max_features=5000,    # top 5000 most useful words
        ngram_range=(1, 2),   # single words + two-word phrases
        stop_words="english"  # ignore 'the', 'is', 'at' etc
    )
    
    X = vectorizer.fit_transform(df["text"])
    y = (df["label"] == "phishing").astype(int)  # phishing=1, legitimate=0
    
    print(f"\nFeature matrix : {X.shape[0]} emails x {X.shape[1]} word features")
    return X, y, vectorizer


# ── STEP C: Train + Evaluate ───────────────────────────────────

def train(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
        # stratify=y means test set has same spam/ham ratio as full dataset
    )
    
    print(f"Training on : {X_train.shape[0]} emails")
    print(f"Testing on  : {X_test.shape[0]} emails")
    
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    
    print("\n── Model Performance ──────────────────────────")
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.2%}")
    print("\nDetailed Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Phishing"]
    ))
    
    return model


# ── STEP D: Save Model ─────────────────────────────────────────

def save_model(model, vectorizer):
    os.makedirs("models", exist_ok=True)
    
    with open("models/phishing_model.pkl", "wb") as f:
        pickle.dump(model, f)
    
    with open("models/vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)
    
    print("\nModel saved     → models/phishing_model.pkl")
    print("Vectorizer saved → models/vectorizer.pkl")


# ── MAIN ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("── Loading data ────────────────────────────────")
    df = load_data()
    
    print("\n── Building features ───────────────────────────")
    X, y, vectorizer = build_features(df)
    
    print("\n── Training model ──────────────────────────────")
    model = train(X, y)
    
    print("\n── Saving model ────────────────────────────────")
    save_model(model, vectorizer)
    
    print("\n✅ Done! Your AI model is ready.")