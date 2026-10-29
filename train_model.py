"""Optional example ML training workflow. Requires requirements-ml.txt and a real labelled dataset."""
import argparse
import re
from urllib.parse import urlsplit
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def clean_url(value):
    value = str(value).strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value
    return value.lower()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="CSV with url,label columns; 1=phishing, 0=legitimate")
    parser.add_argument("--output", default="model.joblib")
    args = parser.parse_args()
    df = pd.read_csv(args.csv)
    if not {"url", "label"}.issubset(df.columns):
        raise SystemExit("CSV must contain url and label columns.")
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    if set(df["label"].unique()) != {0, 1} or len(df) < 20:
        raise SystemExit("Use at least 20 labelled rows and include both labels 0 and 1. Sample data is not enough for credible training.")
    X_train, X_test, y_train, y_test = train_test_split(
        df["url"].map(clean_url), df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=100000)),
        ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced"))
    ])
    model.fit(X_train, y_train)
    print(classification_report(y_test, model.predict(X_test), target_names=["legitimate", "phishing"], zero_division=0))
    joblib.dump(model, args.output)
    print(f"Saved optional model to {args.output}. This is not automatically loaded by the web API.")

if __name__ == "__main__":
    main()
