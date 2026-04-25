"""
Train TF-IDF + LogisticRegression on a dataset and save the model as a pickle.

Usage:
    python train_and_save.py /path/to/dataset.csv

Dataset expectations:
 - CSV with either columns `text` and `label` OR `subject`, `body`, and `label`.
 - `label` should be 1 for malicious/spam/phishing, 0 for benign.

If your dataset has `subject` and `body` columns, the script will concatenate them.
"""
import sys
import argparse
from pathlib import Path
import pandas as pd
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


def load_dataset(csv_path: Path):
    df = pd.read_csv(csv_path, on_bad_lines='skip')
    df.columns = df.columns.str.strip()
    if "text" in df.columns and "label" in df.columns:
        texts = df["text"].fillna("").astype(str).tolist()
        labels = df["label"].astype(int).tolist()
    elif "subject" in df.columns and "body" in df.columns and "label" in df.columns:
        texts = (df["subject"].fillna("") + " " + df["body"].fillna("")).astype(str).tolist()
        labels = df["label"].astype(int).tolist()
    else:
        raise ValueError("CSV must contain either (text,label) or (subject,body,label) columns")
    return texts, labels


def build_pipeline():
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
        ("lr", LogisticRegression(class_weight="balanced", solver="liblinear")),
    ])
    return pipeline


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", help="Path to dataset CSV file")
    parser.add_argument("--out", default="phishlens_model.pkl", help="Output pickle file name")
    args = parser.parse_args()

    csv_path = Path(args.csv) or Path(__file__).with_name("datasets/spam_data.csv")
    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        sys.exit(1)

    print(f"Loading dataset from {csv_path}...")
    texts, labels = load_dataset(csv_path)

    print("Building pipeline...")
    pipe = build_pipeline()

    print("Training model (this may take a while)...")
    pipe.fit(texts, labels)

    out_path = Path(args.out)
    with out_path.open("wb") as fh:
        pickle.dump(pipe, fh)

    print(f"Model saved to {out_path.resolve()}")


if __name__ == "__main__":
    main()
