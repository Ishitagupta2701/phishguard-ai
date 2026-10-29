"""Train the phishing classifier and save it to model/phishing_model.pkl."""
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES, feature_vector

DATA_PATH = "data/urls.csv"
MODEL_PATH = "model/phishing_model.pkl"


def main():
    if not os.path.exists(DATA_PATH):
        import generate_dataset
        generate_dataset.main()

    df = pd.read_csv(DATA_PATH).dropna()
    X = pd.DataFrame([feature_vector(u) for u in df["url"]], columns=FEATURE_NAMES)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    model = RandomForestClassifier(
        n_estimators=200, max_depth=14, random_state=42, n_jobs=-1
    )
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    print(classification_report(y_test, pred, target_names=["legitimate", "phishing"]))
    print("Confusion matrix:\n", confusion_matrix(y_test, pred))

    print("\nTop features:")
    imp = sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda t: -t[1])
    for name, score in imp[:8]:
        print(f"  {name:24s} {score:.3f}")

    os.makedirs("model", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nSaved model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
