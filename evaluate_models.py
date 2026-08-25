import os
import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix

import train_model


def ensure_output_dir(path='evaluation_results'):
    os.makedirs(path, exist_ok=True)
    return path


def evaluate_condition_model(condition_model, X_test, y_test, outdir):
    labels = ['Normal', 'Warning', 'Critical']
    pred = condition_model.predict(X_test)
    acc = accuracy_score(y_test, pred)
    prec = precision_score(y_test, pred, average='weighted', zero_division=0)
    rec = recall_score(y_test, pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, pred, average='weighted', zero_division=0)

    report = classification_report(y_test, pred, labels=labels, zero_division=0)
    cm = confusion_matrix(y_test, pred, labels=labels)

    with open(os.path.join(outdir, 'condition_classification_report.txt'), 'w') as f:
        f.write(f"Accuracy: {acc}\nPrecision: {prec}\nRecall: {rec}\nF1: {f1}\n\n")
        f.write(report)

    cm_df = pd.DataFrame(cm, index=labels, columns=labels)
    cm_df.to_csv(os.path.join(outdir, 'condition_confusion_matrix.csv'))

    return acc, prec, rec, f1


def evaluate_anomaly_model(anomaly_model, X, y, outdir):
    # anomaly_model predicts -1 for outliers, 1 for inliers
    preds = anomaly_model.predict(X)
    # convert to 1 anomalous / 0 normal
    pred_flags = [1 if p == -1 else 0 for p in preds]
    # For evaluation we consider rows not labeled 'Normal' as anomalies
    true_flags = [0 if lab == 'Normal' else 1 for lab in y]

    acc = accuracy_score(true_flags, pred_flags)
    prec = precision_score(true_flags, pred_flags, zero_division=0)
    rec = recall_score(true_flags, pred_flags, zero_division=0)
    f1 = f1_score(true_flags, pred_flags, zero_division=0)

    with open(os.path.join(outdir, 'anomaly_evaluation.txt'), 'w') as f:
        f.write(f"Anomaly detection (IsolationForest) evaluation on dataset\n")
        f.write(f"Accuracy: {acc}\nPrecision: {prec}\nRecall: {rec}\nF1: {f1}\n")

    return acc, prec, rec, f1


def main():
    outdir = ensure_output_dir()

    # load models
    if not os.path.exists('condition_model.pkl') or not os.path.exists('anomaly_model.pkl'):
        print('Models condition_model.pkl and anomaly_model.pkl not found. Run train_model.py first.')
        return

    condition_model = joblib.load('condition_model.pkl')
    anomaly_model = joblib.load('anomaly_model.pkl')

    # load dataset from zenodo preprocessed folder only
    df = train_model.load_dataset_from_data_folder('data/zenodo_cold_storage')

    if df is None or df.shape[0] < 50:
        print('No dataset found for evaluation in data/. Using synthetic split from training logic.')
        # reuse train_model to generate synthetic data
        print('Please run train_model.py to generate models from synthetic data first.')
        return

    data_df = train_model.prepare_features_from_df(df)
    X = data_df[train_model.FEATURES]
    y = data_df['label']

    # split for evaluation
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print('Evaluating condition model...')
    evaluate_condition_model(condition_model, X_test, y_test, outdir)

    print('Evaluating anomaly model...')
    evaluate_anomaly_model(anomaly_model, X, y, outdir)

    print('Evaluation complete. Results saved to', outdir)


if __name__ == '__main__':
    main()
