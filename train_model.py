"""
train_model.py - MediGuard AI Aligned Three-Model Training

This version trains the models to match the project logic:

1. condition_model.pkl
   Predicts Normal/Critical from sensor readings.

2. anomaly_model.pkl
   Learns safe medical storage behavior and detects abnormal readings.

3. attack_model.pkl
   Predicts Normal Operation / Environmental Failure / Possible Cyber Attack.

This fixes the issue where ML prediction and anomaly were always Critical/Anomalous.
"""

import pandas as pd
import os
import zipfile
import pandas as pd
import random
import joblib
from glob import glob
import numpy as np

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix


FEATURES = [
    "serial_reading",
    "temp_c",
    "temp_fh",
    "humidity",
    "object_temp",
    "nw_cooling"
]


def temp_to_f(temp_c):
    return round((temp_c * 9 / 5) + 32, 2)


def create_row(temp_c, humidity, cooling, label):
    object_temp = round(temp_c + random.uniform(-0.5, 0.8), 2)

    return {
        "serial_reading": random.randint(100, 5000),
        "temp_c": temp_c,
        "temp_fh": temp_to_f(temp_c),
        "humidity": humidity,
        "object_temp": object_temp,
        "nw_cooling": cooling,
        "label": label
    }


def find_csv_files(data_dir="data"):
    paths = []

    # look for zip files and extract them into a temp folder
    for z in glob(os.path.join(data_dir, "*.zip")):
        try:
            with zipfile.ZipFile(z, "r") as zf:
                extract_dir = z.replace('.zip', '')
                if not os.path.exists(extract_dir):
                    zf.extractall(extract_dir)
                paths.extend(glob(os.path.join(extract_dir, "**", "*.csv"), recursive=True))
        except Exception:
            continue

    # also look for CSVs directly in data dir
    paths.extend(glob(os.path.join(data_dir, "**", "*.csv"), recursive=True))

    # deduplicate
    return sorted(set(paths))


def detect_temp_humidity_columns(df):
    temp_cols = [c for c in df.columns if 'temp' in c.lower() or 'temperature' in c.lower()]
    hum_cols = [c for c in df.columns if 'humid' in c.lower() or 'rh' in c.lower()]

    return temp_cols, hum_cols


def load_dataset_from_data_folder(data_dir="data"):
    # If using the Zenodo extraction, only load Preprocessed SENSOR CSVs
    pre_dir = os.path.join(data_dir, 'Preprocessed')
    if os.path.isdir(pre_dir):
        csv_files = sorted(glob(os.path.join(pre_dir, 'SENSOR*_preprocessed.csv')))
    else:
        csv_files = find_csv_files(data_dir)

    frames = []
    used_files = []
    for f in csv_files:
        # try reading with automatic/semi-colon/comma separators to handle Zenodo files
        df = None
        for sep in [None, ';', ',']:
            try:
                if sep is None:
                    # let pandas try to infer with python engine
                    df = pd.read_csv(f, sep=None, engine='python')
                else:
                    df = pd.read_csv(f, sep=sep)
                # if read succeeded and has multiple columns, break
                if df is not None and df.shape[1] > 1:
                    break
            except Exception:
                df = None
                continue
        if df is None:
            continue

        temp_cols, hum_cols = detect_temp_humidity_columns(df)

        if not temp_cols or not hum_cols:
            continue

        # choose first columns
        tcol = temp_cols[0]
        hcol = hum_cols[0]

        # build a clean subset with explicit column names
        try:
            sub = pd.DataFrame({'temp_c': df[tcol], 'humidity': df[hcol]})
        except Exception:
            continue

        # try to coerce to numeric and drop NaNs
        sub['temp_c'] = pd.to_numeric(sub['temp_c'], errors='coerce')
        sub['humidity'] = pd.to_numeric(sub['humidity'], errors='coerce')
        sub = sub.dropna()

        frames.append(sub)
        used_files.append(f)

    if not frames:
        return None

    combined = pd.concat(frames, ignore_index=True)
    if used_files:
        print('Using CSV files for dataset:')
        for p in used_files:
            print('-', p)
    return combined


def label_by_cold_storage(temp, humidity):
    # Cold-storage rules
    # Normal: 2 <= temp <= 8
    # Warning: 8 < temp < 13 (we'll use up to 12.5 as warning)
    # Critical: temp >= 13
    if pd.isna(temp):
        return 'Normal'

    if 2.0 <= temp <= 8.0 and (30 <= humidity <= 80):
        return 'Normal'
    if 8.0 < temp < 13.0 or humidity < 30 or humidity > 80:
        # Slight deviations map to Warning, extreme humidity to Critical
        if temp >= 13.0 or humidity < 20 or humidity > 90:
            return 'Critical'
        return 'Warning'
    if temp >= 13.0:
        return 'Critical'

    return 'Normal'


def prepare_features_from_df(df):
    rows = []
    for _, r in df.iterrows():
        temp = float(r['temp_c'])
        humidity = float(r['humidity'])
        cooling = 0
        rows.append(create_row(temp, humidity, cooling, label_by_cold_storage(temp, humidity)))

    return pd.DataFrame(rows)


def build_time_series_features(pre_dir, window_size=5):
    # Read only SENSOR*_preprocessed.csv files
    paths = sorted(glob(os.path.join(pre_dir, 'SENSOR*_preprocessed.csv')))
    all_rows = []

    for p in paths:
        # try reading with semicolon or comma
        df = None
        for sep in [';', ',', None]:
            try:
                if sep is None:
                    df = pd.read_csv(p, sep=None, engine='python')
                else:
                    df = pd.read_csv(p, sep=sep)
                if df is not None and df.shape[1] > 1:
                    break
            except Exception:
                df = None
                continue
        if df is None:
            continue

        # detect temperature and humidity columns
        temp_cols, hum_cols = detect_temp_humidity_columns(df)
        if not temp_cols or not hum_cols:
            continue

        tcol = temp_cols[0]
        hcol = hum_cols[0]

        temps = pd.to_numeric(df[tcol], errors='coerce').ffill()
        hums = pd.to_numeric(df[hcol], errors='coerce').ffill()

        # build sliding windows
        for i in range(window_size - 1, len(temps)):
            window_t = temps[i - window_size + 1:i + 1].values
            window_h = hums[i - window_size + 1:i + 1].values

            current_t = float(window_t[-1])
            current_h = float(window_h[-1])
            prev_t = float(window_t[-2]) if window_size >= 2 else current_t
            prev_h = float(window_h[-2]) if window_size >= 2 else current_h

            temp_change = current_t - prev_t
            hum_change = current_h - prev_h

            rt_mean = float(np.mean(window_t))
            rh_mean = float(np.mean(window_h))
            rt_std = float(np.std(window_t))
            rh_std = float(np.std(window_h))

            # slope via linear fit
            try:
                t_idx = np.arange(window_size)
                t_slope = float(np.polyfit(t_idx, window_t, 1)[0])
                h_slope = float(np.polyfit(t_idx, window_h, 1)[0])
            except Exception:
                t_slope = 0.0
                h_slope = 0.0

            all_rows.append({
                'sensor': os.path.basename(p),
                'temperature': current_t,
                'humidity': current_h,
                'temperature_change': temp_change,
                'humidity_change': hum_change,
                'rolling_temperature_mean': rt_mean,
                'rolling_humidity_mean': rh_mean,
                'rolling_temperature_std': rt_std,
                'rolling_humidity_std': rh_std,
                'temperature_slope': t_slope,
                'humidity_slope': h_slope
            })

    return pd.DataFrame(all_rows)


def generate_anomaly(window_row, anomaly_type):
    # window_row is a dict representing features at a time index
    row = dict(window_row)
    t = row['temperature']
    h = row['humidity']

    if anomaly_type == 'temp_spike':
        row['temperature'] = t + random.uniform(8.0, 20.0)
        row['temperature_change'] += random.uniform(8.0, 20.0)
    elif anomaly_type == 'hum_spike':
        row['humidity'] = min(100.0, h + random.uniform(20.0, 50.0))
        row['humidity_change'] += random.uniform(20.0, 50.0)
    elif anomaly_type == 'slow_drift':
        drift = random.uniform(0.2, 0.8)
        row['temperature'] = t + drift * random.uniform(5, 15)
        row['temperature_change'] += drift
    elif anomaly_type == 'stuck':
        # simulate stuck by setting small std and zero change
        row['temperature'] = round(t, 2)
        row['humidity'] = round(h, 2)
        row['temperature_change'] = 0.0
        row['humidity_change'] = 0.0
        row['rolling_temperature_std'] = 0.0
        row['rolling_humidity_std'] = 0.0
    elif anomaly_type == 'impossible_temp':
        row['temperature'] = random.choice([-100.0, 200.0])
        row['temperature_change'] = row['temperature'] - t
    elif anomaly_type == 'impossible_hum':
        row['humidity'] = random.choice([-20.0, 200.0])
        row['humidity_change'] = row['humidity'] - h
    elif anomaly_type == 'noisy':
        row['temperature'] = t + random.gauss(0, 5.0)
        row['humidity'] = min(100.0, max(0.0, h + random.gauss(0, 10.0)))
    else:
        # default small spike
        row['temperature'] = t + random.uniform(5.0, 12.0)

    return row


def main():
    data_folder = 'data/zenodo_cold_storage'
    print(f"Looking for dataset in {data_folder} ...")
    df = load_dataset_from_data_folder(data_folder)

    # print which CSVs were available
    csvs = find_csv_files(data_folder)
    if csvs:
        print('Found CSV files:')
        for p in csvs:
            print('-', p)
    else:
        print('No CSV files found in', data_folder)

    if df is None or df.shape[0] < 50:
        print("No suitable dataset found in data/, falling back to synthetic data.")
        # generate synthetic aligned data similar to cold-storage
        rows = []

        for _ in range(2500):
            temp = round(random.uniform(2.0, 8.0), 2)
            humidity = round(random.uniform(40.0, 70.0), 2)
            rows.append(create_row(temp, humidity, 0, 'Normal'))

        for _ in range(1500):
            temp = round(random.uniform(8.0, 12.5), 2)
            humidity = round(random.uniform(35.0, 85.0), 2)
            rows.append(create_row(temp, humidity, 0, 'Warning'))

        for _ in range(2000):
            temp = round(random.uniform(13.0, 30.0), 2)
            humidity = round(random.uniform(20.0, 98.0), 2)
            cooling = random.choice([0, 1])
            rows.append(create_row(temp, humidity, cooling, 'Critical'))

        data_df = pd.DataFrame(rows)
    else:
        print(f"Loaded dataset with {df.shape[0]} rows from data folder")
        data_df = prepare_features_from_df(df)

    # Before training, remove old model artifacts to ensure fresh training
    for f in ["condition_model.pkl", "anomaly_model.pkl", "attack_model.pkl", "model.pkl", "feature_columns.pkl"]:
        try:
            if os.path.exists(f):
                os.remove(f)
                print('Removed old model file', f)
        except Exception:
            pass

    X = data_df[FEATURES]
    y = data_df['label']

    # =========================
    # MODEL 1: CONDITION MODEL (3 classes)
    # =========================

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    condition_model = RandomForestClassifier(n_estimators=120, random_state=42)
    condition_model.fit(X_train, y_train)

    pred = condition_model.predict(X_test)

    print("\n=== Condition Classification Model ===")
    print("Accuracy:", accuracy_score(y_test, pred))
    print(classification_report(y_test, pred))

    joblib.dump(condition_model, "condition_model.pkl")

    # =========================
    # MODEL 2: ANOMALY MODEL (time-series features + comparison)
    # =========================
    pre_dir = os.path.join('data', 'zenodo_cold_storage', 'Preprocessed')
    if os.path.isdir(pre_dir):
        print('Building time-series features from', pre_dir)
        ts_df = build_time_series_features(pre_dir, window_size=5)
    else:
        ts_df = pd.DataFrame()

    if ts_df.shape[0] < 200:
        print('Insufficient time-series data for anomaly modeling, falling back to simple IsolationForest on condition features')
        normal_data = data_df[data_df['label'] == 'Normal'][FEATURES]
        if normal_data.shape[0] == 0:
            approx_normal = data_df[(data_df['temp_c'] >= 2.0) & (data_df['temp_c'] <= 8.0)][FEATURES]
            if approx_normal.shape[0] > 10:
                normal_data = approx_normal
            else:
                synth_rows = []
                for _ in range(500):
                    t = round(random.uniform(2.0, 8.0), 2)
                    h = round(random.uniform(40.0, 70.0), 2)
                    synth_rows.append(create_row(t, h, 0, 'Normal'))
                normal_data = pd.DataFrame(synth_rows)[FEATURES]

        anomaly_model = IsolationForest(contamination=0.12, random_state=42)
        anomaly_model.fit(normal_data)
        joblib.dump(anomaly_model, "anomaly_model.pkl")

        print("\n=== Anomaly Detection Model ===")
        print("Anomaly model trained on simple feature set (fallback).")
    else:
        # build per-sensor train/test splits
        feature_cols = [
            'temperature','humidity','temperature_change','humidity_change',
            'rolling_temperature_mean','rolling_humidity_mean','rolling_temperature_std','rolling_humidity_std',
            'temperature_slope','humidity_slope'
        ]

        # prepare train/test by sensor to avoid leakage
        train_rows = []
        test_rows = []

        for sensor, g in ts_df.groupby('sensor'):
            n = len(g)
            if n < 20:
                # small sensor traces go entirely to train
                train_rows.extend(g.to_dict('records'))
                continue

            cutoff = int(n * 0.8)
            records = g.to_dict('records')
            train_rows.extend(records[:cutoff])
            test_rows.extend(records[cutoff:])

        # generate anomalies from train and test separately
        anomaly_types = ['temp_spike','hum_spike','slow_drift','stuck','impossible_temp','impossible_hum','noisy']

        def sample_and_generate(src_rows, fraction=0.05):
            src = list(src_rows)
            k = max(1, int(len(src) * fraction))
            chosen = random.sample(src, min(k, len(src)))
            out = []
            for r in chosen:
                at = random.choice(anomaly_types)
                out.append(generate_anomaly(r, at))
            return out

        random.seed(42)
        train_normals = train_rows
        test_normals = test_rows

        train_anoms = []
        test_anoms = []

        # create some anomaly samples in training (supervised classifier needs examples)
        train_anoms.extend(sample_and_generate(train_normals, fraction=0.05))
        # create richer anomalies for testing
        test_anoms.extend(sample_and_generate(test_normals, fraction=0.10))

        # create final datasets
        X_train_norm = pd.DataFrame(train_normals)
        X_test_norm = pd.DataFrame(test_normals)

        X_train_anom = pd.DataFrame(train_anoms) if train_anoms else pd.DataFrame(columns=feature_cols)
        X_test_anom = pd.DataFrame(test_anoms) if test_anoms else pd.DataFrame(columns=feature_cols)

        # assemble supervised training set for RandomForestClassifier
        if not X_train_anom.empty:
            X_train_rf = pd.concat([X_train_norm[feature_cols], X_train_anom[feature_cols]], ignore_index=True)
            y_train_rf = pd.Series([0] * len(X_train_norm) + [1] * len(X_train_anom))
        else:
            X_train_rf = X_train_norm[feature_cols]
            y_train_rf = pd.Series([0] * len(X_train_norm))

        # test set: normals + anomalies
        X_test = pd.concat([X_test_norm[feature_cols], X_test_anom[feature_cols]], ignore_index=True)
        y_test = pd.Series([0] * len(X_test_norm) + [1] * len(X_test_anom))

        # IsolationForest: train on normals only
        iso = IsolationForest(contamination=0.12, random_state=42)
        iso.fit(X_train_norm[feature_cols])

        # RandomForest supervised
        rf = RandomForestClassifier(n_estimators=120, random_state=42)
        if len(y_train_rf.unique()) > 1:
            rf.fit(X_train_rf, y_train_rf)
        else:
            # not enough anomaly examples in training, create small synthetic perturbations
            extra = sample_and_generate(train_normals, fraction=0.02)
            if extra:
                X_extra = pd.DataFrame(extra)[feature_cols]
                X_train_rf = pd.concat([X_train_rf, X_extra], ignore_index=True)
                y_train_rf = pd.concat([y_train_rf, pd.Series([1] * len(X_extra))], ignore_index=True)
                rf.fit(X_train_rf, y_train_rf)
            else:
                rf.fit(X_train_rf, y_train_rf)

        # evaluate both models on X_test
        results = []

        # IsolationForest predictions
        iso_pred_raw = iso.predict(X_test)
        iso_pred = [1 if p == -1 else 0 for p in iso_pred_raw]
        iso_acc = accuracy_score(y_test, iso_pred)
        iso_prec = precision_score(y_test, iso_pred, zero_division=0)
        iso_rec = recall_score(y_test, iso_pred, zero_division=0)
        iso_f1 = f1_score(y_test, iso_pred, zero_division=0)

        results.append({
            'model': 'IsolationForest',
            'accuracy': iso_acc,
            'precision': iso_prec,
            'recall': iso_rec,
            'f1': iso_f1
        })

        # RandomForest predictions
        rf_pred = rf.predict(X_test)
        rf_acc = accuracy_score(y_test, rf_pred)
        rf_prec = precision_score(y_test, rf_pred, zero_division=0)
        rf_rec = recall_score(y_test, rf_pred, zero_division=0)
        rf_f1 = f1_score(y_test, rf_pred, zero_division=0)

        results.append({
            'model': 'RandomForestClassifier',
            'accuracy': rf_acc,
            'precision': rf_prec,
            'recall': rf_rec,
            'f1': rf_f1
        })

        # save comparison CSV
        os.makedirs('evaluation_results', exist_ok=True)
        comp_df = pd.DataFrame(results)
        comp_df.to_csv(os.path.join('evaluation_results', 'anomaly_model_comparison.csv'), index=False)

        # select best model by f1
        best = max(results, key=lambda r: r['f1'])
        best_name = best['model']

        if best_name == 'IsolationForest':
            chosen_model = iso
        else:
            chosen_model = rf

        # save chosen anomaly model and feature columns
        joblib.dump(chosen_model, 'anomaly_model.pkl')
        joblib.dump(feature_cols, 'anomaly_feature_columns.pkl')

        # write detailed anomaly evaluation
        with open(os.path.join('evaluation_results', 'anomaly_evaluation.txt'), 'w') as f:
            f.write('Anomaly Detection Model Comparison\n')
            f.write(comp_df.to_string(index=False) + '\n\n')
            f.write('Selected model: ' + best_name + '\n')
            f.write('\nIsolationForest confusion matrix:\n')
            f.write(str(confusion_matrix(y_test, iso_pred)) + '\n')
            f.write('\nRandomForest confusion matrix:\n')
            f.write(str(confusion_matrix(y_test, rf_pred)) + '\n')
            f.write('\nSelected model metrics:\n')
            f.write(f"Accuracy: {best['accuracy']:.4f}\nPrecision: {best['precision']:.4f}\nRecall: {best['recall']:.4f}\nF1: {best['f1']:.4f}\n")
            f.write('\nExplanation: Anomaly detection flags readings that differ from normal temporal patterns (sudden spikes, stuck values, impossible values, slow drifts, or noisy/manipulated readings).\n')

        print('\n=== Anomaly Detection Completed ===')
        print('Comparison saved to evaluation_results/anomaly_model_comparison.csv')
        print('Detailed evaluation at evaluation_results/anomaly_evaluation.txt')

    # =========================
    # MODEL 3: ATTACK MODEL
    # =========================
    attack_rows = []

    for _ in range(4000):
        environmental_risk = random.randint(0, 100)
        vulnerability_score = random.randint(0, 100)
        anomaly_flag = random.choice([0, 1])
        critical_prediction = 1 if environmental_risk >= 70 else 0

        if environmental_risk < 30:
            attack_label = "Normal Operation"
        elif environmental_risk >= 70 and vulnerability_score >= 60 and anomaly_flag == 1:
            attack_label = "Possible Cyber Attack"
        elif environmental_risk >= 70:
            attack_label = "Possible Environmental Failure"
        elif anomaly_flag == 1 or vulnerability_score >= 60:
            attack_label = "Suspicious Behavior"
        else:
            attack_label = "Cold-Storage Warning"

        attack_rows.append({
            "environmental_risk": environmental_risk,
            "vulnerability_score": vulnerability_score,
            "anomaly_flag": anomaly_flag,
            "critical_prediction": critical_prediction,
            "attack_label": attack_label
        })

    attack_df = pd.DataFrame(attack_rows)

    attack_X = attack_df[["environmental_risk", "vulnerability_score", "anomaly_flag", "critical_prediction"]]
    attack_y = attack_df["attack_label"]

    attack_X_train, attack_X_test, attack_y_train, attack_y_test = train_test_split(
        attack_X,
        attack_y,
        test_size=0.2,
        random_state=42
    )

    attack_model = RandomForestClassifier(n_estimators=120, random_state=42)
    attack_model.fit(attack_X_train, attack_y_train)

    attack_pred = attack_model.predict(attack_X_test)

    print("\n=== Attack Detection Model ===")
    print("Accuracy:", accuracy_score(attack_y_test, attack_pred))
    print(classification_report(attack_y_test, attack_pred))

    joblib.dump(attack_model, "attack_model.pkl")

    joblib.dump(FEATURES, "feature_columns.pkl")

    print("\nAll models trained and saved:")
    print("- condition_model.pkl")
    print("- anomaly_model.pkl")
    print("- attack_model.pkl")
    print("- feature_columns.pkl")


if __name__ == '__main__':
    main()