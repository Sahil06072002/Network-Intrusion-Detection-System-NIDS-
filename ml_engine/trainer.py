import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

def retrain_model(dataset_key, csv_path):
    """
    Expert-level retraining logic for NIDS models.
    Loads a dataset, trains a Random Forest, and saves artifacts to the correct directory.
    """
    print(f"Expert System: Retraining agent for '{dataset_key}'...")
    
    # Load Data
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        return False, f"CSV Load Error: {e}"

    # Clean and Prepare (Expert Feature Set)
    df.columns = df.columns.str.strip()
    # Assume the last column or 'Label' is target
    target_col = 'Label' if 'Label' in df.columns else df.columns[-1]
    
    X = df.drop(columns=[target_col, 'Source IP', 'Destination IP', 'Timestamp'], errors='ignore')
    y = df[target_col]

    # Handle numeric/inf
    X = X.select_dtypes(include=[np.number]).fillna(0).replace([np.inf, -np.inf], 0)
    
    # Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Expert Choice: Random Forest for balanced performance
    model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    model.fit(X_train_scaled, y_train)

    # Validate
    y_pred = model.predict(X_test_scaled)
    acc = round(accuracy_score(y_test, y_pred) * 100, 2)
    
    # Save Artifacts
    save_dir = os.path.join(r"D:\CDAC\project\new_v2\network-ids-all_models", dataset_key)
    os.makedirs(save_dir, exist_ok=True)
    
    model_name = f"{dataset_key}_BEST_RF_AUTO.pkl"
    joblib.dump(model, os.path.join(save_dir, model_name))
    joblib.dump(scaler, os.path.join(save_dir, f"{dataset_key}_scaler.pkl"))
    joblib.dump(list(X.columns), os.path.join(save_dir, f"{dataset_key}_features.pkl"))

    print(f"Expert System: Retraining complete. Accuracy: {acc}%")
    return True, {"accuracy": acc, "model_name": model_name}

if __name__ == "__main__":
    # Test script usage
    # retrain_model("Fri_DDos", "path/to/data.csv")
    pass
