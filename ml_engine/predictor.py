import joblib
import pandas as pd
import numpy as np
import os
import glob
import sys
from django.conf import settings

# Expert Core: NumPy 2.x Compatibility Shim
# Ensures models trained on modern environments can be loaded in this lab environment
if 'numpy._core' not in sys.modules:
    import numpy
    sys.modules['numpy._core'] = numpy
    if hasattr(numpy, 'core'):
         sys.modules['numpy._core.multiarray'] = numpy.core.multiarray
    else:
         # Handle even weirder cases
         import numpy.core.multiarray as ma
         sys.modules['numpy._core.multiarray'] = ma

class NIDSPredictor:
    """
    Expert-level NIDS Predictor that utilizes a multi-model approach.
    It scans the network-ids-all_models directory and loads all 'BEST' models
    available to provide comprehensive traffic analysis.
    """
    def __init__(self):
        self.models_root = r"D:\CDAC\project\new_v2\network-ids-all_models"
        self.specialized_models = {} # dataset_key -> {model, scaler, features}
        self.load_all_models()

    def load_all_models(self):
        """Discovers and loads all optimized models available in the root directory."""
        import sys
        if not os.path.exists(self.models_root):
             print(f"Expert System CRITICAL: Root {self.models_root} vanished!")
             return
             
        dataset_dirs = [d for d in os.listdir(self.models_root) if os.path.isdir(os.path.join(self.models_root, d))]
        print(f"Expert System: Scanning root {self.models_root}")
        sys.stdout.flush()
        
        for dataset_key in dataset_dirs:
            models_dir = os.path.join(self.models_root, dataset_key)
            try:
                best_model_files = glob.glob(os.path.join(models_dir, "*_BEST_*.pkl"))
                scaler_files = glob.glob(os.path.join(models_dir, "*_scaler.pkl"))
                features_files = glob.glob(os.path.join(models_dir, "*_features.pkl"))
                
                if not best_model_files or not scaler_files or not features_files:
                    print(f"Expert System: Skip {dataset_key} - Missing artifacts.")
                    continue

                model_path = best_model_files[0]
                scaler_path = scaler_files[0]
                features_path = features_files[0]

                print(f"Expert System: Loading {dataset_key} agent...")
                sys.stdout.flush()
                
                self.specialized_models[dataset_key] = {
                    'model': joblib.load(model_path),
                    'scaler': joblib.load(scaler_path),
                    'features': joblib.load(features_path),
                    'name': os.path.basename(model_path).replace('.pkl', '')
                }
                print(f"Expert System: Successfully integrated '{dataset_key}' detection agent.")
                sys.stdout.flush()
            except Exception as e:
                print(f"Expert System: Diagnostics failed for agent '{dataset_key}': {e}")
                sys.stdout.flush()

        print(f"Expert System: Initialization complete. Total agents active: {len(self.specialized_models)}")
        sys.stdout.flush()

    def preprocess(self, df, feature_names, scaler):
        """Preprocesses the dataframe for a specific model's requirements."""
        df_copy = df.copy()
        df_copy.columns = df_copy.columns.str.strip()
        
        for col in feature_names:
            if col not in df_copy.columns:
                df_copy[col] = 0
        
        X = df_copy[feature_names]
        X = X.fillna(0).replace([np.inf, -np.inf], 0)
        return scaler.transform(X)

    def predict(self, df):
        """
        Analyzes traffic using all loaded models.
        Returns a list of tuples: (Label, Confidence, ModelUsed)
        Uses a priority mechanism: If any specialized model detects an attack, that is prioritized.
        """
        if not self.specialized_models:
            self.load_all_models()

        num_samples = len(df)
        final_results = [("BENIGN", 1.0, "None")] * num_samples
        
        # Track if an attack has been detected for each sample to avoid overwriting with BENIGN
        attack_detected = [False] * num_samples

        for dataset_key, components in self.specialized_models.items():
            try:
                X_scaled = self.preprocess(df, components['features'], components['scaler'])
                raw_preds = components['model'].predict(X_scaled)
                
                # Get confidence
                if hasattr(components['model'], "predict_proba"):
                    probs = components['model'].predict_proba(X_scaled)
                    confidences = np.max(probs, axis=1)
                else:
                    confidences = np.ones(num_samples)

                for i in range(num_samples):
                    pred = raw_preds[i]
                    conf = confidences[i]
                    
                    # Normalization of labels (Expert logic)
                    is_current_attack = False
                    label_str = str(pred).strip()
                    
                    if isinstance(pred, (int, np.integer)):
                        if pred != 0:
                            is_current_attack = True
                            label_str = dataset_key 
                        else:
                            label_str = "BENIGN"
                    else:
                        # String label logic: anything not containing 'benign' is an attack
                        if "BENIGN" not in label_str.upper():
                            is_current_attack = True
                        else:
                            label_str = "BENIGN"
                    
                    # Priority: Once an attack is detected by ANY model, we keep identifying it as an attack.
                    # We update only if the current model detects an attack and either:
                    # 1. No attack was detected yet.
                    # 2. This model has higher confidence.
                    if is_current_attack:
                        if not attack_detected[i] or conf > final_results[i][1]:
                            final_results[i] = (label_str, conf, components['name'])
                            attack_detected[i] = True
                    elif not attack_detected[i]:
                        # If no attack detected yet by anyone, we can stay BENIGN but update confidence/model info
                        if conf > final_results[i][1] or final_results[i][2] == "None":
                            final_results[i] = (label_str, conf, components['name'])

            except Exception as e:
                print(f"Expert System: Error running model {dataset_key}: {e}")

        return final_results
