from ml_engine.predictor import NIDSPredictor
import traceback

try:
    print("Expert System: Attempting to boot NIDSPredictor...")
    predictor = NIDSPredictor()
    print(f"Expert System: Boot successful. Agents active: {len(predictor.specialized_models)}")
    for key, c in predictor.specialized_models.items():
        print(f"  - Agent '{key}' [Model: {c['name']}]")
except Exception:
    print("Expert System: Boot FAILED.")
    traceback.print_exc()
