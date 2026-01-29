import os
import glob

models_root = r"D:\CDAC\project\new_v2\network-ids-all_models"
print(f"Path exists: {os.path.exists(models_root)}")

if os.path.exists(models_root):
    dataset_dirs = [d for d in os.listdir(models_root) if os.path.isdir(os.path.join(models_root, d))]
    print(f"Found directories: {dataset_dirs}")
    for d in dataset_dirs:
        m_dir = os.path.join(models_root, d)
        files = os.listdir(m_dir)
        print(f"Directory {d} contains {len(files)} files.")
        best = glob.glob(os.path.join(m_dir, "*_BEST_*.pkl"))
        print(f"  BEST models: {best}")
