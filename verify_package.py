from pathlib import Path
import sys
p = Path(__file__).resolve().parent / "model" / "best_model.pt"
print("Expected model:", p)
if not p.exists():
    print("STATUS: MISSING")
    sys.exit(1)
print("STATUS: FOUND")
print("Size MB:", round(p.stat().st_size / 1024 / 1024, 2))
