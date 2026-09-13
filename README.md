# ModerContext — Streamlit Live Deployment Package

This package is separate from the research project and does not modify the original checkpoint.

## Put the trained model here

Copy your final LineVul checkpoint into:

    model/best_model.pt

Original source checkpoint:

    stage2_codet5p/best_model_runs/
    modernbert_linevul_paper_bigvul_ws_hardpos_soft_pm8_run1/
    best_model.pt

Do not move or rename the original. Copy it. The copy inside this package must be named exactly `best_model.pt`.

## Local verification

    python verify_package.py
    python -m pip install -r requirements.txt
    streamlit run streamlit_app.py

## GitHub / Streamlit Cloud

The checkpoint is larger than GitHub's normal file limit, so use Git LFS. This package already contains `.gitattributes`.

    git lfs install
    git add .
    git commit -m "Deploy ModerContext Streamlit app"
    git push

In Streamlit Community Cloud use `streamlit_app.py` as the main file. Choose Python 3.10 if available.

## Runtime

The app uses the real trained checkpoint, the extracted LineVul ModerContext preprocessing code, max length 8192, context budget 1024, task budget 64, head 24, tail 12, evidence window ±3, and argmax SAFE/VULNERABLE classification.

## Resource note

The real checkpoint is large and 8192-token inference is substantial. Free Streamlit Cloud may be slow or may hit memory limits. If that happens, the package itself can be deployed on a larger host without changing the model.
