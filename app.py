import streamlit as st
import pandas as pd
import numpy as np
import joblib
import gdown
import os
import traceback

# =======================================================================
# CONFIG
# =======================================================================
st.set_page_config(page_title="IDPS System", page_icon="🛡️", layout="wide")

# ---------------------------
# 🔴 Paste your Google Drive file IDs here (replace the placeholders)
# ---------------------------
MODEL_FILE_ID = "1ROjXla7J_wAEpaWBVPFR88pOxlZRAmbe"
SCALER_FILE_ID = "1fbREKxsJ4n3m_n1n6ExrQzpmeaXG9DIx"
FEATURES_FILE_ID = "1fbREKxsJ4n3m_n1n6ExrQzpmeaXG9DIx"
ENCODERS_FILE_ID = "13fsMK6xKJrk9uQ0S5p-PxarUYYqrGKOT"

# =======================================================================
# UTIL: download files from Drive (via gdown)
# =======================================================================
@st.cache_resource
def download_file(file_id, output_name):
    if file_id.startswith("PASTE_") or file_id.strip() == "":
        st.error(f"❌ FILE_ID for {output_name} not set. Please update app.py with your Drive file IDs.")
        return None
    if not os.path.exists(output_name):
        url = f'https://drive.google.com/uc?id={file_id}'
        try:
            gdown.download(url, output_name, quiet=False)
        except Exception as e:
            st.error(f"❌ Download error for {output_name}: {e}")
            return None
    return output_name

@st.cache_resource
def load_model_and_utils():
    """Downloads and loads model, scaler, feature names and encoders (if present)."""
    try:
        # download
        mfile = download_file(MODEL_FILE_ID, 'idps_model.joblib')
        sfile = download_file(SCALER_FILE_ID, 'feature_scaler.joblib')
        ffile = download_file(FEATURES_FILE_ID, 'feature_names.joblib')
        efile = None
        try:
            efile = download_file(ENCODERS_FILE_ID, 'label_encoders.joblib')
        except Exception:
            # not critical
            efile = None

        # load
        model = joblib.load('idps_model.joblib') if mfile else None
        scaler = joblib.load('feature_scaler.joblib') if sfile else None
        feature_names = joblib.load('feature_names.joblib') if ffile else None

        label_encoders = None
        if efile:
            try:
                label_encoders = joblib.load('label_encoders.joblib')
            except Exception:
                label_encoders = None

        return model, scaler, feature_names, label_encoders

    except Exception as e:
        st.error("❌ Error loading model files: " + str(e))
        st.error(traceback.format_exc())
        return None, None, None, None

# =======================================================================
# FALLBACK MAPPINGS (used only if label_encoders is missing or invalid)
# =======================================================================
# NOTE: These numeric values are placeholders so the app does not crash.
# For best predictions you *must* replace them with the exact integers that
# your LabelEncoder produced during training (or re-save the encoders as a dict).
PROTOCOL_MAP = {
    'tcp': 0,
    'udp': 1,
    'icmp': 2
}

# A small common-services map. Add/update to match encoder integers from training.
SERVICE_MAP = {
    'http': 0,
    'smtp': 1,
    'ftp': 2,
    'ssh': 3,
    'dns': 4,
    'pop3': 5,
    'domain_u': 6,
    'auth': 7,
    'eco_i': 8,
    'other': 9
}

# Example flag map
FLAG_MAP = {
    'SF': 0,
    'S0': 1,
    'REJ': 2,
    'RSTR': 3,
    'RSTO': 4,
    'SH': 5,
    'OTH': 6
}

# =======================================================================
# Load resources
# =======================================================================
with st.spinner("⏳ Loading model and utilities..."):
    model, scaler, feature_names, label_encoders = load_model_and_utils()

if model is None or scaler is None or feature_names is None:
    st.stop()

st.success("✅ Model & utilities loaded.")

# =======================================================================
# Helper: get encoder transform safely (falls back to mapping)
# =======================================================================
def safe_transform_label(encoders, key, value):
    """
    Attempts to transform using LabelEncoder if available and valid.
    If not, falls back to the manual mapping dictionaries above.
    Returns an integer index.
    """
    # If we have encoders and it's a dict with proper LabelEncoder objects
    if isinstance(encoders, dict) and key in encoders:
        encoder = encoders[key]
        # check for transform method
        if hasattr(encoder, 'transform'):
            try:
                return int(encoder.transform([value])[0])
            except Exception:
                # fallback to mapping below
                pass

    # Fallbacks for each key
    if key == 'protocol_type':
        k = value.lower()
        if k in PROTOCOL_MAP:
            return int(PROTOCOL_MAP[k])
        # last resort: return first mapping value
        return int(next(iter(PROTOCOL_MAP.values())))
    elif key == 'service':
        k = value.lower()
        # try exact match, else 'other'
        for serv_key, serv_val in SERVICE_MAP.items():
            if serv_key.lower() == k:
                return int(serv_val)
        return int(SERVICE_MAP.get('other', next(iter(SERVICE_MAP.values()))))
    elif key == 'flag':
        # uppercase flags
        k = value.upper()
        if k in FLAG_MAP:
            return int(FLAG_MAP[k])
        return int(next(iter(FLAG_MAP.values())))
    else:
        # default fallback
        return 0

# =======================================================================
# CSS (same style as before)
# =======================================================================
st.markdown("""
    <style>
        .header-container {
            background: linear-gradient(135deg, #0066cc 0%, #004499 100%);
            padding: 30px 20px;
            border-radius: 12px;
            text-align: center;
            margin-bottom: 20px;
            color: white;
        }
        .header-title { 
            font-size: 2.2em; 
            font-weight: bold; 
            margin: 0;
        }
        .result-box { padding: 20px; border-radius: 10px; text-align:center; font-weight:bold; color:white; margin-top: 15px;}
        .result-normal { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); }
        .result-attack { background: linear-gradient(135deg, #dc3545 0%, #ff6b6b 100%); }
        .metric-card { background: white; padding: 15px; border-radius: 8px; text-align:center; }
        .metric-value { font-size: 1.6em; font-weight: bold; color:#0066cc; }
    </style>
""", unsafe_allow_html=True)

st.markdown("""
    <div class="header-container">
        <div class="header-title">🛡️ IDPS - AI Intrusion Detection System</div>
        <div style="margin-top:8px;color:#e6f0ff;">Manual & Batch analysis (NSL-KDD format)</div>
    </div>
""", unsafe_allow_html=True)

# =======================================================================
# TABS: Manual, Batch, About
# =======================================================================
tab1, tab2, tab3 = st.tabs(["📊 Manual Analysis", "📁 Batch CSV", "ℹ️ About"])

# -------------------
# TAB 1 - Manual
# -------------------
with tab1:
    st.markdown("## 📝 Enter Network Traffic Features (Manual)")

    # split fields into columns for readability
    col1, col2, col3 = st.columns(3)
    features_dict = {}

    with col1:
        features_dict['duration'] = st.number_input("Duration (seconds)", 0, 100000, 100)
        features_dict['src_bytes'] = st.number_input("Source Bytes", 0, 1000000, 250)
        features_dict['dst_bytes'] = st.number_input("Destination Bytes", 0, 1000000, 4000)
        features_dict['land'] = st.number_input("Land (0/1)", 0, 1, 0)
        features_dict['wrong_fragment'] = st.number_input("Wrong Fragment", 0, 100, 0)

    with col2:
        features_dict['urgent'] = st.number_input("Urgent", 0, 100, 0)
        features_dict['hot'] = st.number_input("Hot", 0, 100, 0)
        features_dict['num_failed_logins'] = st.number_input("Failed Logins", 0, 100, 0)
        features_dict['logged_in'] = st.number_input("Logged In (0/1)", 0, 1, 1)
        features_dict['num_compromised'] = st.number_input("Compromised", 0, 100, 0)

    with col3:
        features_dict['serror_rate'] = st.number_input("SYN Error Rate", 0.0, 1.0, 0.0, step=0.01)
        features_dict['srv_serror_rate'] = st.number_input("Service SYN Error", 0.0, 1.0, 0.0, step=0.01)
        features_dict['rerror_rate'] = st.number_input("Reset Error Rate", 0.0, 1.0, 0.0, step=0.01)
        features_dict['srv_rerror_rate'] = st.number_input("Service Reset Error", 0.0, 1.0, 0.0, step=0.01)
        features_dict['same_srv_rate'] = st.number_input("Same Service Rate", 0.0, 1.0, 1.0, step=0.01)

    st.markdown("---")

    col_protocol, col_service, col_flag = st.columns(3)

    with col_protocol:
        st.subheader("Protocol Type")
        # if we have valid encoders and classes, show those, else show PROTOCOL_MAP keys
        try:
            if isinstance(label_encoders, dict) and 'protocol_type' in label_encoders and hasattr(label_encoders['protocol_type'], 'classes_'):
                proto_options = list(label_encoders['protocol_type'].classes_)
            else:
                proto_options = list(PROTOCOL_MAP.keys())
        except Exception:
            proto_options = list(PROTOCOL_MAP.keys())

        protocol_type = st.selectbox("Protocol Type", proto_options)
        # safe transform
        features_dict['protocol_type'] = safe_transform_label(label_encoders, 'protocol_type', protocol_type)

    with col_service:
        st.subheader("Service")
        try:
            if isinstance(label_encoders, dict) and 'service' in label_encoders and hasattr(label_encoders['service'], 'classes_'):
                service_options = list(label_encoders['service'].classes_)
            else:
                # show most common services (fallback)
                service_options = list(SERVICE_MAP.keys())
        except Exception:
            service_options = list(SERVICE_MAP.keys())

        service_choice = st.selectbox("Service", service_options[:50])  # limit dropdown length if large
        features_dict['service'] = safe_transform_label(label_encoders, 'service', service_choice)

    with col_flag:
        st.subheader("Flag")
        try:
            if isinstance(label_encoders, dict) and 'flag' in label_encoders and hasattr(label_encoders['flag'], 'classes_'):
                flag_options = list(label_encoders['flag'].classes_)
            else:
                flag_options = list(FLAG_MAP.keys())
        except Exception:
            flag_options = list(FLAG_MAP.keys())

        flag_choice = st.selectbox("Flag", flag_options)
        features_dict['flag'] = safe_transform_label(label_encoders, 'flag', flag_choice)

    st.markdown("---")

    # add remaining features default to 0 (keeps same order as training feature_names)
    remaining = [f for f in feature_names if f not in features_dict.keys() and f != 'label']
    for feat in remaining:
        # choose default 0, or let user tune if desired (keeps UI compact)
        features_dict[feat] = 0

    st.markdown("### Review input (first 10 features):")
    st.write({k: features_dict[k] for k in list(features_dict.keys())[:10]})

    if st.button("🔍 ANALYZE TRAFFIC", use_container_width=True):
        try:
            # Build input array in correct order
            X_input = np.array([[features_dict[fname] for fname in feature_names]])
            # scale
            X_scaled = scaler.transform(X_input)
            pred = model.predict(X_scaled)[0]
            proba = model.predict_proba(X_scaled)[0]
            conf = max(proba) * 100

            st.markdown("---")
            if pred == 0:
                st.markdown('<div class="result-box result-normal">✅ NORMAL TRAFFIC DETECTED</div>', unsafe_allow_html=True)
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown(f'<div class="metric-card"><div>Confidence</div><div class="metric-value">{conf:.2f}%</div></div>', unsafe_allow_html=True)
                with col_b:
                    st.markdown('<div class="metric-card"><div>Threat</div><div class="metric-value" style="color:#28a745;">LOW</div></div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="result-box result-attack">🚨 ATTACK DETECTED!</div>', unsafe_allow_html=True)
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown(f'<div class="metric-card"><div>Confidence</div><div class="metric-value">{conf:.2f}%</div></div>', unsafe_allow_html=True)
                with col_b:
                    st.markdown('<div class="metric-card"><div>Threat</div><div class="metric-value" style="color:#dc3545;">HIGH</div></div>', unsafe_allow_html=True)
                st.error("⚠️ INTRUSION DETECTED - Take action as required.")

        except Exception as e:
            st.error("❌ Error during prediction: " + str(e))
            st.error(traceback.format_exc())

# -------------------
# TAB 2 - Batch CSV
# -------------------
with tab2:
    st.markdown("## 📁 Batch CSV Analysis (NSL-KDD Format)")
    file = st.file_uploader("Upload CSV file (must contain the same features in same names/order)", type=['csv'])

    if file:
        try:
            df = pd.read_csv(file)
            st.dataframe(df.head(10), use_container_width=True)

            if st.button("🔍 ANALYZE BATCH", use_container_width=True):
                try:
                    # Ensure required features exist
                    missing = [f for f in feature_names if f not in df.columns and f != 'label']
                    if missing:
                        st.error("Uploaded CSV missing features: " + ", ".join(missing))
                    else:
                        X_batch = df[feature_names]
                        # If any categorical columns are still strings, try to convert using safe_transform_label
                        # (Only protocol_type, service, flag are expected to be categorical here)
                        if 'protocol_type' in X_batch.columns and X_batch['protocol_type'].dtype == object:
                            X_batch['protocol_type'] = X_batch['protocol_type'].apply(lambda v: safe_transform_label(label_encoders, 'protocol_type', v))
                        if 'service' in X_batch.columns and X_batch['service'].dtype == object:
                            X_batch['service'] = X_batch['service'].apply(lambda v: safe_transform_label(label_encoders, 'service', v))
                        if 'flag' in X_batch.columns and X_batch['flag'].dtype == object:
                            X_batch['flag'] = X_batch['flag'].apply(lambda v: safe_transform_label(label_encoders, 'flag', v))

                        X_scaled_batch = scaler.transform(X_batch)
                        preds = model.predict(X_scaled_batch)
                        df['Prediction'] = ['🟢 Normal' if p == 0 else '🔴 Attack' for p in preds]

                        normal = (preds == 0).sum()
                        attack = (preds == 1).sum()

                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown(f'<div class="metric-card"><div>Normal</div><div class="metric-value" style="color:#28a745;">{normal}</div></div>', unsafe_allow_html=True)
                        with col2:
                            st.markdown(f'<div class="metric-card"><div>Attacks</div><div class="metric-value" style="color:#dc3545;">{attack}</div></div>', unsafe_allow_html=True)

                        st.dataframe(df, use_container_width=True)
                        csv_data = df.to_csv(index=False)
                        st.download_button("📥 Download Results", csv_data, "idps_results.csv")

                except Exception as e:
                    st.error("❌ Batch analysis error: " + str(e))
                    st.error(traceback.format_exc())
        except Exception as e:
            st.error("❌ Could not read CSV: " + str(e))

# -------------------
# TAB 3 - ABOUT
# -------------------
with tab3:
    st.markdown("""
    ## 🎯 IDPS System - Notes & Troubleshooting

    - This app will try to use the saved `label_encoders` if they were saved as a **dict** of `LabelEncoder` objects.
    - **If encoders were saved incorrectly (for example as a list)**, the app falls back to numeric mappings so it **won't crash**.
    - **IMPORTANT:** fallback numeric mappings (in this file) are placeholders — to preserve prediction quality, replace them with the *exact* integers your training LabelEncoders used or re-save the encoders as a dict.

    ### Quick Manual Test (scenario you provided):
    - Duration: 0
    - Source Bytes: 250
    - Destination Bytes: 4000
    - Logged In: 1
    - Protocol: tcp
    - Service: http
    - Flag: SF
    - Press 🔍 ANALYZE TRAFFIC — expect NORMAL traffic result.

    ### If you still see errors:
    1. Copy the full traceback shown in the app and paste here.
    2. If encoders show as a list, re-save encoders during training as a dict:
       ```
       label_encoders = {'protocol_type': le_proto, 'service': le_service, 'flag': le_flag}
       joblib.dump(label_encoders, 'label_encoders.joblib')
       ```
    3. Or update the PROTOCOL_MAP / SERVICE_MAP / FLAG_MAP above to match the integers used by your encoders.

    """)

    # Show debug indicator if encoders invalid
    if not isinstance(label_encoders, dict):
        st.warning("⚠️ Label encoders not loaded as dict. App is using fallback mappings. For best accuracy, re-save encoders as a dict of LabelEncoder objects.")
    else:
        st.success("✅ Label encoders loaded correctly (using real encoders).")
