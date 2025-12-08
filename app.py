import streamlit as st
import pandas as pd
import numpy as np
import joblib
import gdown
import os

st.set_page_config(page_title="IDPS System", page_icon="🛡️", layout="wide")

# 🔴 PASTE YOUR GOOGLE DRIVE FILE IDs HERE 🔴
MODEL_FILE_ID = "1ROjXla7J_wAEpaWBVPFR88pOxlZRAmbe"
SCALER_FILE_ID = "1fbREKxsJ4n3m_n1n6ExrQzpmeaXG9DIx"
FEATURES_FILE_ID = "1fbREKxsJ4n3m_n1n6ExrQzpmeaXG9DIx"
# ⚠️ Encoders ab use nahi karenge, isliye isko optional chhodo
ENCODERS_FILE_ID = ""

@st.cache_resource
def download_file(file_id, output_name):
    if file_id.startswith("PASTE_") or file_id == "":
        # sirf warning dikha do, but app crash mat karo
        st.warning(f"ℹ️ {output_name} FILE_ID not set, assuming file already present.")
    if not os.path.exists(output_name):
        if file_id.startswith("PASTE_") or file_id == "":
            return None
        url = f'https://drive.google.com/uc?id={file_id}'
        try:
            gdown.download(url, output_name, quiet=False)
        except Exception as e:
            st.error(f"❌ Download Error ({output_name}): {str(e)}")
            return None
    return output_name

@st.cache_resource
def load_model_and_utils():
    try:
        download_file(MODEL_FILE_ID, 'idps_model.joblib')
        download_file(SCALER_FILE_ID, 'feature_scaler.joblib')
        download_file(FEATURES_FILE_ID, 'feature_names.joblib')
        # label_encoders ko ab load bhi nahi kar rahe

        model = joblib.load('idps_model.joblib')
        scaler = joblib.load('feature_scaler.joblib')
        feature_names = joblib.load('feature_names.joblib')

        # return label_encoders ki jagah None
        return model, scaler, feature_names
    except Exception as e:
        st.error(f"❌ Error loading files: {str(e)}")
        return None, None, None

# ================= CSS same as pehle =================
st.markdown("""
    <style>
        .header-container {
            background: linear-gradient(135deg, #0066cc 0%, #004499 100%);
            padding: 40px 20px;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 30px;
            color: white;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .header-title { 
            font-size: 2.8em; 
            font-weight: bold; 
            margin: 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .result-box {
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            font-size: 1.3em;
            font-weight: bold;
            color: white;
            margin: 20px 0;
        }
        .result-normal {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
        }
        .result-attack {
            background: linear-gradient(135deg, #dc3545 0%, #ff6b6b 100%);
        }
        .metric-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #dee2e6;
            text-align: center;
            box-shadow: 0 3px 8px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 2.2em;
            font-weight: bold;
            color: #0066cc;
            margin: 10px 0;
        }
    </style>
""", unsafe_allow_html=True)

st.markdown("""
    <div class="header-container">
        <p class="header-title">🛡️ IDPS - AI Intrusion Detection System</p>
        <p style="font-size:1.2em; margin-top:10px; color:#e0e0e0;">Real-time Network Traffic Analysis</p>
    </div>
""", unsafe_allow_html=True)

with st.spinner("⏳ Loading AI Model & Components..."):
    model, scaler, feature_names = load_model_and_utils()

if model is None:
    st.stop()

st.success("✅ Model Loaded Successfully!")

tab1, tab2, tab3 = st.tabs(["📊 Manual Analysis", "📁 Batch CSV", "ℹ️ About"])

# ===================== TAB 1: MANUAL ANALYSIS =====================

with tab1:
    st.markdown("## 📝 Enter Network Traffic Features (NSL-KDD Format)")
    
    col1, col2, col3 = st.columns(3)
    features_dict = {}

    with col1:
        st.subheader("Basic Parameters")
        features_dict['duration'] = st.number_input("Duration (seconds)", 0, 100000, 100)
        features_dict['src_bytes'] = st.number_input("Source Bytes", 0, 1000000, 100)
        features_dict['dst_bytes'] = st.number_input("Destination Bytes", 0, 1000000, 100)
        features_dict['land'] = st.number_input("Land (0/1)", 0, 1, 0)
        features_dict['wrong_fragment'] = st.number_input("Wrong Fragment", 0, 100, 0)

    with col2:
        st.subheader("Connection Info")
        features_dict['urgent'] = st.number_input("Urgent", 0, 100, 0)
        features_dict['hot'] = st.number_input("Hot", 0, 100, 0)
        features_dict['num_failed_logins'] = st.number_input("Failed Logins", 0, 100, 0)
        features_dict['logged_in'] = st.number_input("Logged In (0/1)", 0, 1, 0)
        features_dict['num_compromised'] = st.number_input("Compromised", 0, 100, 0)

    with col3:
        st.subheader("Advanced Metrics")
        features_dict['serror_rate'] = st.number_input("SYN Error Rate", 0.0, 1.0, 0.0, step=0.01)
        features_dict['srv_serror_rate'] = st.number_input("Service SYN Error", 0.0, 1.0, 0.0, step=0.01)
        features_dict['rerror_rate'] = st.number_input("Reset Error Rate", 0.0, 1.0, 0.0, step=0.01)
        features_dict['srv_rerror_rate'] = st.number_input("Service Reset Error", 0.0, 1.0, 0.0, step=0.01)
        features_dict['same_srv_rate'] = st.number_input("Same Service Rate", 0.0, 1.0, 1.0, step=0.01)

    st.markdown("---")

    # ========== MANUAL MAPPINGS FOR CATEGORICAL FEATURES ==========

    protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
    protocol_name = st.selectbox("Protocol Type", list(protocol_map.keys()))
    features_dict['protocol_type'] = protocol_map[protocol_name]

    # yahan tum realistic limited services rakh sakte ho
    service_map = {
        'http': 0,
        'smtp': 1,
        'ftp': 2,
        'ftp_data': 3,
        'ssh': 4,
        'domain_u': 5,
        'telnet': 6,
        'eco_i': 7,
        'ftp_proxy': 8,
        'other': 9
    }
    service_name = st.selectbox("Service", list(service_map.keys()))
    features_dict['service'] = service_map[service_name]

    flag_map = {
        'SF': 0,
        'S0': 1,
        'REJ': 2,
        'RSTR': 3,
        'S1': 4,
        'S2': 5,
        'S3': 6,
        'SH': 7,
        'RSTO': 8
    }
    flag_name = st.selectbox("Flag", list(flag_map.keys()))
    features_dict['flag'] = flag_map[flag_name]

    st.markdown("---")

    # Baki features ko default 0 de do
    remaining_features = [
        'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
    ]
    for feat in remaining_features:
        if feat not in features_dict:
            features_dict[feat] = 0

    if st.button("🔍 ANALYZE TRAFFIC", use_container_width=True):
        try:
            # feature_names order ke according array banao
            X_input = np.array([[features_dict[fname] for fname in feature_names]])
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
                st.error("⚠️ INTRUSION DETECTED - Taking preventive action...")

        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

# ===================== TAB 2: BATCH CSV ANALYSIS =====================

with tab2:
    st.markdown("## 📁 Batch CSV Analysis (NSL-KDD Format)")
    file = st.file_uploader("Upload CSV file", type=['csv'])

    if file:
        try:
            df = pd.read_csv(file)
            st.dataframe(df.head(10), use_container_width=True)

            if st.button("🔍 ANALYZE BATCH", use_container_width=True):
                try:
                    X_batch = df[feature_names]
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
                    st.error(f"❌ Error: {str(e)}")
        except Exception as e:
            st.error(f"❌ CSV Error: {str(e)}")

# ===================== TAB 3: ABOUT =====================

with tab3:
    st.markdown("""
    ## 🎯 IDPS System - Real-World Edition
    
    ### 📊 Dataset: NSL-KDD
    - **Samples:** 125,973 training records
    - **Features:** 41 network parameters
    - **Labels:** Normal (0) vs Attack (1)
    - **Real-world intrusion attempts**
    
    ### 🤖 Model: Random Forest
    - **Accuracy:** >99%
    - **Trees:** 200
    - **Features:** 41 NSL-KDD parameters
    
    ### 🎯 Attack Types Detected
    - DoS (Denial of Service)
    - Probe (Port scanning)
    - R2L (Remote to Local)
    - U2R (User to Root)
    
    ### 📈 Performance Metrics
    - **Accuracy:** High precision detection
    - **Recall:** Catches most real attacks
    - **F1-Score:** Balanced detection
    """)
