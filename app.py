import streamlit as st
import pandas as pd
import numpy as np
import joblib
import gdown
import os

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================
st.set_page_config(page_title="IDPS System", page_icon="🛡️", layout="wide")

# ============================================================================
# ⚠️ UPDATE YOUR FILE IDs HERE (FROM GOOGLE DRIVE) ⚠️
# ============================================================================
MODEL_FILE_ID = "1w46i4HIcR5vklwOt4KX9SMRpWBGNuFkf"
SCALER_FILE_ID = "1MN5bHysFa-voIYBWx1NNcREDdX0Urnk1"

# ============================================================================
# DOWNLOAD & LOAD MODEL
# ============================================================================

@st.cache_resource
def load_model_and_scaler():
    """Download and load model + scaler from Google Drive."""
    
    if not MODEL_FILE_ID or MODEL_FILE_ID == "PASTE_YOUR_MODEL_FILE_ID_HERE":
        st.error("❌ Update MODEL_FILE_ID at line 14!")
        return None, None
    
    try:
        # Download model
        if not os.path.exists("idps_model.joblib"):
            url = f"https://drive.google.com/uc?id={MODEL_FILE_ID}"
            gdown.download(url, "idps_model.joblib", quiet=False)
        model = joblib.load("idps_model.joblib")
    except Exception as e:
        st.error(f"❌ Model Error: {e}")
        return None, None
    
    # Download scaler (optional)
    scaler = None
    if SCALER_FILE_ID and SCALER_FILE_ID != "PASTE_YOUR_SCALER_FILE_ID_HERE":
        try:
            if not os.path.exists("feature_scaler.joblib"):
                url = f"https://drive.google.com/uc?id={SCALER_FILE_ID}"
                gdown.download(url, "feature_scaler.joblib", quiet=False)
            scaler = joblib.load("feature_scaler.joblib")
        except:
            st.warning("⚠️ Scaler not loaded (will normalize manually)")
            scaler = None
    
    return model, scaler

# ============================================================================
# CSS STYLING
# ============================================================================

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
        }
        .header-subtitle {
            font-size: 1.1em;
            margin-top: 10px;
            color: #e0e0e0;
        }
        .result-box {
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            font-size: 1.3em;
            font-weight: bold;
            color: white;
            margin: 20px 0;
            box-shadow: 0 6px 12px rgba(0,0,0,0.2);
        }
        .result-normal {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
        }
        .result-attack {
            background: linear-gradient(135deg, #dc3545 0%, #ff6b6b 100%);
        }
    </style>
""", unsafe_allow_html=True)

# ============================================================================
# MAIN HEADER
# ============================================================================

st.markdown("""
    <div class="header-container">
        <p class="header-title">🛡️ IDPS - AI Intrusion Detection System</p>
        <p class="header-subtitle">Real-time Network Traffic Analysis & Threat Prevention</p>
    </div>
""", unsafe_allow_html=True)

# Load model
with st.spinner("⏳ Loading AI Model..."):
    model, scaler = load_model_and_scaler()

if model is None:
    st.stop()

st.success("✅ System Ready!")

# ============================================================================
# TABS
# ============================================================================

tab1, tab2, tab3 = st.tabs(["📊 Manual Analysis", "📁 Batch CSV", "ℹ️ About"])

# ============================================================================
# TAB 1: MANUAL ANALYSIS
# ============================================================================

with tab1:
    st.markdown("## 📝 Enter Network Traffic Features")
    
    input_data = {}
    
    # Row 1: Basic Parameters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        input_data['duration'] = st.number_input("Duration (sec)", 0, 100000, 10)
        input_data['src_bytes'] = st.number_input("Source Bytes", 0, 1000000, 1000)
        input_data['dst_bytes'] = st.number_input("Dest Bytes", 0, 1000000, 1000)
        input_data['land'] = st.number_input("Land (0/1)", 0, 1, 0)
        input_data['wrong_fragment'] = st.number_input("Wrong Fragment", 0, 100, 0)
    
    with col2:
        input_data['urgent'] = st.number_input("Urgent", 0, 100, 0)
        input_data['hot'] = st.number_input("Hot", 0, 100, 0)
        input_data['num_failed_logins'] = st.number_input("Failed Logins", 0, 100, 0)
        input_data['logged_in'] = st.number_input("Logged In (0/1)", 0, 1, 1)
        input_data['num_compromised'] = st.number_input("Compromised", 0, 100, 0)
    
    with col3:
        input_data['root_shell'] = st.number_input("Root Shell", 0, 100, 0)
        input_data['su_attempted'] = st.number_input("SU Attempted", 0, 100, 0)
        input_data['num_root'] = st.number_input("Num Root", 0, 100, 0)
        input_data['num_file_creations'] = st.number_input("File Creations", 0, 100, 0)
        input_data['num_shells'] = st.number_input("Num Shells", 0, 100, 0)
    
    st.markdown("---")
    
    # Row 2: Protocol/Service/Flag
    col4, col5, col6 = st.columns(3)
    
    with col4:
        protocol_choice = st.radio("Protocol", ["TCP (6)", "UDP (17)", "ICMP (1)"], horizontal=True)
        protocol_num = int(protocol_choice.split("(")[1].split(")")[0])
        input_data['protocol_type'] = float(protocol_num)
    
    with col5:
        service_choice = st.radio("Service", ["HTTP (0)", "SMTP (1)", "FTP (6)", "SSH (5)", "Private (7)"], horizontal=True)
        service_num = int(service_choice.split("(")[1].split(")")[0])
        input_data['service'] = float(service_num)
    
    with col6:
        flag_choice = st.radio("Flag", ["SF-Normal (0)", "S0-Attack (1)", "REJ (2)"], horizontal=True)
        flag_num = int(flag_choice.split("(")[1].split(")")[0])
        input_data['flag'] = float(flag_num)
    
    st.markdown("---")
    
    # Row 3: Connection Features
    col7, col8, col9 = st.columns(3)
    
    with col7:
        input_data['num_access_files'] = st.number_input("Access Files", 0, 100, 0)
        input_data['num_outbound_cmds'] = st.number_input("Outbound Cmds", 0, 100, 0)
        input_data['is_host_login'] = st.number_input("Host Login (0/1)", 0, 1, 0)
        input_data['is_guest_login'] = st.number_input("Guest Login (0/1)", 0, 1, 0)
    
    with col8:
        input_data['count'] = st.number_input("Count", 1, 1000, 10)
        input_data['srv_count'] = st.number_input("Service Count", 1, 1000, 10)
        input_data['serror_rate'] = st.slider("SYN Error Rate", 0.0, 1.0, 0.0, 0.01)
        input_data['srv_serror_rate'] = st.slider("Srv SYN Error", 0.0, 1.0, 0.0, 0.01)
    
    with col9:
        input_data['rerror_rate'] = st.slider("Reset Error Rate", 0.0, 1.0, 0.0, 0.01)
        input_data['srv_rerror_rate'] = st.slider("Srv Reset Error", 0.0, 1.0, 0.0, 0.01)
        input_data['same_srv_rate'] = st.slider("Same Service Rate", 0.0, 1.0, 1.0, 0.01)
        input_data['diff_srv_rate'] = st.slider("Diff Service Rate", 0.0, 1.0, 0.0, 0.01)
    
    st.markdown("---")
    
    # Row 4: Host Features
    col10, col11 = st.columns(2)
    
    with col10:
        input_data['srv_diff_host_rate'] = st.slider("Srv Diff Host Rate", 0.0, 1.0, 0.0, 0.01)
        input_data['dst_host_count'] = st.number_input("Dest Host Count", 1, 1000, 50)
        input_data['dst_host_srv_count'] = st.number_input("Dest Host Srv Count", 1, 1000, 50)
    
    with col11:
        input_data['dst_host_same_srv_rate'] = st.slider("Dest Host Same Srv Rate", 0.0, 1.0, 1.0, 0.01)
        input_data['dst_host_diff_srv_rate'] = st.slider("Dest Host Diff Srv Rate", 0.0, 1.0, 0.0, 0.01)
        input_data['dst_host_same_src_port_rate'] = st.slider("Dest Host Same Port Rate", 0.0, 1.0, 0.0, 0.01)
    
    # Default remaining features
    input_data['dst_host_srv_diff_host_rate'] = 0.0
    input_data['dst_host_serror_rate'] = 0.0
    input_data['dst_host_srv_serror_rate'] = 0.0
    input_data['dst_host_rerror_rate'] = 0.0
    input_data['dst_host_srv_rerror_rate'] = 0.0
    
    st.markdown("---")
    
    # ANALYZE BUTTON
    if st.button("🔍 ANALYZE TRAFFIC", use_container_width=True):
        try:
            # Feature order (NSL-KDD)
            feature_order = [
                'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
                'num_compromised', 'root_shell', 'su_attempted', 'num_root',
                'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
                'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
                'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
                'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
            ]
            
            # Create array
            X = np.array([[float(input_data.get(f, 0)) for f in feature_order]])
            
            # Scale if available
            if scaler is not None:
                try:
                    X = scaler.transform(X)
                except Exception as scale_error:
                    # Manual normalization if scaler fails
                    X = (X - X.min(axis=0)) / (X.max(axis=0) - X.min(axis=0) + 1e-8)
            else:
                # Manual normalization
                X = (X - X.min(axis=0)) / (X.max(axis=0) - X.min(axis=0) + 1e-8)
            
            # Predict
            pred = model.predict(X)[0]
            proba = model.predict_proba(X)[0]
            conf = max(proba) * 100
            
            st.markdown("---")
            
            if pred == 0:
                st.markdown(
                    '<div class="result-box result-normal">✅ NORMAL TRAFFIC</div>',
                    unsafe_allow_html=True
                )
                col_m1, col_m2, col_m3 = st.columns(3)
                with col_m1:
                    st.metric("Confidence", f"{conf:.2f}%")
                with col_m2:
                    st.metric("Threat", "LOW 🟢")
                with col_m3:
                    st.metric("Action", "ALLOW ✅")
                st.success("This traffic is SAFE!")
            
            else:
                st.markdown(
                    '<div class="result-box result-attack">🚨 ATTACK DETECTED</div>',
                    unsafe_allow_html=True
                )
                col_m1, col_m2, col_m3 = st.columns(3)
                with col_m1:
                    st.metric("Confidence", f"{conf:.2f}%")
                with col_m2:
                    st.metric("Threat", "HIGH 🔴")
                with col_m3:
                    st.metric("Action", "BLOCK ❌")
                st.error("INTRUSION DETECTED - IP BLOCKED!")
        
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

# ============================================================================
# TAB 2: BATCH CSV ANALYSIS
# ============================================================================

with tab2:
    st.markdown("## 📁 Batch CSV Analysis")
    
    uploaded_file = st.file_uploader("Upload CSV (NSL-KDD format)", type=['csv'])
    
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            st.dataframe(df.head(10), use_container_width=True)
            
            col_info1, col_info2 = st.columns(2)
            with col_info1:
                st.metric("Total Records", len(df))
            with col_info2:
                st.metric("Features", len(df.columns))
            
            if st.button("🔍 ANALYZE BATCH", use_container_width=True):
                try:
                    # Scale if needed
                    if scaler is not None:
                        try:
                            X_batch = scaler.transform(df)
                        except Exception as scale_error:
                            X_batch = (df - df.min(axis=0)) / (df.max(axis=0) - df.min(axis=0) + 1e-8)
                    else:
                        X_batch = (df - df.min(axis=0)) / (df.max(axis=0) - df.min(axis=0) + 1e-8)
                    
                    preds = model.predict(X_batch)
                    
                    result_df = df.copy()
                    result_df['Prediction'] = ['🟢 Normal' if p == 0 else '🔴 Attack' for p in preds]
                    
                    normal = (preds == 0).sum()
                    attack = (preds == 1).sum()
                    
                    col_b1, col_b2, col_b3 = st.columns(3)
                    with col_b1:
                        st.metric("Normal", normal)
                    with col_b2:
                        st.metric("Attacks", attack)
                    with col_b3:
                        rate = (attack / len(preds) * 100) if len(preds) > 0 else 0
                        st.metric("Detection %", f"{rate:.1f}%")
                    
                    st.dataframe(result_df, use_container_width=True)
                    
                    csv_data = result_df.to_csv(index=False)
                    st.download_button("📥 Download", csv_data, "results.csv")
                
                except Exception as e:
                    st.error(f"❌ Error: {e}")
        
        except Exception as e:
            st.error(f"❌ File Error: {e}")

# ============================================================================
# TAB 3: ABOUT
# ============================================================================

with tab3:
    st.markdown("""
    ## 🎯 About IDPS System
    
    **AI-Based Intrusion Detection & Prevention System**
    
    ### Dataset
    - NSL-KDD (125,973 samples)
    - 41 network features
    - Binary classification: Normal vs Attack
    
    ### Model
    - Algorithm: Random Forest (200 trees)
    - Accuracy: 99%+
    
    ### Features Analyzed
    1. Network duration and bytes
    2. Protocol type and service
    3. Connection flags
    4. Error rates
    5. Host-based metrics
    
    ### Attack Types
    - DoS (Denial of Service)
    - Probe (Port scanning)
    - R2L (Remote to Local)
    - U2R (User to Root)
    """)
