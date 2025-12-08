import streamlit as st
import pandas as pd
import numpy as np
import joblib
import gdown
import os

st.set_page_config(page_title="IDPS System", page_icon="🛡️", layout="wide")

MODEL_FILE_ID = "1ROjXla7J_wAEpaWBVPFR88pOxlZRAmbe"
SCALER_FILE_ID = "1tHV0P3yPbblm_8Lds9bRMyTnSdDLvu7n"
FEATURES_FILE_ID = "1fbREKxsJ4n3m_n1n6ExrQzpmeaXG9DIx"

@st.cache_resource
def load_all_files_safe():
    model = None
    scaler = None
    feature_names = None
    
    try:
        if not os.path.exists('idps_model.joblib'):
            gdown.download(f'https://drive.google.com/uc?id={MODEL_FILE_ID}', 'idps_model.joblib', quiet=False)
        model = joblib.load('idps_model.joblib')
        st.success(f"✅ Model: {type(model).__name__}")
    except Exception as e:
        st.error(f"❌ Model: {e}")
    
    try:
        if not os.path.exists('feature_scaler.joblib'):
            gdown.download(f'https://drive.google.com/uc?id={SCALER_FILE_ID}', 'feature_scaler.joblib', quiet=False)
        scaler = joblib.load('feature_scaler.joblib')
        st.warning(f"⚠️ Scaler: {type(scaler).__name__} - DISABLED FOR TEST")
        scaler = None  # ✅ DISABLE SCALER FOR NOW
    except Exception as e:
        st.warning(f"⚠️ Scaler: {e}")
        scaler = None
    
    try:
        if not os.path.exists('feature_names.joblib'):
            gdown.download(f'https://drive.google.com/uc?id={FEATURES_FILE_ID}', 'feature_names.joblib', quiet=False)
        feature_names = joblib.load('feature_names.joblib')
        st.success(f"✅ Features: {len(feature_names)} features loaded")
    except Exception as e:
        st.warning(f"⚠️ Features: {e}")
    
    return model, scaler, feature_names

st.markdown("""
    <style>
        .header-container { background: linear-gradient(135deg, #0066cc 0%, #004499 100%); padding: 40px 20px; border-radius: 15px; text-align: center; margin-bottom: 30px; color: white; }
        .header-title { font-size: 2.8em; font-weight: bold; margin: 0; }
        .result-normal { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); padding: 25px; border-radius: 12px; text-align: center; color: white; font-size: 1.5em; font-weight: bold; }
        .result-attack { background: linear-gradient(135deg, #dc3545 0%, #ff6b6b 100%); padding: 25px; border-radius: 12px; text-align: center; color: white; font-size: 1.5em; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

st.markdown('<div class="header-container"><p class="header-title">🛡️ IDPS System</p></div>', unsafe_allow_html=True)

model, scaler, feature_names = load_all_files_safe()

if model is None:
    st.error("❌ Cannot load model!")
    st.stop()

st.success("✅ Ready!")

tab1, tab2, tab3 = st.tabs(["📊 Manual", "📁 Batch", "ℹ️ About"])

with tab1:
    st.markdown("## Manual Analysis")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        duration = st.number_input("Duration", 0, 100000, 103)
        src_bytes = st.number_input("Source Bytes", 0, 1000000, 3192)
        dst_bytes = st.number_input("Dest Bytes", 0, 1000000, 566)
        land = st.number_input("Land", 0, 1, 0)
    
    with col2:
        urgent = st.number_input("Urgent", 0, 100, 0)
        hot = st.number_input("Hot", 0, 100, 0)
        num_failed_logins = st.number_input("Failed Logins", 0, 100, 0)
        logged_in = st.number_input("Logged In", 0, 1, 1)
    
    with col3:
        st.subheader("Error Rates")
        serror_rate = st.number_input("SYN Error Rate", 0.0, 1.0, 0.0521, step=0.0001, format="%.4f")
        srv_serror_rate = st.number_input("Srv SYN Error", 0.0, 1.0, 0.0139, step=0.0001, format="%.4f")
        rerror_rate = st.number_input("Reset Error", 0.0, 1.0, 0.0292, step=0.0001, format="%.4f")
        same_srv_rate = st.number_input("Same Srv Rate", 0.0, 1.0, 0.6521, step=0.0001, format="%.4f")
    
    st.markdown("---")
    
    protocol = st.radio("Protocol", ["TCP (6)", "UDP (17)", "ICMP (1)"], horizontal=True, index=0)
    service = st.radio("Service", ["HTTP (0)", "SMTP (1)", "FTP (6)", "SSH (5)"], horizontal=True, index=0)
    flag = st.radio("Flag", ["SF (0)", "S0 (1)", "REJ (2)", "SH (7)"], horizontal=True, index=0)
    
    protocol_num = int(protocol.split("(")[1].split(")")[0])
    service_num = int(service.split("(")[1].split(")")[0])
    flag_num = int(flag.split("(")[1].split(")")[0])
    
    if st.button("🔍 ANALYZE", use_container_width=True):
        try:
            input_dict = {
                'duration': float(duration),
                'protocol_type': float(protocol_num),
                'service': float(service_num),
                'flag': float(flag_num),
                'src_bytes': float(src_bytes),
                'dst_bytes': float(dst_bytes),
                'land': float(land),
                'wrong_fragment': 0.0,
                'urgent': float(urgent),
                'hot': float(hot),
                'num_failed_logins': float(num_failed_logins),
                'logged_in': float(logged_in),
                'num_compromised': 0.0,
                'root_shell': 0.0,
                'su_attempted': 0.0,
                'num_root': 0.0,
                'num_file_creations': 0.0,
                'num_shells': 0.0,
                'num_access_files': 0.0,
                'num_outbound_cmds': 0.0,
                'is_host_login': 0.0,
                'is_guest_login': 0.0,
                'count': 10.0,
                'srv_count': 10.0,
                'serror_rate': float(serror_rate),
                'srv_serror_rate': float(srv_serror_rate),
                'rerror_rate': float(rerror_rate),
                'srv_rerror_rate': 0.0,
                'same_srv_rate': float(same_srv_rate),
                'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': 50.0,
                'dst_host_srv_count': 50.0,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 0.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
            
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
            
            X = np.array([[input_dict[f] for f in feature_order]])
            
            # DEBUG: Show raw values
            st.info(f"📊 Raw Feature Array Shape: {X.shape}")
            st.write(f"First 10 values: {X[0][:10]}")
            
            # NO SCALING - test without it
            if scaler and not isinstance(scaler, (list, dict)):
                st.write("Attempting to scale...")
                X = scaler.transform(X)
            
            st.write(f"After scaling: {X[0][:10]}")
            
            # Predict
            pred = model.predict(X)[0]
            proba = model.predict_proba(X)[0]
            conf = max(proba) * 100
            
            st.markdown("---")
            
            # DEBUG: Show prediction proba
            st.write(f"Prediction: {pred}")
            st.write(f"Probabilities: Normal={proba[0]*100:.2f}%, Attack={proba[1]*100:.2f}%")
            
            if pred == 0:
                st.markdown('<div class="result-normal">✅ NORMAL</div>', unsafe_allow_html=True)
                st.success(f"Confidence: {conf:.1f}%")
            else:
                st.markdown('<div class="result-attack">🚨 ATTACK!</div>', unsafe_allow_html=True)
                st.error(f"Confidence: {conf:.1f}%")
        
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")
            import traceback
            st.error(traceback.format_exc())

with tab2:
    st.markdown("## Batch CSV")
    file = st.file_uploader("Upload CSV", type=['csv'])
    if file:
        df = pd.read_csv(file)
        st.dataframe(df.head())
        if st.button("🔍 ANALYZE BATCH"):
            try:
                cols = feature_names if feature_names else df.columns.tolist()
                X = df[cols]
                preds = model.predict(X)
                df['Prediction'] = ['Normal' if p == 0 else 'Attack' for p in preds]
                st.dataframe(df)
                st.download_button("📥 Download", df.to_csv(index=False), "results.csv")
            except Exception as e:
                st.error(f"Error: {e}")

with tab3:
    st.markdown("## IDPS System")
