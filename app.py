# ============================================================================
# app.py - CORRECTED VERSION
# ============================================================================

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import gdown
import os

st.set_page_config(page_title="IDPS System", page_icon="🛡️", layout="wide")

# Google Drive File IDs (Update these with your new files)
MODEL_FILE_ID = "1mM0QSUwYITYdMbVtobD8ypI4qEXDOV55"  # Replace with actual
SCALER_FILE_ID = "1fJdATmcCzuvxrlJsdmC71rIigKF8k9PI"  # Replace with actual
FEATURES_FILE_ID = "1N95ZHeJ7AzaBfxcQV3QQ6IK7yA7BJa_z"  # Replace with actual
ENCODERS_FILE_ID = "1GQHLaphw1Adld6ppKY57u1oDkDId4YhL"  # Replace with actual

@st.cache_resource
def load_all_files():
    """Load all necessary files"""
    files = {}
    
    # Model
    try:
        if not os.path.exists('idps_model.joblib'):
            gdown.download(f'https://drive.google.com/uc?id={MODEL_FILE_ID}', 'idps_model.joblib', quiet=False)
        files['model'] = joblib.load('idps_model.joblib')
        st.success(f"✅ Model loaded: {type(files['model']).__name__}")
    except Exception as e:
        st.error(f"❌ Model error: {e}")
        return None
    
    # Scaler
    try:
        if not os.path.exists('feature_scaler.joblib'):
            gdown.download(f'https://drive.google.com/uc?id={SCALER_FILE_ID}', 'feature_scaler.joblib', quiet=False)
        files['scaler'] = joblib.load('feature_scaler.joblib')
        st.success(f"✅ Scaler loaded")
    except:
        st.warning("⚠️ Scaler not available")
        files['scaler'] = None
    
    # Features
    try:
        if not os.path.exists('feature_names.joblib'):
            gdown.download(f'https://drive.google.com/uc?id={FEATURES_FILE_ID}', 'feature_names.joblib', quiet=False)
        files['features'] = joblib.load('feature_names.joblib')
        st.success(f"✅ {len(files['features'])} features loaded")
    except:
        st.warning("⚠️ Features not available")
        files['features'] = None
    
    # Encoders
    try:
        if not os.path.exists('label_encoders.joblib'):
            gdown.download(f'https://drive.google.com/uc?id={ENCODERS_FILE_ID}', 'label_encoders.joblib', quiet=False)
        files['encoders'] = joblib.load('label_encoders.joblib')
        st.success(f"✅ Encoders loaded")
    except:
        st.warning("⚠️ Encoders not available")
        files['encoders'] = None
    
    return files

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
        }
        .header-title {
            font-size: 2.8em;
            font-weight: bold;
            margin: 0;
        }
        .result-normal {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            color: white;
            font-size: 1.5em;
            font-weight: bold;
            margin: 20px 0;
        }
        .result-attack {
            background: linear-gradient(135deg, #dc3545 0%, #ff6b6b 100%);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            color: white;
            font-size: 1.5em;
            font-weight: bold;
            margin: 20px 0;
        }
        .feature-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            border-left: 4px solid #0066cc;
            margin: 10px 0;
        }
    </style>
""", unsafe_allow_html=True)

# ============================================================================
# HEADER
# ============================================================================
st.markdown('<div class="header-container"><p class="header-title">🛡️ AI-Powered IDPS System</p></div>', unsafe_allow_html=True)

# ============================================================================
# LOAD FILES
# ============================================================================
with st.spinner("Loading AI model..."):
    files = load_all_files()

if not files or 'model' not in files:
    st.error("❌ Failed to load model. Please check file IDs!")
    st.stop()

st.success("✅ System Ready for Intrusion Detection!")

# ============================================================================
# TABS
# ============================================================================
tab1, tab2, tab3, tab4 = st.tabs(["🔍 Real-time Detection", "📁 Batch Analysis", "📊 System Info", "🛠️ Test Samples"])

# ============================================================================
# TAB 1: REAL-TIME DETECTION
# ============================================================================
with tab1:
    st.markdown("## 🔍 Real-time Network Traffic Analysis")
    st.info("Enter network traffic parameters below for real-time analysis")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.subheader("Connection Features")
        duration = st.number_input("Duration (seconds)", 0.0, 100000.0, 0.0, step=0.1)
        protocol_type = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"], index=0)
        service = st.selectbox("Service", ["http", "smtp", "ftp", "ssh", "domain_u", "private", "eco_i", "ecr_i"], index=0)
        flag = st.selectbox("Connection Flag", ["SF", "S0", "REJ", "RSTR", "SH", "RSTO", "S1", "S2", "S3"], index=0)
    
    with col2:
        st.subheader("Traffic Volume")
        src_bytes = st.number_input("Source Bytes", 0, 1000000, 0)
        dst_bytes = st.number_input("Destination Bytes", 0, 1000000, 0)
        count = st.number_input("Connection Count", 0, 500, 0)
        srv_count = st.number_input("Service Count", 0, 500, 0)
    
    with col3:
        st.subheader("Error Rates")
        serror_rate = st.slider("SYN Error Rate", 0.0, 1.0, 0.0, 0.01)
        srv_serror_rate = st.slider("Service SYN Error Rate", 0.0, 1.0, 0.0, 0.01)
        rerror_rate = st.slider("REJ Error Rate", 0.0, 1.0, 0.0, 0.01)
        same_srv_rate = st.slider("Same Service Rate", 0.0, 1.0, 0.0, 0.01)
    
    # Advanced features (collapsible)
    with st.expander("⚙️ Advanced Features"):
        col4, col5 = st.columns(2)
        with col4:
            logged_in = st.selectbox("Logged In", [0, 1], index=0)
            num_failed_logins = st.number_input("Failed Logins", 0, 10, 0)
            urgent = st.number_input("Urgent Packets", 0, 100, 0)
            hot = st.number_input("Hot Indicators", 0, 100, 0)
        
        with col5:
            wrong_fragment = st.number_input("Wrong Fragments", 0, 10, 0)
            num_root = st.number_input("Root Accesses", 0, 10, 0)
            num_file_creations = st.number_input("File Creations", 0, 10, 0)
            num_shells = st.number_input("Shell Prompts", 0, 10, 0)
    
    st.markdown("---")
    
    if st.button("🚀 ANALYZE TRAFFIC", type="primary", use_container_width=True):
        try:
            # Prepare input dictionary
            input_data = {
                'duration': duration,
                'protocol_type': protocol_type,
                'service': service,
                'flag': flag,
                'src_bytes': src_bytes,
                'dst_bytes': dst_bytes,
                'land': 0,
                'wrong_fragment': wrong_fragment,
                'urgent': urgent,
                'hot': hot,
                'num_failed_logins': num_failed_logins,
                'logged_in': logged_in,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': num_root,
                'num_file_creations': num_file_creations,
                'num_shells': num_shells,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': count,
                'srv_count': srv_count,
                'serror_rate': serror_rate,
                'srv_serror_rate': srv_serror_rate,
                'rerror_rate': rerror_rate,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': same_srv_rate,
                'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
                'dst_host_count': 100,
                'dst_host_srv_count': 50,
                'dst_host_same_srv_rate': 0.5,
                'dst_host_diff_srv_rate': 0.5,
                'dst_host_same_src_port_rate': 0.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': serror_rate,
                'dst_host_srv_serror_rate': srv_serror_rate,
                'dst_host_rerror_rate': rerror_rate,
                'dst_host_srv_rerror_rate': 0.0
            }
            
            # Convert to DataFrame
            input_df = pd.DataFrame([input_data])
            
            # Encode categorical features
            if 'encoders' in files and files['encoders']:
                for col in ['protocol_type', 'service', 'flag']:
                    if col in input_df.columns and col in files['encoders']:
                        le = files['encoders'][col]
                        # Handle unseen labels
                        input_df[col] = input_df[col].apply(lambda x: le.transform([x])[0] if x in le.classes_ else 0)
            
            # Ensure correct feature order
            if 'features' in files and files['features']:
                input_df = input_df[files['features']]
            
            # Scale features
            if 'scaler' in files and files['scaler']:
                input_scaled = files['scaler'].transform(input_df)
            else:
                input_scaled = input_df.values
            
            # Make prediction
            model = files['model']
            prediction = model.predict(input_scaled)[0]
            probabilities = model.predict_proba(input_scaled)[0]
            
            # Display results
            st.markdown("---")
            st.markdown("## 📊 Analysis Results")
            
            if prediction == 0:
                st.markdown('<div class="result-normal">✅ NORMAL TRAFFIC DETECTED</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="result-attack">🚨 ATTACK DETECTED!</div>', unsafe_allow_html=True)
            
            # Metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Prediction", "Normal" if prediction == 0 else "Attack")
            with col2:
                st.metric("Confidence", f"{max(probabilities)*100:.1f}%")
            with col3:
                st.metric("Normal Probability", f"{probabilities[0]*100:.1f}%")
            with col4:
                st.metric("Attack Probability", f"{probabilities[1]*100:.1f}%")
            
            # Recommendations
            if prediction == 0:
                st.success("✅ **Recommendation:** Traffic appears normal. Continue monitoring.")
            else:
                st.error("🚨 **Recommendation:** Immediate action required! Consider:")
                st.warning("1. Block source IP address\n2. Alert security team\n3. Isolate affected systems\n4. Review logs for similar patterns")
        
        except Exception as e:
            st.error(f"❌ Error during analysis: {str(e)}")
            st.info("💡 Tip: Ensure all categorical values match training data categories.")

# ============================================================================
# TAB 2: BATCH ANALYSIS
# ============================================================================
with tab2:
    st.markdown("## 📁 Batch CSV Analysis")
    
    uploaded_file = st.file_uploader("Upload CSV file with network traffic data", type=['csv'])
    
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            st.success(f"✅ File loaded: {df.shape[0]} rows, {df.shape[1]} columns")
            
            if st.button("🔍 ANALYZE BATCH", type="primary"):
                with st.spinner("Analyzing..."):
                    # Preprocess
                    if 'encoders' in files and files['encoders']:
                        df_encoded = df.copy()
                        for col in ['protocol_type', 'service', 'flag']:
                            if col in df_encoded.columns and col in files['encoders']:
                                le = files['encoders'][col]
                                df_encoded[col] = df_encoded[col].apply(lambda x: le.transform([x])[0] if x in le.classes_ else 0)
                    
                    # Scale
                    if 'scaler' in files and files['scaler']:
                        X_scaled = files['scaler'].transform(df_encoded)
                    else:
                        X_scaled = df_encoded.values
                    
                    # Predict
                    predictions = files['model'].predict(X_scaled)
                    probabilities = files['model'].predict_proba(X_scaled)
                    
                    # Add results to dataframe
                    df['Prediction'] = ['Normal' if p == 0 else 'Attack' for p in predictions]
                    df['Confidence'] = [max(prob) * 100 for prob in probabilities]
                    df['Normal_Prob'] = [prob[0] * 100 for prob in probabilities]
                    df['Attack_Prob'] = [prob[1] * 100 for prob in probabilities]
                    
                    # Display summary
                    normal_count = (predictions == 0).sum()
                    attack_count = (predictions == 1).sum()
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Normal Traffic", normal_count)
                    with col2:
                        st.metric("Attacks Detected", attack_count)
                    with col3:
                        detection_rate = attack_count / len(predictions) * 100 if len(predictions) > 0 else 0
                        st.metric("Detection Rate", f"{detection_rate:.1f}%")
                    
                    # Display results
                    st.dataframe(df)
                    
                    # Download button
                    csv = df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Results",
                        data=csv,
                        file_name="idps_analysis_results.csv",
                        mime="text/csv"
                    )
        
        except Exception as e:
            st.error(f"❌ Error processing file: {str(e)}")

# ============================================================================
# TAB 3: SYSTEM INFO
# ============================================================================
with tab3:
    st.markdown("## 📊 System Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info("### 🎯 Model Details")
        if 'model' in files:
            model = files['model']
            st.write(f"**Type:** {type(model).__name__}")
            if hasattr(model, 'n_estimators'):
                st.write(f"**Trees:** {model.n_estimators}")
            if hasattr(model, 'n_features_in_'):
                st.write(f"**Features:** {model.n_features_in_}")
    
    with col2:
        st.info("### 📁 Loaded Components")
        components = []
        if 'model' in files: components.append("✅ Model")
        if 'scaler' in files and files['scaler']: components.append("✅ Scaler")
        if 'features' in files and files['features']: components.append("✅ Features")
        if 'encoders' in files and files['encoders']: components.append("✅ Encoders")
        
        for comp in components:
            st.write(comp)
    
    st.markdown("---")
    st.markdown("### 📚 NSL-KDD Dataset Info")
    st.write("""
    - **Total Features:** 41 network parameters
    - **Attack Types:** DOS, Probe, R2L, U2R
    - **Normal Samples:** ~67,000
    - **Attack Samples:** ~58,000
    - **Accuracy Target:** >99%
    """)

# ============================================================================
# TAB 4: TEST SAMPLES
# ============================================================================
with tab4:
    st.markdown("## 🛠️ Test with Sample Data")
    
    st.info("Use these pre-defined samples to test the system")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🧪 Test Normal Traffic", use_container_width=True):
            # Sample normal traffic values
            normal_sample = {
                'duration': 0.0,
                'protocol_type': 'tcp',
                'service': 'http',
                'flag': 'SF',
                'src_bytes': 100,
                'dst_bytes': 200,
                'count': 10,
                'srv_count': 5,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'same_srv_rate': 0.8,
                'logged_in': 1,
                'num_failed_logins': 0
            }
            
            # Set values in session state for tab1
            for key, value in normal_sample.items():
                if key in st.session_state:
                    st.session_state[key] = value
            
            st.success("✅ Normal sample loaded! Switch to 'Real-time Detection' tab")
    
    with col2:
        if st.button("🚨 Test Attack Traffic", use_container_width=True):
            # Sample attack traffic values
            attack_sample = {
                'duration': 1000.0,
                'protocol_type': 'tcp',
                'service': 'http',
                'flag': 'S0',
                'src_bytes': 100000,
                'dst_bytes': 0,
                'count': 200,
                'srv_count': 200,
                'serror_rate': 1.0,
                'srv_serror_rate': 1.0,
                'rerror_rate': 1.0,
                'same_srv_rate': 0.0,
                'logged_in': 0,
                'num_failed_logins': 5
            }
            
            # Set values in session state
            for key, value in attack_sample.items():
                if key in st.session_state:
                    st.session_state[key] = value
            
            st.warning("⚠️ Attack sample loaded! Switch to 'Real-time Detection' tab")
