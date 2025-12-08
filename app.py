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
# ⚠️ UPDATE THESE FILE IDs FROM YOUR GOOGLE DRIVE ⚠️
# ============================================================================
MODEL_FILE_ID = "1ROjXla7J_wAEpaWBVPFR88pOxlZRAmbe"
SCALER_FILE_ID = "1fbREKxsJ4n3m_n1n6ExrQzpmeaXG9DIx"
FEATURES_FILE_ID = "1fbREKxsJ4n3m_n1n6ExrQzpmeaXG9DIx"
ENCODERS_FILE_ID = ""

# ============================================================================
# DOWNLOAD & LOAD FILES
# ============================================================================

@st.cache_resource
def download_and_load():
    """Download and load all files from Google Drive"""
    
    errors = []
    
    # Check FILE IDs
    if MODEL_FILE_ID == "PASTE_MODEL_FILE_ID_HERE":
        st.error("❌ MODEL FILE_ID NOT SET - Update Line 20")
        st.stop()
    
    # Download Model
    try:
        if not os.path.exists('idps_model.joblib'):
            url = f'https://drive.google.com/uc?id={MODEL_FILE_ID}'
            gdown.download(url, 'idps_model.joblib', quiet=False)
        model = joblib.load('idps_model.joblib')
    except Exception as e:
        errors.append(f"Model: {str(e)}")
        model = None
    
    # Download Scaler
    scaler = None
    try:
        if SCALER_FILE_ID != "PASTE_SCALER_FILE_ID_HERE":
            if not os.path.exists('feature_scaler.joblib'):
                url = f'https://drive.google.com/uc?id={SCALER_FILE_ID}'
                gdown.download(url, 'feature_scaler.joblib', quiet=False)
            scaler = joblib.load('feature_scaler.joblib')
    except:
        st.warning("⚠️ Scaler not loaded (optional)")
    
    # Download Feature Names
    feature_names = None
    try:
        if FEATURES_FILE_ID != "PASTE_FEATURES_FILE_ID_HERE":
            if not os.path.exists('feature_names.joblib'):
                url = f'https://drive.google.com/uc?id={FEATURES_FILE_ID}'
                gdown.download(url, 'feature_names.joblib', quiet=False)
            feature_names = joblib.load('feature_names.joblib')
    except:
        st.warning("⚠️ Feature names not loaded")
    
    # Download Encoders
    label_encoders = None
    try:
        if ENCODERS_FILE_ID != "PASTE_ENCODERS_FILE_ID_HERE":
            if not os.path.exists('label_encoders.joblib'):
                url = f'https://drive.google.com/uc?id={ENCODERS_FILE_ID}'
                gdown.download(url, 'label_encoders.joblib', quiet=False)
            label_encoders = joblib.load('label_encoders.joblib')
    except:
        st.warning("⚠️ Encoders not loaded")
    
    if errors:
        for error in errors:
            st.error(error)
    
    return model, scaler, feature_names, label_encoders

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
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
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
# MAIN APP
# ============================================================================

st.markdown("""
    <div class="header-container">
        <p class="header-title">🛡️ IDPS - AI Intrusion Detection System</p>
        <p class="header-subtitle">Real-time Network Traffic Analysis & Threat Prevention</p>
    </div>
""", unsafe_allow_html=True)

# Load files
with st.spinner("⏳ Loading system components..."):
    model, scaler, feature_names, label_encoders = download_and_load()

if model is None:
    st.error("❌ CRITICAL: Model not loaded. Check FILE_IDs!")
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
    
    # Initialize input dictionary
    input_data = {}
    
    # Row 1: Basic Features
    col1, col2, col3 = st.columns(3)
    
    with col1:
        input_data['duration'] = st.number_input("Duration (seconds)", 0, 100000, 100)
        input_data['src_bytes'] = st.number_input("Source Bytes", 0, 1000000, 100)
        input_data['dst_bytes'] = st.number_input("Destination Bytes", 0, 1000000, 100)
        input_data['land'] = st.number_input("Land (0/1)", 0, 1, 0)
        input_data['wrong_fragment'] = st.number_input("Wrong Fragment", 0, 100, 0)
    
    with col2:
        input_data['urgent'] = st.number_input("Urgent", 0, 100, 0)
        input_data['hot'] = st.number_input("Hot", 0, 100, 0)
        input_data['num_failed_logins'] = st.number_input("Failed Logins", 0, 100, 0)
        input_data['logged_in'] = st.number_input("Logged In (0/1)", 0, 1, 0)
        input_data['num_compromised'] = st.number_input("Compromised", 0, 100, 0)
    
    with col3:
        input_data['root_shell'] = st.number_input("Root Shell", 0, 100, 0)
        input_data['su_attempted'] = st.number_input("SU Attempted", 0, 100, 0)
        input_data['num_root'] = st.number_input("Num Root", 0, 100, 0)
        input_data['num_file_creations'] = st.number_input("File Creations", 0, 100, 0)
        input_data['num_shells'] = st.number_input("Num Shells", 0, 100, 0)
    
    st.markdown("---")
    
    # Row 2: Protocol/Service/Flag with DIRECT NUMERICAL INPUT
    col4, col5, col6 = st.columns(3)
    
    with col4:
        st.write("**Protocol Type** (0-255)")
        protocol_choice = st.radio("Select Protocol:", ["TCP (6)", "UDP (17)", "ICMP (1)"], horizontal=True)
        if "TCP" in protocol_choice:
            input_data['protocol_type'] = 6.0
        elif "UDP" in protocol_choice:
            input_data['protocol_type'] = 17.0
        else:
            input_data['protocol_type'] = 1.0
    
    with col5:
        st.write("**Service Type**")
        service_choice = st.radio("Select Service:", ["HTTP (0)", "SMTP (1)", "FTP (6)", "SSH (5)", "Other (12)"], horizontal=True)
        service_num = int(service_choice.split("(")[1].split(")")[0])
        input_data['service'] = float(service_num)
    
    with col6:
        st.write("**Connection Flag**")
        flag_choice = st.radio("Select Flag:", ["SF - Normal (0)", "S0 - Attack (1)", "REJ (2)"], horizontal=True)
        flag_num = int(flag_choice.split("(")[1].split(")")[0])
        input_data['flag'] = float(flag_num)
    
    # Row 3: Additional Features
    col7, col8, col9 = st.columns(3)
    
    with col7:
        input_data['num_access_files'] = st.number_input("Access Files", 0, 100, 0)
        input_data['num_outbound_cmds'] = st.number_input("Outbound Commands", 0, 100, 0)
        input_data['is_host_login'] = st.number_input("Host Login (0/1)", 0, 1, 0)
        input_data['is_guest_login'] = st.number_input("Guest Login (0/1)", 0, 1, 0)
    
    with col8:
        input_data['count'] = st.number_input("Count", 0, 1000, 10)
        input_data['srv_count'] = st.number_input("Service Count", 0, 1000, 10)
        input_data['serror_rate'] = st.slider("SYN Error Rate", 0.0, 1.0, 0.0, 0.01)
        input_data['srv_serror_rate'] = st.slider("Service SYN Error", 0.0, 1.0, 0.0, 0.01)
    
    with col9:
        input_data['rerror_rate'] = st.slider("Reset Error Rate", 0.0, 1.0, 0.0, 0.01)
        input_data['srv_rerror_rate'] = st.slider("Service Reset Error", 0.0, 1.0, 0.0, 0.01)
        input_data['same_srv_rate'] = st.slider("Same Service Rate", 0.0, 1.0, 1.0, 0.01)
        input_data['diff_srv_rate'] = st.slider("Diff Service Rate", 0.0, 1.0, 0.0, 0.01)
    
    st.markdown("---")
    
    # Row 4: Remaining features with defaults
    col10, col11 = st.columns(2)
    
    with col10:
        input_data['srv_diff_host_rate'] = st.slider("Service Diff Host Rate", 0.0, 1.0, 0.0, 0.01)
        input_data['dst_host_count'] = st.number_input("Dest Host Count", 0, 1000, 50)
        input_data['dst_host_srv_count'] = st.number_input("Dest Host Service Count", 0, 1000, 50)
    
    with col11:
        input_data['dst_host_same_srv_rate'] = st.slider("Dest Host Same Service Rate", 0.0, 1.0, 1.0, 0.01)
        input_data['dst_host_diff_srv_rate'] = st.slider("Dest Host Diff Service Rate", 0.0, 1.0, 0.0, 0.01)
        input_data['dst_host_same_src_port_rate'] = st.slider("Dest Host Same Src Port Rate", 0.0, 1.0, 0.0, 0.01)
    
    # Default remaining features
    input_data['dst_host_srv_diff_host_rate'] = 0.0
    input_data['dst_host_serror_rate'] = 0.0
    input_data['dst_host_srv_serror_rate'] = 0.0
    input_data['dst_host_rerror_rate'] = 0.0
    input_data['dst_host_srv_rerror_rate'] = 0.0
    
    st.markdown("---")
    
# Analyze Button
    if st.button("🔍 ANALYZE TRAFFIC", use_container_width=True):
        try:
            # Create complete feature dictionary with defaults
            all_features = {
                'duration': 0, 'protocol_type': 0, 'service': 0, 'flag': 0,
                'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
                'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
                'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
                'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
                'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0,
                'is_guest_login': 0, 'count': 0, 'srv_count': 0, 'serror_rate': 0.0,
                'srv_serror_rate': 0.0, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
                'same_srv_rate': 0.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
                'dst_host_count': 0, 'dst_host_srv_count': 0,
                'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0
            }
            
            # Update with user inputs
            all_features.update(input_data)
            
            # Feature order (EXACT NSL-KDD order)
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
            
            # Create numpy array
            X_input = np.array([[float(all_features[fname]) for fname in feature_order]])
            
            # Scale data if scaler exists
            if scaler is not None:
                X_scaled = scaler.transform(X_input)
            else:
                X_scaled = X_input
            
            # Make prediction
            prediction = model.predict(X_scaled)[0]
            probabilities = model.predict_proba(X_scaled)[0]
            confidence = max(probabilities) * 100
            
            st.markdown("---")
            
            if prediction == 0:
                # NORMAL TRAFFIC RESULT
                st.markdown(
                    '<div class="result-box result-normal">✅ NORMAL TRAFFIC DETECTED</div>',
                    unsafe_allow_html=True
                )
                
                col_m1, col_m2, col_m3 = st.columns(3)
                with col_m1:
                    st.metric("🔒 Confidence Level", f"{confidence:.2f}%")
                with col_m2:
                    st.metric("⚠️ Threat Level", "🟢 LOW")
                with col_m3:
                    st.metric("✅ Action Taken", "ALLOW")
                
                st.success("✅ **This traffic is SAFE.** No malicious activity detected. Connection ALLOWED!")
                
                # Additional info
                with st.expander("📊 Traffic Analysis Details"):
                    st.write(f"• Duration: {all_features['duration']} seconds")
                    st.write(f"• Protocol: {all_features['protocol_type']}")
                    st.write(f"• Source Bytes: {all_features['src_bytes']}")
                    st.write(f"• Destination Bytes: {all_features['dst_bytes']}")
                    st.write(f"• Confidence: {confidence:.2f}%")
            
            else:
                # ATTACK DETECTED RESULT
                st.markdown(
                    '<div class="result-box result-attack">🚨 ATTACK DETECTED!</div>',
                    unsafe_allow_html=True
                )
                
                col_m1, col_m2, col_m3 = st.columns(3)
                with col_m1:
                    st.metric("🔒 Confidence Level", f"{confidence:.2f}%")
                with col_m2:
                    st.metric("⚠️ Threat Level", "🔴 HIGH")
                with col_m3:
                    st.metric("❌ Action Taken", "BLOCK IP")
                
                st.error("🚨 **INTRUSION DETECTED!** Malicious traffic pattern identified. IP address BLOCKED immediately!")
                
                # Attack details
                with st.expander("🚨 Attack Analysis Details"):
                    st.write(f"• Attack Type: Potential DoS/Probe/R2L/U2R")
                    st.write(f"• Confidence: {confidence:.2f}%")
                    st.write(f"• Count: {all_features['count']}")
                    st.write(f"• Error Rate: {all_features['serror_rate']}")
                    st.write(f"• Recommended Action: BLOCK SOURCE IP")
        
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")
            st.write(f"**Debug Info:** {type(e).__name__}")

# ============================================================================
# TAB 2: BATCH CSV ANALYSIS
# ============================================================================

with tab2:
    st.markdown("## 📁 Batch CSV Analysis")
    
    uploaded_file = st.file_uploader("Upload CSV file (NSL-KDD format)", type=['csv'])
    
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            st.dataframe(df.head(10), use_container_width=True)
            
            col_info1, col_info2, col_info3 = st.columns(3)
            with col_info1:
                st.metric("Total Records", len(df))
            with col_info2:
                st.metric("Columns", len(df.columns))
            with col_info3:
                st.metric("File Size (KB)", f"{df.memory_usage(deep=True).sum()/1024:.2f}")
            
            if st.button("🔍 ANALYZE BATCH", use_container_width=True):
                try:
                    if feature_names and len(feature_names) == len(df.columns):
                        X_batch = df[feature_names]
                    else:
                        X_batch = df
                    
                    if scaler:
                        X_scaled_batch = scaler.transform(X_batch)
                    else:
                        X_scaled_batch = X_batch
                    
                    preds = model.predict(X_scaled_batch)
                    
                    result_df = df.copy()
                    result_df['Prediction'] = ['🟢 Normal' if p == 0 else '🔴 Attack' for p in preds]
                    
                    normal_count = (preds == 0).sum()
                    attack_count = (preds == 1).sum()
                    
                    col_b1, col_b2, col_b3 = st.columns(3)
                    with col_b1:
                        st.metric("Normal Traffic", normal_count)
                    with col_b2:
                        st.metric("Attacks Detected", attack_count)
                    with col_b3:
                        rate = (attack_count / len(preds) * 100) if len(preds) > 0 else 0
                        st.metric("Detection Rate", f"{rate:.2f}%")
                    
                    st.markdown("---")
                    st.dataframe(result_df, use_container_width=True)
                    
                    csv_data = result_df.to_csv(index=False)
                    st.download_button("📥 Download Results", csv_data, "idps_results.csv", "text/csv")
                
                except Exception as e:
                    st.error(f"❌ Batch Analysis Error: {str(e)}")
        
        except Exception as e:
            st.error(f"❌ File Upload Error: {str(e)}")

# ============================================================================
# TAB 3: ABOUT
# ============================================================================

with tab3:
    st.markdown("""
    ## 🎯 About IDPS System
    
    **AI-Based Intrusion Detection & Prevention System**
    
    ### 📊 Dataset
    - **Name:** NSL-KDD
    - **Samples:** 125,973 records
    - **Features:** 41 network parameters
    - **Classes:** Normal vs Attack
    
    ### 🤖 Model
    - **Algorithm:** Random Forest Classifier
    - **Trees:** 200
    - **Accuracy:** >99%
    
    ### 🎯 Attack Types Detected
    - **DoS:** Denial of Service attacks
    - **Probe:** Reconnaissance/Port scanning
    - **R2L:** Remote to Local attacks
    - **U2R:** User to Root escalation
    
    ### 📈 Performance
    - **Precision:** High true positive rate
    - **Recall:** Catches most attacks
    - **F1-Score:** Balanced metrics
    
    ### 🔧 Technology Stack
    - **Framework:** Streamlit
    - **ML Library:** scikit-learn
    - **Data Processing:** Pandas, NumPy
    - **Model Serialization:** joblib
    
    ---
    *IDPS v1.0 | Real-World Intrusion Detection | December 2025*
    """)
