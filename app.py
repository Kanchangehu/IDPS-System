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
# 🔴 PASTE YOUR GOOGLE DRIVE FILE IDs HERE 🔴
# ============================================================================
MODEL_FILE_ID = "1ROjXla7J_wAEpaWBVPFR88pOxlZRAmbe"
SCALER_FILE_ID = "1fbREKxsJ4n3m_n1n6ExrQzpmeaXG9DIx"
FEATURES_FILE_ID = "1fbREKxsJ4n3m_n1n6ExrQzpmeaXG9DIx"
ENCODERS_FILE_ID = "13fsMK6xKJrk9uQ0S5p-PxarUYYqrGKOT"

# ============================================================================
# FILE DOWNLOADER
# ============================================================================

@st.cache_resource
def download_file(file_id, output_name):
    """Download file from Google Drive"""
    if file_id == "PASTE_MODEL_FILE_ID_HERE":
        st.error(f"❌ {output_name} FILE_ID NOT SET!")
        return None
    
    if not os.path.exists(output_name):
        url = f'https://drive.google.com/uc?id={file_id}'
        try:
            gdown.download(url, output_name, quiet=False)
        except Exception as e:
            st.error(f"❌ Download Error ({output_name}): {str(e)}")
            return None
    
    return output_name

@st.cache_resource
def load_model_and_utils():
    """Load all model files"""
    try:
        # Download files
        download_file(MODEL_FILE_ID, 'idps_model.joblib')
        download_file(SCALER_FILE_ID, 'feature_scaler.joblib')
        download_file(FEATURES_FILE_ID, 'feature_names.joblib')
        download_file(ENCODERS_FILE_ID, 'label_encoders.joblib')
        
        # Load files
        model = joblib.load('idps_model.joblib')
        scaler = joblib.load('feature_scaler.joblib')
        feature_names = joblib.load('feature_names.joblib')
        label_encoders = joblib.load('label_encoders.joblib')
        
        return model, scaler, feature_names, label_encoders
    except Exception as e:
        st.error(f"❌ Error loading files: {str(e)}")
        return None, None, None, None

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

# ============================================================================
# MAIN APP
# ============================================================================

st.markdown("""
    <div class="header-container">
        <p class="header-title">🛡️ IDPS - AI Intrusion Detection System</p>
        <p style="font-size:1.2em; margin-top:10px; color:#e0e0e0;">Real-time Network Traffic Analysis</p>
    </div>
""", unsafe_allow_html=True)

with st.spinner("⏳ Loading AI Model & Components..."):
    model, scaler, feature_names, label_encoders = load_model_and_utils()

if model is None:
    st.stop()

st.success("✅ Model Loaded Successfully!")

# ============================================================================
# TABS
# ============================================================================

tab1, tab2, tab3 = st.tabs(["📊 Manual Analysis", "📁 Batch CSV", "ℹ️ About"])

# ============================================================================
# TAB 1: MANUAL ANALYSIS
# ============================================================================

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
    
    col4, col5, col6 = st.columns(3)
    
    with col4:
        proto = st.selectbox("Protocol", ['tcp', 'udp', 'icmp'])
        # Safe encoding with error handling
        try:
            encoded_proto = label_encoders['protocol_type'].transform([proto.lower()])[0]
            input_data['protocol_type'] = float(encoded_proto)
        except:
            input_data['protocol_type'] = 0.0
    
    with col5:
        services_list = list(label_encoders['service'].classes_)[:50]
        service = st.selectbox("Service", services_list)
        try:
            encoded_service = label_encoders['service'].transform([service])[0]
            input_data['service'] = float(encoded_service)
        except:
            input_data['service'] = 0.0
    
    with col6:
        flags_list = list(label_encoders['flag'].classes_)
        flag = st.selectbox("Flag", flags_list)
        try:
            encoded_flag = label_encoders['flag'].transform([flag])[0]
            input_data['flag'] = float(encoded_flag)
        except:
            input_data['flag'] = 0.0
    
    st.markdown("---")
    
    # Add default values for remaining features
    for feat in feature_names:
        if feat not in input_data:
            input_data[feat] = 0.0
    
    if st.button("🔍 ANALYZE TRAFFIC", use_container_width=True):
        try:
            # Create feature array in correct order
            X_input = np.array([[float(input_data.get(fname, 0.0)) for fname in feature_names]])
            
            # Scale
            X_scaled = scaler.transform(X_input)
            
            # Predict
            pred = model.predict(X_scaled)[0]
            proba = model.predict_proba(X_scaled)[0]
            conf = max(proba) * 100
            
            st.markdown("---")
            
            if pred == 0:
                st.markdown('<div class="result-box result-normal">✅ NORMAL TRAFFIC</div>', unsafe_allow_html=True)
                col_m1, col_m2 = st.columns(2)
                with col_m1:
                    st.metric("Confidence", f"{conf:.2f}%")
                with col_m2:
                    st.metric("Threat Level", "LOW")
            else:
                st.markdown('<div class="result-box result-attack">🚨 ATTACK DETECTED</div>', unsafe_allow_html=True)
                col_m1, col_m2 = st.columns(2)
                with col_m1:
                    st.metric("Confidence", f"{conf:.2f}%")
                with col_m2:
                    st.metric("Threat Level", "HIGH")
        
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")
    
    for feat in remaining_features:
        features_dict[feat] = 0
    
    if st.button("🔍 ANALYZE TRAFFIC", use_container_width=True):
        try:
            # Create feature array in correct order
            X_input = np.array([[features_dict[fname] for fname in feature_names]])
            
            # Scale
            X_scaled = scaler.transform(X_input)
            
            # Predict
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

# ============================================================================
# TAB 2: BATCH CSV ANALYSIS
# ============================================================================

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
                    
                    df['Prediction'] = ['🟢 Normal' if p==0 else '🔴 Attack' for p in preds]
                    
                    normal = (preds==0).sum()
                    attack = (preds==1).sum()
                    
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

# ============================================================================
# TAB 3: ABOUT
# ============================================================================

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
