# ============================================================================
# app.py - FIXED VERSION (Handles encoding properly)
# ============================================================================

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import gdown
import os

st.set_page_config(page_title="IDPS System", page_icon="🛡️", layout="wide")

# Update with your actual Google Drive file IDs
FILE_IDS = {
    'model': "1twl2RVHkagcSk-nSg3FZaTlhSVZE3hZx",
    'scaler': "1N0ioToIQCijaAyWmUEEj3NlzXpUPRsmy",
    'features': "19KT6y8QUNJYwAKjik8B6JD7gN1dQiviY",
    'encoders': "1EpIZSjd3_ObSc616_tz8GfB9PR9z15Op",
    'categories': "1cOE8jNYdUmnM-Bz4SGS5lY-_LSj7NsUm"
}

def download_file(file_id, filename):
    """Download file from Google Drive"""
    if not os.path.exists(filename):
        url = f'https://drive.google.com/uc?id={file_id}'
        gdown.download(url, filename, quiet=False)
    return joblib.load(filename)

@st.cache_resource
def load_resources():
    """Load all model resources"""
    resources = {}
    
    try:
        # Download and load files
        resources['model'] = download_file(FILE_IDS['model'], 'idps_model.joblib')
        resources['scaler'] = download_file(FILE_IDS['scaler'], 'feature_scaler.joblib')
        resources['features'] = download_file(FILE_IDS['features'], 'feature_names.joblib')
        resources['encoders'] = download_file(FILE_IDS['encoders'], 'label_encoders.joblib')
        resources['categories'] = download_file(FILE_IDS['categories'], 'category_info.joblib')
        
        st.success("✅ All resources loaded successfully!")
        return resources
        
    except Exception as e:
        st.error(f"❌ Error loading resources: {str(e)}")
        return None

# Load resources
with st.spinner("Loading AI Model..."):
    resources = load_resources()

if not resources:
    st.error("Failed to load model. Please check file IDs and try again.")
    st.stop()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
def encode_categorical_values(input_dict, encoders):
    """Encode categorical features using saved mappings"""
    encoded = input_dict.copy()
    
    for col, encoder_info in encoders.items():
        if col in encoded:
            mapping = encoder_info.get('mapping', {})
            value = encoded[col]
            # Use mapping if available, otherwise use -1 for unknown
            encoded[col] = mapping.get(value, -1)
    
    return encoded

def create_input_features(input_values):
    """Create properly formatted input features"""
    # Get default values for all 41 features
    default_features = {
        'duration': 0.0,
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'src_bytes': 0,
        'dst_bytes': 0,
        'land': 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 0,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
        'count': 0,
        'srv_count': 0,
        'serror_rate': 0.0,
        'srv_serror_rate': 0.0,
        'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0,
        'same_srv_rate': 0.0,
        'diff_srv_rate': 0.0,
        'srv_diff_host_rate': 0.0,
        'dst_host_count': 0,
        'dst_host_srv_count': 0,
        'dst_host_same_srv_rate': 0.0,
        'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 0.0,
        'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0,
        'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    }
    
    # Update with user inputs
    default_features.update(input_values)
    
    return default_features

# ============================================================================
# UI STYLING
# ============================================================================
st.markdown("""
    <style>
        .main-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 2rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
        }
        .result-box {
            padding: 2rem;
            border-radius: 10px;
            margin: 1rem 0;
            text-align: center;
            font-size: 1.5rem;
            font-weight: bold;
        }
        .normal-result {
            background: linear-gradient(135deg, #00b09b 0%, #96c93d 100%);
            color: white;
        }
        .attack-result {
            background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
            color: white;
        }
        .metric-card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 10px;
            border-left: 4px solid #667eea;
            margin: 0.5rem 0;
        }
    </style>
""", unsafe_allow_html=True)

# ============================================================================
# APP HEADER
# ============================================================================
st.markdown("""
<div class="main-header">
    <h1 style="margin:0; font-size: 2.5rem;">🛡️ AI Intrusion Detection System</h1>
    <p style="margin:0; opacity: 0.9;">Real-time Network Traffic Analysis using Machine Learning</p>
</div>
""", unsafe_allow_html=True)

# ============================================================================
# TABS
# ============================================================================
tab1, tab2, tab3 = st.tabs(["🔍 Real-time Analysis", "📁 Batch Analysis", "📊 System Info"])

# ============================================================================
# TAB 1: REAL-TIME ANALYSIS
# ============================================================================
with tab1:
    st.markdown("### 📝 Enter Network Traffic Parameters")
    
    # Get available categories from loaded resources
    categories = resources.get('categories', {})
    protocol_options = categories.get('protocol_types', ['tcp', 'udp', 'icmp'])
    service_options = categories.get('common_services', ['http', 'smtp', 'ftp', 'ssh'])
    flag_options = categories.get('common_flags', ['SF', 'S0', 'REJ', 'RSTR'])
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.subheader("Basic Features")
        duration = st.number_input("Duration (sec)", 0.0, 100000.0, 0.0, 0.1)
        protocol_type = st.selectbox("Protocol Type", protocol_options, index=0)
        service = st.selectbox("Service", service_options, index=0)
        flag = st.selectbox("Flag", flag_options, index=0)
        
    with col2:
        st.subheader("Traffic Volume")
        src_bytes = st.number_input("Source Bytes", 0, 10000000, 0)
        dst_bytes = st.number_input("Destination Bytes", 0, 10000000, 0)
        count = st.number_input("Connection Count", 0, 1000, 0)
        srv_count = st.number_input("Service Count", 0, 1000, 0)
        
    with col3:
        st.subheader("Error Indicators")
        serror_rate = st.slider("SYN Error Rate", 0.0, 1.0, 0.0, 0.01)
        srv_serror_rate = st.slider("Service SYN Error", 0.0, 1.0, 0.0, 0.01)
        rerror_rate = st.slider("Reset Error Rate", 0.0, 1.0, 0.0, 0.01)
        same_srv_rate = st.slider("Same Service Rate", 0.0, 1.0, 0.0, 0.01)
    
    # Advanced features (collapsible)
    with st.expander("⚙️ Advanced Features (Optional)"):
        col4, col5 = st.columns(2)
        with col4:
            logged_in = st.selectbox("Logged In", [0, 1], index=0)
            num_failed_logins = st.number_input("Failed Logins", 0, 10, 0)
            wrong_fragment = st.number_input("Wrong Fragments", 0, 10, 0)
            urgent = st.number_input("Urgent Packets", 0, 10, 0)
            
        with col5:
            hot = st.number_input("Hot Indicators", 0, 100, 0)
            num_root = st.number_input("Root Accesses", 0, 10, 0)
            num_file_creations = st.number_input("File Creations", 0, 10, 0)
            num_shells = st.number_input("Shell Prompts", 0, 10, 0)
    
    st.markdown("---")
    
    if st.button("🚀 ANALYZE TRAFFIC", type="primary", use_container_width=True):
        with st.spinner("Analyzing traffic..."):
            try:
                # Create input dictionary
                input_data = {
                    'duration': float(duration),
                    'protocol_type': protocol_type,
                    'service': service,
                    'flag': flag,
                    'src_bytes': float(src_bytes),
                    'dst_bytes': float(dst_bytes),
                    'land': 0.0,
                    'wrong_fragment': float(wrong_fragment),
                    'urgent': float(urgent),
                    'hot': float(hot),
                    'num_failed_logins': float(num_failed_logins),
                    'logged_in': float(logged_in),
                    'num_compromised': 0.0,
                    'root_shell': 0.0,
                    'su_attempted': 0.0,
                    'num_root': float(num_root),
                    'num_file_creations': float(num_file_creations),
                    'num_shells': float(num_shells),
                    'num_access_files': 0.0,
                    'num_outbound_cmds': 0.0,
                    'is_host_login': 0.0,
                    'is_guest_login': 0.0,
                    'count': float(count),
                    'srv_count': float(srv_count),
                    'serror_rate': float(serror_rate),
                    'srv_serror_rate': float(srv_serror_rate),
                    'rerror_rate': float(rerror_rate),
                    'srv_rerror_rate': 0.0,
                    'same_srv_rate': float(same_srv_rate),
                    'diff_srv_rate': 0.0,
                    'srv_diff_host_rate': 0.0,
                    'dst_host_count': 100.0,
                    'dst_host_srv_count': 50.0,
                    'dst_host_same_srv_rate': 0.9,
                    'dst_host_diff_srv_rate': 0.1,
                    'dst_host_same_src_port_rate': 0.0,
                    'dst_host_srv_diff_host_rate': 0.0,
                    'dst_host_serror_rate': float(serror_rate),
                    'dst_host_srv_serror_rate': float(srv_serror_rate),
                    'dst_host_rerror_rate': float(rerror_rate),
                    'dst_host_srv_rerror_rate': 0.0
                }
                
                # Encode categorical features
                encoded_data = encode_categorical_values(input_data, resources['encoders'])
                
                # Convert to DataFrame with correct feature order
                features = resources['features']
                input_df = pd.DataFrame([encoded_data])
                
                # Ensure all features are present
                for feature in features:
                    if feature not in input_df.columns:
                        input_df[feature] = 0.0
                
                # Reorder to match training
                input_df = input_df[features]
                
                # Scale features
                input_scaled = resources['scaler'].transform(input_df)
                
                # Make prediction
                model = resources['model']
                prediction = model.predict(input_scaled)[0]
                probabilities = model.predict_proba(input_scaled)[0]
                
                # Display results
                st.markdown("### 📊 Analysis Results")
                
                if prediction == 0:
                    st.markdown('<div class="result-box normal-result">✅ NORMAL TRAFFIC DETECTED</div>', 
                              unsafe_allow_html=True)
                else:
                    st.markdown('<div class="result-box attack-result">🚨 ATTACK DETECTED!</div>', 
                              unsafe_allow_html=True)
                
                # Show metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Prediction", "Normal" if prediction == 0 else "Attack")
                with col2:
                    confidence = max(probabilities) * 100
                    st.metric("Confidence", f"{confidence:.1f}%")
                with col3:
                    st.metric("Normal Probability", f"{probabilities[0]*100:.1f}%")
                with col4:
                    st.metric("Attack Probability", f"{probabilities[1]*100:.1f}%")
                
                # Show recommendations
                st.markdown("### 🎯 Recommendations")
                if prediction == 0:
                    st.success("""
                    **Traffic Analysis:** This appears to be normal network traffic.
                    **Action:** No immediate action required. Continue monitoring.
                    """)
                else:
                    st.error("""
                    **Traffic Analysis:** Potential intrusion detected!
                    **Immediate Actions Recommended:**
                    1. **Block** source IP address
                    2. **Alert** security team
                    3. **Review** system logs
                    4. **Isolate** affected systems if necessary
                    """)
                    
            except Exception as e:
                st.error(f"❌ Error during analysis: {str(e)}")
                st.info("""
                **Troubleshooting Tips:**
                1. Ensure all categorical values match training data
                2. Check that all 41 features are properly defined
                3. Verify the model files are correctly loaded
                """)

# ============================================================================
# TAB 2: BATCH ANALYSIS
# ============================================================================
with tab2:
    st.markdown("### 📁 Batch CSV Analysis")
    
    uploaded_file = st.file_uploader("Upload CSV file", type=['csv'])
    
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            st.success(f"✅ Loaded {len(df)} records")
            
            if st.button("🔍 Analyze Batch", type="primary"):
                with st.spinner("Processing..."):
                    # Encode categorical columns
                    df_encoded = df.copy()
                    for col in ['protocol_type', 'service', 'flag']:
                        if col in df_encoded.columns and col in resources['encoders']:
                            mapping = resources['encoders'][col]['mapping']
                            df_encoded[col] = df_encoded[col].apply(
                                lambda x: mapping.get(x, -1)
                            )
                    
                    # Ensure correct feature order
                    features = resources['features']
                    missing_cols = [col for col in features if col not in df_encoded.columns]
                    
                    if missing_cols:
                        st.warning(f"Adding missing columns: {missing_cols}")
                        for col in missing_cols:
                            df_encoded[col] = 0.0
                    
                    df_encoded = df_encoded[features]
                    
                    # Scale
                    X_scaled = resources['scaler'].transform(df_encoded)
                    
                    # Predict
                    predictions = resources['model'].predict(X_scaled)
                    probabilities = resources['model'].predict_proba(X_scaled)
                    
                    # Add results to dataframe
                    results_df = df.copy()
                    results_df['Prediction'] = ['Normal' if p == 0 else 'Attack' for p in predictions]
                    results_df['Confidence'] = [max(prob) * 100 for prob in probabilities]
                    
                    # Show summary
                    normal_count = (predictions == 0).sum()
                    attack_count = (predictions == 1).sum()
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Normal Traffic", normal_count)
                    with col2:
                        st.metric("Attacks Detected", attack_count)
                    with col3:
                        detection_rate = attack_count / len(predictions) * 100
                        st.metric("Detection Rate", f"{detection_rate:.1f}%")
                    
                    # Show results
                    st.dataframe(results_df)
                    
                    # Download button
                    csv = results_df.to_csv(index=False)
                    st.download_button(
                        "📥 Download Results",
                        csv,
                        "idps_results.csv",
                        "text/csv"
                    )
                    
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

# ============================================================================
# TAB 3: SYSTEM INFO
# ============================================================================
with tab3:
    st.markdown("### 📊 System Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info("**Model Details**")
        if 'model' in resources:
            model = resources['model']
            st.write(f"- Type: {type(model).__name__}")
            st.write(f"- Features: {model.n_features_in_}")
            st.write(f"- Classes: {model.n_classes_}")
    
    with col2:
        st.info("**Dataset Info**")
        st.write("- Source: NSL-KDD Dataset")
        st.write("- Features: 41 network parameters")
        st.write("- Classes: Normal vs Attack")
    
    st.markdown("### 🎯 Quick Test Values")
    
    test_col1, test_col2 = st.columns(2)
    
    with test_col1:
        st.markdown("**Normal Traffic:**")
        st.code("""
        Duration: 0-10 seconds
        Protocol: tcp
        Service: http
        Flag: SF
        Error Rates: 0.0
        Logged In: 1
        Source Bytes: < 1000
        """)
    
    with test_col2:
        st.markdown("**Attack Traffic:**")
        st.code("""
        Duration: > 1000 seconds
        Protocol: tcp
        Service: http
        Flag: S0
        Error Rates: > 0.5
        Logged In: 0
        Source Bytes: > 10000
        """)
