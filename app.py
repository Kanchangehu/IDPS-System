import streamlit as st
import pandas as pd
import numpy as np
import pickle
import gdown
import os

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================
st.set_page_config(page_title="IDPS System", page_icon="🛡️", layout="wide")

# ============================================================================
# ⚠️⚠️⚠️ PASTE YOUR FILE ID HERE ⚠️⚠️⚠️
# ============================================================================

# Apna Google Drive FILE ID yahan dhyan se paste karo!
# Link: https://drive.google.com/file/d/1xD9e.../view
# ID: 1xD9e...
FILE_ID = "1AGdmfXHO_4xibHf_P2uP56dtiYO0QO0c" 

# ============================================================================
# ROBUST MODEL LOADER USING GDOWN
# ============================================================================

@st.cache_resource
def load_model(file_id):
    output = 'idps_model.pkl'
    
    # Agar file pehle se nahi hai toh download karo
    if not os.path.exists(output):
        url = f'https://drive.google.com/uc?id={file_id}'
        try:
            # gdown handles large files & virus warnings automatically
            gdown.download(url, output, quiet=False)
        except Exception as e:
            st.error(f"❌ Download Error: {str(e)}")
            return None

    # Ab file load karo
    try:
        with open(output, 'rb') as f:
            model = pickle.load(f)
        return model
    except Exception as e:
        st.error(f"❌ Model Load Error: {str(e)}")
        st.error("💡 Tip: Check if FILE ID is correct and File Permission is 'Anyone with link'")
        return None

# ============================================================================
# CSS STYLING
# ============================================================================
st.markdown("""
    <style>
        .header-container {
            background: linear-gradient(135deg, #0066cc 0%, #004499 100%);
            padding: 30px 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
            color: white;
        }
        .header-title { font-size: 2.5em; font-weight: bold; color: white; margin: 0; }
        .result-box {
            padding: 20px; border-radius: 10px; text-align: center;
            font-size: 1.2em; font-weight: bold; color: white; margin: 15px 0;
        }
        .result-normal { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); }
        .result-attack { background: linear-gradient(135deg, #dc3545 0%, #ff6b6b 100%); }
    </style>
""", unsafe_allow_html=True)

# ============================================================================
# MAIN APP LOGIC
# ============================================================================

st.markdown("""
    <div class="header-container">
        <p class="header-title">🛡️ IDPS - AI Intrusion Detection System</p>
    </div>
""", unsafe_allow_html=True)

if FILE_ID == "PASTE_YOUR_FILE_ID_HERE":
    st.error("❌ FILE ID Missing! Please open app.py and paste your Google Drive File ID in Line 19.")
    st.stop()

with st.spinner("📥 Downloading Model (one-time setup)..."):
    model = load_model(FILE_ID)

if model is None:
    st.stop()

# Helper Functions
def block_ip(ip):
    parts = ip.split('.')
    if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        return f"✅ IP {ip} blocked successfully!"
    return "⚠️ Invalid IP"

# TABS
tab1, tab2 = st.tabs(["📊 Manual Input", "📁 CSV Upload"])

with tab1:
    col1, col2, col3 = st.columns(3)
    features = {}
    with col1:
        features['Protocol'] = st.number_input("Protocol", 0, 255, 6)
        features['Packet_Length'] = st.number_input("Packet Length", 0, 10000, 100)
        features['Traffic_Rate'] = st.number_input("Traffic Rate", 0.0, 1000.0, 10.0)
    with col2:
        features['TTL'] = st.number_input("TTL", 1, 255, 64)
        features['Header_Length'] = st.number_input("Header Length", 0, 100, 20)
        features['Flag_Count'] = st.number_input("Flag Count", 0, 32, 2)
    with col3:
        features['Window_Size'] = st.number_input("Window Size", 0, 65535, 8192)
        features['Urgency'] = st.number_input("Urgency", 0, 1, 0)
        features['Error_Rate'] = st.number_input("Error Rate", 0.0, 100.0, 0.0)
    
    st.markdown("---")
    ip = st.text_input("Source IP", "192.168.1.100")
    
    if st.button("🔍 Analyze Traffic", use_container_width=True):
        feat_arr = np.array([float(v) for v in features.values()])
        pred = model.predict([feat_arr])[0]
        
        if pred == 0:
            st.markdown('<div class="result-box result-normal">✅ NORMAL TRAFFIC</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="result-box result-attack">🚨 ATTACK DETECTED</div>', unsafe_allow_html=True)
            st.error(block_ip(ip))

with tab2:
    file = st.file_uploader("Upload CSV", type=['csv'])
    if file and st.button("Analyze Batch"):
        df = pd.read_csv(file)
        preds = model.predict(df)
        df['Prediction'] = ['Normal' if p==0 else 'Attack' for p in preds]
        st.dataframe(df)
