import streamlit as st
import pandas as pd
import numpy as np
import requests
import joblib
from io import BytesIO

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================
st.set_page_config(page_title="IDPS System", page_icon="🛡️", layout="wide")

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
        .header-title { font-size: 2.5em; font-weight: bold; color: white; }
        .header-subtitle { font-size: 1.1em; margin-top: 10px; color: #e0e0e0; }
        .result-box {
            padding: 20px; border-radius: 10px; text-align: center;
            font-size: 1.2em; font-weight: bold; color: white; margin: 15px 0;
        }
        .result-normal { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); }
        .result-attack { background: linear-gradient(135deg, #dc3545 0%, #ff6b6b 100%); }
        .info-box {
            background-color: #e7f3ff; border-left: 4px solid #0066cc;
            padding: 15px; border-radius: 5px; margin: 15px 0; color: #003d99;
        }
        .success-box {
            background-color: #d4edda; border-left: 4px solid #28a745;
            padding: 15px; border-radius: 5px; margin: 15px 0; color: #155724;
        }
        .danger-box {
            background-color: #f8d7da; border-left: 4px solid #dc3545;
            padding: 15px; border-radius: 5px; margin: 15px 0; color: #721c24;
        }
        .metric-card {
            background: white; padding: 20px; border-radius: 8px;
            border: 1px solid #dee2e6; text-align: center;
        }
        .metric-value { font-size: 2em; font-weight: bold; color: #0066cc; margin: 10px 0; }
    </style>
""", unsafe_allow_html=True)

# ============================================================================
# DOWNLOAD MODEL FROM GOOGLE DRIVE (ROBUST METHOD)
# ============================================================================

@st.cache_resource
def download_model_from_drive(file_id):
    """Robust Google Drive downloader"""
    url = "https://docs.google.com/uc?export=download"
    session = requests.Session()
    
    try:
        response = session.get(url, params={'id': file_id}, stream=True)
        token = None
        for key, value in response.cookies.items():
            if key.startswith('download_warning'):
                token = value
                break
        
        if token:
            params = {'id': file_id, 'confirm': token}
            response = session.get(url, params=params, stream=True)
            
        if response.status_code == 200:
            # Save temporarily
            with open("temp_model.pkl", "wb") as f:
                for chunk in response.iter_content(32768):
                    if chunk:
                        f.write(chunk)
            
            # Load with joblib (more robust than pickle)
            try:
                model = joblib.load("temp_model.pkl")
                return model
            except Exception as e:
                # Fallback to pandas pickle
                try:
                    model = pd.read_pickle("temp_model.pkl")
                    return model
                except:
                    st.error(f"❌ Model load error: {str(e)}")
                    return None
        else:
            st.error("❌ Google Drive download failed")
            return None
            
    except Exception as e:
        st.error(f"❌ Connection error: {str(e)}")
        return None

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def block_ip(ip):
    parts = ip.split('.')
    if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        return f"✅ IP {ip} successfully blocked!"
    else:
        return f"⚠️ Invalid IP"

def make_prediction(model, features):
    try:
        pred = model.predict([features])[0]
        try:
            prob = model.predict_proba([features])[0]
            conf = max(prob) * 100
        except:
            conf = 95.0
        return pred, conf
    except Exception as e:
        st.error(f"❌ Prediction Error: {str(e)}")
        return None, None

def validate_features(features_dict):
    try:
        features = np.array([float(v) for v in features_dict.values()])
        return True, features, None
    except:
        return False, None, "❌ All values must be numbers"

# ============================================================================
# MAIN APP LOGIC
# ============================================================================

st.markdown("""
    <div class="header-container">
        <p class="header-title">🛡️ IDPS - AI Intrusion Detection System</p>
        <p class="header-subtitle">Network Traffic Analysis & Threat Prevention</p>
    </div>
""", unsafe_allow_html=True)

# ------------------------------------------------------------------
# ↓↓↓ PASTE YOUR FILE ID HERE (INSIDE QUOTES) ↓↓↓
# ------------------------------------------------------------------
FILE_ID = "10uPeB1FmQWWpmobpZ_YYT8_pG16sFlDc"
# ------------------------------------------------------------------

with st.spinner("📥 Loading AI Model... Please wait..."):
    model = download_model_from_drive(FILE_ID)

if model is None:
    st.error("❌ CRITICAL ERROR: Model failed to load.")
    st.info("💡 Try re-uploading your .pkl file to Google Drive and updating the FILE ID.")
    st.stop()

# TABS
tab1, tab2, tab3 = st.tabs(["📊 Manual Input", "📁 CSV Upload", "ℹ️ About"])

# TAB 1: MANUAL INPUT
with tab1:
    st.markdown("<div class='info-box'><strong>💡 Enter Network Features</strong></div>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    features = {}
    
    with col1:
        features['Protocol'] = st.number_input("Protocol (0-255)", 0, 255, 6)
        features['Packet_Length'] = st.number_input("Packet Length", 0, 10000, 100)
        features['Traffic_Rate'] = st.number_input("Traffic Rate", 0.0, 1000.0, 10.0)
    with col2:
        features['TTL'] = st.number_input("TTL", 1, 255, 64)
        features['Header_Length'] = st.number_input("Header Length", 0, 100, 20)
        features['Flag_Count'] = st.number_input("Flag Count", 0, 32, 2)
    with col3:
        features['Window_Size'] = st.number_input("Window Size", 0, 65535, 8192)
        features['Urgency'] = st.number_input("Urgency", 0, 1, 0)
        features['Error_Rate'] = st.number_input("Error Rate (%)", 0.0, 100.0, 0.0)
    
    st.markdown("---")
    ip = st.text_input("IP Address", "192.168.1.100")
    
    if st.button("🔍 Analyze Traffic", key="btn1"):
        valid, feat_array, err = validate_features(features)
        if not valid:
            st.error(err)
        else:
            pred, conf = make_prediction(model, feat_array)
            if pred is not None:
                if pred == 0:
                    st.markdown('<div class="result-box result-normal">✅ NORMAL TRAFFIC</div>', unsafe_allow_html=True)
                    col_a, col_b = st.columns(2)
                    with col_a: st.metric("Confidence", f"{conf:.1f}%")
                    with col_b: st.metric("Action", "None")
                else:
                    st.markdown('<div class="result-box result-attack">🚨 ATTACK DETECTED!</div>', unsafe_allow_html=True)
                    col_a, col_b = st.columns(2)
                    with col_a: st.metric("Confidence", f"{conf:.1f}%")
                    with col_b: st.metric("Action", "BLOCK IP")
                    st.markdown("---")
                    res = block_ip(ip)
                    st.success(res)

# TAB 2: CSV UPLOAD
with tab2:
    file = st.file_uploader("Upload CSV", type=['csv'])
    if file:
        df = pd.read_csv(file)
        st.dataframe(df.head())
        if st.button("🔍 Analyze Batch"):
            preds = model.predict(df)
            res_df = df.copy()
            res_df['Prediction'] = ['Attack' if p==1 else 'Normal' for p in preds]
            st.dataframe(res_df)
            csv = res_df.to_csv(index=False)
            st.download_button("Download Results", csv, "results.csv")

# TAB 3: ABOUT
with tab3:
    st.markdown("### 🛡️ IDPS System\nAI-based intrusion detection system using Random Forest.")
\
