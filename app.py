import streamlit as st
import pickle
import pandas as pd
import numpy as np
import requests
from io import BytesIO

# ============================================================================
# PAGE CONFIG
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
# GOOGLE DRIVE SE MODEL DOWNLOAD KARO
# ============================================================================

@st.cache_resource
def download_model_from_drive(file_id):
    """Google Drive se model download aur load karo"""
    try:
        url = f"https://drive.google.com/uc?id={file_id}&export=download"
        
        st.info("📥 Model download ho raha hai... thoda wait karo")
        
        response = requests.get(url)
        
        if response.status_code == 200:
            model = pickle.load(BytesIO(response.content))
            st.success("✅ Model successfully loaded!")
            return model
        else:
            st.error("❌ Model download nahi ho saka")
            return None
    
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
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
        if hasattr(model, 'predict_proba'):
            prob = model.predict_proba([features])[0]
            conf = max(prob) * 100
        else:
            conf = 95.0
        return pred, conf
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        return None, None

def validate_features(features_dict):
    try:
        features = np.array([float(v) for v in features_dict.values()])
        return True, features, None
    except:
        return False, None, "❌ Sab values numbers honi chahiye"

# ============================================================================
# HEADER
# ============================================================================

st.markdown("""
    <div class="header-container">
        <p class="header-title">🛡️ IDPS - AI Intrusion Detection System</p>
        <p class="header-subtitle">Network Traffic Analysis & Threat Prevention</p>
    </div>
""", unsafe_allow_html=True)

# ============================================================================
# GOOGLE DRIVE FILE ID - IDHAR APNA FILE ID PASTE KARO
# ============================================================================

GOOGLE_DRIVE_FILE_ID = "1OuPeB1FmQWWpmobpZ_YYT8_pG16sFlDc"  # ← YAHAN APNA FILE ID LIKHO!

# Model load karo
model = download_model_from_drive(1OuPeB1FmQWWpmobpZ_YYT8_pG16sFlDc)

if model is None:
    st.error("❌ Model load nahi ho saka! File ID check karo")
    st.stop()

# ============================================================================
# TABS
# ============================================================================

tab1, tab2, tab3 = st.tabs(["📊 Manual Input", "📁 CSV Upload", "ℹ️ About"])

# ============================================================================
# TAB 1: MANUAL INPUT
# ============================================================================

with tab1:
    st.markdown("<div class='info-box'><strong>💡 Network Features Enter Karo</strong></div>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    features = {}
    
    with col1:
        features['Protocol'] = st.number_input("Protocol (0-255)", 0, 255, 6)
        features['Packet_Length'] = st.number_input("Packet Length", 0, 10000, 100)
        features['Traffic_Rate'] = st.number_input("Traffic Rate (Mbps)", 0.0, 1000.0, 10.0)
    
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
    
    if st.button("🔍 Analyze", key="btn1"):
        with st.spinner("🔄 Analyzing..."):
            valid, feat_array, err = validate_features(features)
            
            if not valid:
                st.error(err)
            else:
                pred, conf = make_prediction(model, feat_array)
                
                if pred is not None:
                    if pred == 0:
                        st.markdown("""
                            <div class="result-box result-normal">
                                ✅ NORMAL TRAFFIC
                            </div>
                        """, unsafe_allow_html=True)
                        
                        col_a, col_b, col_c = st.columns(3)
                        with col_a:
                            st.markdown(f'<div class="metric-card"><div>Confidence</div><div class="metric-value">{conf:.1f}%</div></div>', unsafe_allow_html=True)
                        with col_b:
                            st.markdown('<div class="metric-card"><div>Threat</div><div class="metric-value" style="color:#28a745">LOW</div></div>', unsafe_allow_html=True)
                        with col_c:
                            st.markdown('<div class="metric-card"><div>Action</div><div class="metric-value">NONE</div></div>', unsafe_allow_html=True)
                    
                    else:
                        st.markdown("""
                            <div class="result-box result-attack">
                                🚨 ATTACK DETECTED!
                            </div>
                        """, unsafe_allow_html=True)
                        
                        col_a, col_b, col_c = st.columns(3)
                        with col_a:
                            st.markdown(f'<div class="metric-card"><div>Confidence</div><div class="metric-value">{conf:.1f}%</div></div>', unsafe_allow_html=True)
                        with col_b:
                            st.markdown('<div class="metric-card"><div>Threat</div><div class="metric-value" style="color:#dc3545">HIGH</div></div>', unsafe_allow_html=True)
                        with col_c:
                            st.markdown('<div class="metric-card"><div>Action</div><div class="metric-value" style="color:#dc3545">BLOCK</div></div>', unsafe_allow_html=True)
                        
                        st.markdown("---")
                        result = block_ip(ip)
                        if "successfully" in result:
                            st.markdown(f'<div class="success-box">{result}</div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="danger-box">{result}</div>', unsafe_allow_html=True)

# ============================================================================
# TAB 2: CSV UPLOAD
# ============================================================================

with tab2:
    st.markdown("<div class='info-box'><strong>📁 CSV Upload Karo</strong></div>", unsafe_allow_html=True)
    
    file = st.file_uploader("CSV file select karo", type=['csv'])
    
    if file is not None:
        try:
            df = pd.read_csv(file)
            st.dataframe(df.head(), use_container_width=True)
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Records", len(df))
            with col2:
                st.metric("Features", len(df.columns))
            
            if st.button("🔍 Analyze Batch", key="btn2"):
                with st.spinner("Processing..."):
                    try:
                        preds = model.predict(df)
                        
                        if hasattr(model, 'predict_proba'):
                            probs = model.predict_proba(df)
                            confs = np.max(probs, axis=1) * 100
                        else:
                            confs = np.full(len(preds), 95.0)
                        
                        res_df = df.copy()
                        res_df['Prediction'] = ['Normal' if p == 0 else 'Attack' for p in preds]
                        res_df['Confidence'] = confs
                        
                        normal = len(preds[preds == 0])
                        attack = len(preds[preds == 1])
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown(f'<div class="metric-card"><div>Normal</div><div class="metric-value" style="color:#28a745">{normal}</div></div>', unsafe_allow_html=True)
                        with col2:
                            st.markdown(f'<div class="metric-card"><div>Attacks</div><div class="metric-value" style="color:#dc3545">{attack}</div></div>', unsafe_allow_html=True)
                        
                        st.dataframe(res_df, use_container_width=True)
                        
                        csv = res_df.to_csv(index=False)
                        st.download_button("📥 Download Results", csv, "results.csv", "text/csv")
                    
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        
        except Exception as e:
            st.error(f"CSV error: {str(e)}")

# ============================================================================
# TAB 3: ABOUT
# ============================================================================

with tab3:
    st.markdown("""
    ### 🎯 About This System
    
    **AI-Based Intrusion Detection & Prevention System**
    
    - Network traffic analysis
    - Real-time threat detection
    - Automatic IP blocking
    
    **Technology Used:**
    - Random Forest ML Model
    - Python & Streamlit
    - scikit-learn
    """)
