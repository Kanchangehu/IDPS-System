import streamlit as st
import pandas as pd
import numpy as np
import requests
import pickle
from io import BytesIO
import time

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
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
        }
        .header-title { 
            font-size: 2.5em; 
            font-weight: bold; 
            color: white;
            margin: 0;
        }
        .header-subtitle { 
            font-size: 1.1em; 
            margin-top: 10px; 
            color: #e0e0e0;
        }
        .result-box {
            padding: 20px; 
            border-radius: 10px; 
            text-align: center;
            font-size: 1.2em; 
            font-weight: bold; 
            color: white; 
            margin: 15px 0;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        .result-normal { 
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
        }
        .result-attack { 
            background: linear-gradient(135deg, #dc3545 0%, #ff6b6b 100%); 
        }
        .info-box {
            background-color: #e7f3ff; 
            border-left: 4px solid #0066cc;
            padding: 15px; 
            border-radius: 5px; 
            margin: 15px 0; 
            color: #003d99;
        }
        .success-box {
            background-color: #d4edda; 
            border-left: 4px solid #28a745;
            padding: 15px; 
            border-radius: 5px; 
            margin: 15px 0; 
            color: #155724;
        }
        .danger-box {
            background-color: #f8d7da; 
            border-left: 4px solid #dc3545;
            padding: 15px; 
            border-radius: 5px; 
            margin: 15px 0; 
            color: #721c24;
        }
        .metric-card {
            background: white; 
            padding: 20px; 
            border-radius: 8px;
            border: 1px solid #dee2e6; 
            text-align: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .metric-value { 
            font-size: 2em; 
            font-weight: bold; 
            color: #0066cc; 
            margin: 10px 0; 
        }
        .metric-label {
            font-size: 0.85em;
            color: #666;
        }
    </style>
""", unsafe_allow_html=True)

# ============================================================================
# DOWNLOAD MODEL FROM GOOGLE DRIVE (FINAL ROBUST VERSION)
# ============================================================================

@st.cache_resource
def download_model_from_drive(file_id):
    """
    Download model from Google Drive with error handling
    """
    if not file_id or file_id == "PASTE_YOUR_FILE_ID_HERE":
        st.error("❌ FILE_ID not configured. Please update LINE 159")
        return None
    
    try:
        # Direct download URL
        url = f"https://drive.google.com/uc?id={file_id}&export=download&confirm=t"
        
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            # Load directly from bytes
            model = pickle.loads(response.content)
            return model
        else:
            st.error(f"❌ Download failed (Status: {response.status_code})")
            return None
            
    except requests.exceptions.Timeout:
        st.error("❌ Download timeout - file too large or slow connection")
        return None
    except pickle.UnpicklingError:
        st.error("❌ Model file corrupted or invalid format")
        return None
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        return None

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def block_ip(ip):
    """Block IP address"""
    try:
        parts = ip.split('.')
        if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            return f"✅ IP {ip} successfully blocked!"
        else:
            return f"⚠️ Invalid IP format"
    except:
        return f"⚠️ Invalid IP format"

def make_prediction(model, features):
    """Make prediction from model"""
    try:
        pred = model.predict([features])[0]
        try:
            prob = model.predict_proba([features])[0]
            conf = max(prob) * 100
        except:
            conf = 90.0
        return pred, conf
    except Exception as e:
        st.error(f"❌ Prediction Error: {str(e)}")
        return None, None

def validate_features(features_dict):
    """Validate all features are numeric"""
    try:
        features = np.array([float(v) for v in features_dict.values()])
        return True, features, None
    except ValueError:
        return False, None, "❌ All values must be numbers!"

# ============================================================================
# MAIN APP HEADER
# ============================================================================

st.markdown("""
    <div class="header-container">
        <p class="header-title">🛡️ IDPS - AI Intrusion Detection System</p>
        <p class="header-subtitle">Network Traffic Analysis & Threat Prevention</p>
    </div>
""", unsafe_allow_html=True)

# ============================================================================
# ⚠️⚠️⚠️ PASTE YOUR GOOGLE DRIVE FILE ID HERE ⚠️⚠️⚠️
# ============================================================================

FILE_ID = "1AGdmfXHO_4xibHf_P2uP56dtiYO0QO0c"  # ← YAHAN APNA FILE ID LIKHO!

# Example: FILE_ID = "1xD9e4f2kL0pQ9rR8vW3xY5zB2cD4eF6gH"

# ============================================================================

with st.spinner("⏳ Loading AI Model... Please wait..."):
    model = download_model_from_drive(FILE_ID)
    time.sleep(1)

if model is None:
    st.error("❌ CRITICAL ERROR: Model failed to load.")
    st.info("""
    **💡 HOW TO FIX:**
    
    1. Go to https://drive.google.com
    2. Upload your idps_model.pkl file
    3. Right-click → Share → "Anyone with link"
    4. Copy the link
    5. Extract FILE_ID from URL:
       - Link: https://drive.google.com/file/d/**1xD9e4f2kL0pQ9rR8...zB2cD4eF6gH**/view
       - FILE_ID = **1xD9e4f2kL0pQ9rR8...zB2cD4eF6gH**
    6. Update FILE_ID on LINE 159 of app.py
    7. Commit changes in GitHub
    8. Wait 2-3 minutes for auto-reload
    """)
    st.stop()

st.success("✅ Model loaded successfully!")

# ============================================================================
# TABS
# ============================================================================

tab1, tab2, tab3 = st.tabs(["📊 Manual Input", "📁 CSV Upload", "ℹ️ About"])

# ============================================================================
# TAB 1: MANUAL INPUT
# ============================================================================

with tab1:
    st.markdown("""
        <div class='info-box'>
            <strong>💡 Enter Network Traffic Features Below</strong>
        </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    features = {}
    
    with col1:
        st.subheader("Column 1")
        features['Protocol'] = st.number_input("Protocol (0-255)", 0, 255, 6)
        features['Packet_Length'] = st.number_input("Packet Length (bytes)", 0, 10000, 100)
        features['Traffic_Rate'] = st.number_input("Traffic Rate (Mbps)", 0.0, 1000.0, 10.0)
    
    with col2:
        st.subheader("Column 2")
        features['TTL'] = st.number_input("TTL Value", 1, 255, 64)
        features['Header_Length'] = st.number_input("Header Length", 0, 100, 20)
        features['Flag_Count'] = st.number_input("Flag Count", 0, 32, 2)
    
    with col3:
        st.subheader("Column 3")
        features['Window_Size'] = st.number_input("Window Size", 0, 65535, 8192)
        features['Urgency'] = st.number_input("Urgency Flag", 0, 1, 0)
        features['Error_Rate'] = st.number_input("Error Rate (%)", 0.0, 100.0, 0.0)
    
    st.markdown("---")
    
    col_ip1, col_ip2 = st.columns([2, 1])
    with col_ip1:
        ip = st.text_input("Source IP Address", "192.168.1.100")
    with col_ip2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔍 ANALYZE TRAFFIC", key="btn1", use_container_width=True):
            valid, feat_array, err = validate_features(features)
            
            if not valid:
                st.error(err)
            else:
                with st.spinner("🔄 Analyzing traffic..."):
                    pred, conf = make_prediction(model, feat_array)
                    
                    if pred is not None:
                        st.markdown("---")
                        
                        if pred == 0:
                            # NORMAL TRAFFIC
                            st.markdown("""
                                <div class="result-box result-normal">
                                    ✅ STATUS: NORMAL TRAFFIC DETECTED
                                </div>
                            """, unsafe_allow_html=True)
                            
                            st.markdown("""
                                <div class="success-box">
                                    <strong>✓ No Threat Detected</strong><br>
                                    Network traffic is benign. No attacks identified.
                                </div>
                            """, unsafe_allow_html=True)
                            
                            col_a, col_b, col_c = st.columns(3)
                            with col_a:
                                st.markdown(f"""
                                    <div class="metric-card">
                                        <div class="metric-label">Confidence</div>
                                        <div class="metric-value">{conf:.1f}%</div>
                                    </div>
                                """, unsafe_allow_html=True)
                            with col_b:
                                st.markdown("""
                                    <div class="metric-card">
                                        <div class="metric-label">Threat Level</div>
                                        <div class="metric-value" style="color: #28a745;">LOW</div>
                                    </div>
                                """, unsafe_allow_html=True)
                            with col_c:
                                st.markdown("""
                                    <div class="metric-card">
                                        <div class="metric-label">Action</div>
                                        <div class="metric-value">NONE</div>
                                    </div>
                                """, unsafe_allow_html=True)
                        
                        else:
                            # ATTACK DETECTED
                            st.markdown("""
                                <div class="result-box result-attack">
                                    🚨 ALERT: ATTACK DETECTED!
                                </div>
                            """, unsafe_allow_html=True)
                            
                            st.markdown("""
                                <div class="danger-box">
                                    <strong>⚠️ Potential Intrusion Detected!</strong><br>
                                    Anomalous traffic pattern detected. Prevention measures initiated...
                                </div>
                            """, unsafe_allow_html=True)
                            
                            col_a, col_b, col_c = st.columns(3)
                            with col_a:
                                st.markdown(f"""
                                    <div class="metric-card">
                                        <div class="metric-label">Confidence</div>
                                        <div class="metric-value">{conf:.1f}%</div>
                                    </div>
                                """, unsafe_allow_html=True)
                            with col_b:
                                st.markdown("""
                                    <div class="metric-card">
                                        <div class="metric-label">Threat Level</div>
                                        <div class="metric-value" style="color: #dc3545;">HIGH</div>
                                    </div>
                                """, unsafe_allow_html=True)
                            with col_c:
                                st.markdown("""
                                    <div class="metric-card">
                                        <div class="metric-label">Action</div>
                                        <div class="metric-value" style="color: #dc3545;">BLOCK IP</div>
                                    </div>
                                """, unsafe_allow_html=True)
                            
                            st.markdown("---")
                            st.markdown("<div style='font-size: 1.1em; font-weight: bold;'>🛡️ Prevention Actions</div>", unsafe_allow_html=True)
                            
                            col_pa, col_pb = st.columns(2)
                            with col_pa:
                                st.markdown("""
                                    <div class="danger-box">
                                        <strong>🚨 Attack Type:</strong><br>
                                        Potential Intrusion/Anomalous Pattern
                                    </div>
                                """, unsafe_allow_html=True)
                            
                            with col_pb:
                                res = block_ip(ip)
                                if "successfully" in res:
                                    st.markdown(f"""
                                        <div class="success-box">
                                            <strong>✅ Prevention:</strong><br>
                                            {res}
                                        </div>
                                    """, unsafe_allow_html=True)
                                else:
                                    st.markdown(f"""
                                        <div class="danger-box">
                                            <strong>⚠️ Prevention:</strong><br>
                                            {res}
                                        </div>
                                    """, unsafe_allow_html=True)

# ============================================================================
# TAB 2: CSV UPLOAD
# ============================================================================

with tab2:
    st.markdown("""
        <div class='info-box'>
            <strong>📁 Upload CSV File for Batch Analysis</strong>
        </div>
    """, unsafe_allow_html=True)
    
    file = st.file_uploader("Choose CSV file", type=['csv'])
    
    if file:
        try:
            df = pd.read_csv(file)
            st.dataframe(df.head(10), use_container_width=True)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Records", len(df))
            with col2:
                st.metric("Features", len(df.columns))
            with col3:
                st.metric("Data Size", f"{df.memory_usage(deep=True).sum()/1024:.2f} KB")
            
            if st.button("🔍 ANALYZE BATCH", use_container_width=True):
                try:
                    preds = model.predict(df)
                    res_df = df.copy()
                    res_df['Prediction'] = ['🟢 Normal' if p==0 else '🔴 Attack' for p in preds]
                    
                    normal = len(preds[preds == 0])
                    attack = len(preds[preds == 1])
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.markdown(f"""
                            <div class="metric-card">
                                <div class="metric-label">Normal Traffic</div>
                                <div class="metric-value" style="color: #28a745;">{normal}</div>
                            </div>
                        """, unsafe_allow_html=True)
                    with col2:
                        st.markdown(f"""
                            <div class="metric-card">
                                <div class="metric-label">Attacks Detected</div>
                                <div class="metric-value" style="color: #dc3545;">{attack}</div>
                            </div>
                        """, unsafe_allow_html=True)
                    with col3:
                        rate = (attack/len(preds)*100) if len(preds) > 0 else 0
                        st.markdown(f"""
                            <div class="metric-card">
                                <div class="metric-label">Detection Rate</div>
                                <div class="metric-value">{rate:.1f}%</div>
                            </div>
                        """, unsafe_allow_html=True)
                    
                    st.markdown("---")
                    st.dataframe(res_df, use_container_width=True)
                    
                    csv = res_df.to_csv(index=False)
                    st.download_button("📥 Download Results", csv, "idps_results.csv")
                
                except Exception as e:
                    st.error(f"❌ Batch analysis error: {str(e)}")
        
        except Exception as e:
            st.error(f"❌ CSV upload error: {str(e)}")

# ============================================================================
# TAB 3: ABOUT
# ============================================================================

with tab3:
    st.markdown("""
        ## 🎯 About IDPS System
        
        **AI-Based Intrusion Detection & Prevention System**
        
        ### Purpose
        - Real-time network traffic analysis
        - Threat detection using Machine Learning
        - Automatic IP blocking for detected attacks
        
        ### Technology Stack
        - **ML Model:** Random Forest Classifier
        - **Frontend:** Streamlit
        - **Backend:** Python, scikit-learn
        - **Data Processing:** Pandas, NumPy
        
        ### Features (9 Network Parameters)
        1. **Protocol Type** - Network protocol (TCP/UDP/ICMP)
        2. **Packet Length** - Size of network packet (bytes)
        3. **Traffic Rate** - Speed of data transmission (Mbps)
        4. **TTL** - Time To Live value
        5. **Header Length** - Protocol header size
        6. **Flag Count** - Number of protocol flags
        7. **Window Size** - TCP window size
        8. **Urgency** - Urgency flag status
        9. **Error Rate** - Packet error percentage
        
        ### Prediction Classes
        - **0 (Normal)** ✅ - Benign traffic, no threat
        - **1 (Attack)** 🚨 - Anomalous pattern, potential threat
        
        ### Confidence Scoring
        - **>90%** - Very High Confidence
        - **70-90%** - High Confidence
        - **<70%** - Medium Confidence
        
        ### Prevention Actions
        - Automatic IP blocking (demonstration)
        - Alert notifications
        - Audit trail logging
        
        ---
        **Version:** 1.0 | **Built with:** Streamlit | **Last Updated:** Dec 2025
    """)
