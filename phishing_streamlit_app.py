
"""
Real-Time Phishing Email Detection System
--------------------------------------------------
Streamlit dashboard for Email and Web Security applications.
"""
import streamlit as st
import joblib
import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import socket
import tldextract
import os

# Load ML model and vectorizer
@st.cache_resource
def load_model():
    model = joblib.load('phishing_detection_model.pkl')
    vectorizer = joblib.load('tfidf_vectorizer.pkl')
    return model, vectorizer

model, tfidf_vectorizer = load_model()

# Sender reputation database (simple CSV for demo)
REPUTATION_FILE = 'sender_reputation.csv'
def get_sender_reputation(sender_email):
    if not os.path.exists(REPUTATION_FILE):
        return 0.5  # Neutral if no history
    df = pd.read_csv(REPUTATION_FILE)
    row = df[df['email'] == sender_email]
    if row.empty:
        return 0.5
    return float(row.iloc[0]['score'])

def update_sender_reputation(sender_email, is_phishing):
    score = get_sender_reputation(sender_email)
    score = max(0, min(1, score + (0.2 if is_phishing else -0.1)))
    if os.path.exists(REPUTATION_FILE):
        df = pd.read_csv(REPUTATION_FILE)
        if sender_email in df['email'].values:
            df.loc[df['email'] == sender_email, 'score'] = score
        else:
            df = pd.concat([df, pd.DataFrame({'email':[sender_email],'score':[score]})], ignore_index=True)
    else:
        df = pd.DataFrame({'email':[sender_email],'score':[score]})
    df.to_csv(REPUTATION_FILE, index=False)

# Email preprocessing
def preprocess(text):
    text = text.lower()
    text = re.sub(r'<.*?>', '', text)
    text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

URL_REGEX = r'(https?://[\w\.-/?=&%]+)'
def extract_urls(text):
    return re.findall(URL_REGEX, text)

# URL risk scoring function
def url_risk_score(url):
    score = 0
    parsed = urlparse(url)
    url = url.strip()
    # Length
    if len(url) > 60:
        score += 0.2
    # IP address
    try:
        if re.match(r"^https?://(\d+\.\d+\.\d+\.\d+)", url):
            score += 0.3
    except:
        pass
    # Suspicious keywords
    if re.search(r'(login|verify|update|secure|account|bank|password|confirm|reset|pay|invoice|alert|urgent)', url, re.I):
        score += 0.25
    # Long URLs
    if len(url) > 60:
        score += 0.25
    # IP address in URL
    if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url):
        score += 0.25
    # HTTPS usage
    if not parsed.scheme == 'https':
        score += 0.1
    # Suspicious TLDs
    if re.search(r'(\.ru|\.cn|\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top|\.work|\.info|\.biz)', url, re.I):
        score += 0.2
    # Excessive special characters
    if re.search(r'[\?&=%@#]', url) and len(re.findall(r'[\?&=%@#]', url)) > 3:
        score += 0.15
    # Shortener domains
    if re.search(r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|buff\.ly)', url, re.I):
        score += 0.2
    # Domain structure
    ext = tldextract.extract(url)
    if ext.domain in ['bitly', 'tinyurl', 'goo', 'owly']:
        score += 0.2
    # Subdomain count
    if ext.subdomain and len(ext.subdomain.split('.')) > 1:
        score += 0.1
    return min(score, 1.0)

# Compute risk from ML, URL, and sender reputation
def compute_risk(ml_pred, ml_prob, url_scores, sender_score):
    phishing_prob = ml_prob[1] if isinstance(ml_prob, (list, np.ndarray)) else ml_prob
    url_risk = max(url_scores) if url_scores else 0.0
    # Weighted sum: ML (0.5), URL (0.3), sender (0.2)
    risk = 0.5 * phishing_prob + 0.3 * url_risk + 0.2 * (1 - sender_score)
    if risk > 0.7:
        return 'High Risk', risk
    elif risk > 0.4:
        return 'Medium Risk', risk
    else:
        return 'Low Risk', risk

# Streamlit UI configuration
st.set_page_config(
    page_title="Link Sights - Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)





# Custom CSS styling
st.markdown("""
<style>
    :root {
        --primary-color: #FF4B4B;
        --success-color: #4BB543;
        --warning-color: #FFA500;
        --info-color: #1E90FF;
        --bg-dark: #0f1419;
        --text-light: #f0f2f6;
    }
    
    .main {
        padding-top: 1rem;
    }
    
    .stTabs [data-baseweb="tab-list"] button {
        padding: 10px 20px;
        font-weight: 600;
        border-radius: 8px;
    }
    
    .stButton button {
        width: 100%;
        padding: 12px;
        font-weight: 600;
        border-radius: 8px;
        transition: all 0.3s ease;
    }
    
    .stTextInput, .stTextArea {
        border-radius: 8px;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        margin-bottom: 10px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    }
    
    .risk-high {
        background: linear-gradient(135deg, #FF6B6B 0%, #FF4B4B 100%);
        border-left: 4px solid #FF0000;
        padding: 15px;
        border-radius: 8px;
        color: white;
        box-shadow: 0 4px 10px rgba(255, 75, 75, 0.3);
    }
    
    .risk-medium {
        background: linear-gradient(135deg, #FFB84D 0%, #FFA500 100%);
        border-left: 4px solid #FF8C00;
        padding: 15px;
        border-radius: 8px;
        color: white;
        box-shadow: 0 4px 10px rgba(255, 165, 0, 0.3);
    }
    
    .risk-low {
        background: linear-gradient(135deg, #5FD15F 0%, #4BB543 100%);
        border-left: 4px solid #2ECC71;
        padding: 15px;
        border-radius: 8px;
        color: white;
        box-shadow: 0 4px 10px rgba(75, 181, 67, 0.3);
    }
</style>
""", unsafe_allow_html=True)

# Custom sidebar branding and analysis mode selection
st.sidebar.markdown("""
<div style='text-align:center; padding: 20px 0;'>
    <h2 style='color:#FF4B4B; font-family: Arial, sans-serif; margin-bottom: 5px;'>🛡️ Link Sights</h2>
    <p style='font-size: 13px; color: #888;'>Phishing Detection System</p>
    <hr style='border: 1px solid #FF4B4B; margin: 15px 0;'>
    <p style='font-size: 13px; color: #666; line-height: 1.5;'>Advanced phishing detection using ML models and URL analysis</p>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")

# Add info section in sidebar
with st.sidebar.expander("📊 Quick Stats", expanded=False):
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Model Status", "✓", label_visibility="collapsed")
    with col2:
        st.metric("Methods", "3", label_visibility="collapsed")
    st.markdown("<p style='font-size: 12px; margin-top: -15px;'><b>ML Model:</b> Random Forest</p>", unsafe_allow_html=True)

st.sidebar.markdown("---")

mode_options = {
    "Email Content + URL Analysis": "Analyze both email text and embedded URLs for comprehensive phishing detection.",
    "Email Content Only Analysis": "Detect phishing attempts using only the email message content.",
    "URL Only Analysis": "Inspect individual URLs for safety using rule-based analysis."
}
mode = st.sidebar.radio(
    "Select Analysis Mode:",
    list(mode_options.keys()),
    help="Choose how you want to analyze for phishing risks."
)
st.sidebar.info(mode_options[mode])

st.markdown("""
<div style='text-align:center; padding: 30px 0;'>
    <h1 style='color:#FF4B4B; font-size: 2.5rem; margin-bottom: 10px;'>🛡️ Real-Time Phishing Detection</h1>
    <p style='color: #888; font-size: 1.1rem;'>Protect yourself with AI-powered email and URL analysis</p>
</div>
""", unsafe_allow_html=True)

if mode == "Email Content + URL Analysis":
    st.markdown("---")
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("<h3 style='color:#FF4B4B;'>📧 Email Analysis</h3>", unsafe_allow_html=True)
        sender_email = st.text_input('👤 Sender Email Address', placeholder='sender@example.com')
        email_content = st.text_area('💬 Email Content (with URLs)', height=200, placeholder='Paste email content here...')
    
    with col2:
        st.markdown("<h3 style='color:#1E90FF;'>ℹ️ Analysis Info</h3>", unsafe_allow_html=True)
        st.info("""
        **Analysis includes:**
        - 🤖 ML Model prediction
        - 🔗 URL risk assessment  
        - 👥 Sender reputation
        - ⚠️ Risk scoring
        """)
    
    col1, col2 = st.columns(2)
    with col1:
        analyze = st.button('🔍 Analyze Email & URLs', use_container_width=True, key='analyze_email_url')
    
    if analyze:
        if not email_content or len(email_content.strip()) < 10:
            st.error('❗ Please enter valid email content (at least 10 characters).')
        else:
            with st.spinner('🔄 Analyzing email...'):
                cleaned_text = preprocess(email_content)
                features = tfidf_vectorizer.transform([cleaned_text])
                ml_pred = model.predict(features)[0]
                ml_prob = model.predict_proba(features)[0]
                label = 'Phishing' if ml_pred == 1 or ml_pred == 'Phishing' else 'Legitimate'
                confidence = max(ml_prob) * 100
                urls = extract_urls(email_content)
                url_scores = [url_risk_score(u) for u in urls]
                sender_score = get_sender_reputation(sender_email) if sender_email else 0.5
                risk_level, risk_score = compute_risk(ml_pred, ml_prob, url_scores, sender_score)

                # Display results in organized layout
                st.markdown("---")
                
                # Risk overview cards
                cols = st.columns(3)
                with cols[0]:
                    risk_color = '#4BB543' if risk_level=='Low Risk' else ('#FFA500' if risk_level=='Medium Risk' else '#FF4B4B')
                    risk_bg = '#2ECC71' if risk_level=='Low Risk' else ('#FF8C00' if risk_level=='Medium Risk' else '#FF6B6B')
                    st.markdown(f"""
                    <div class='metric-card' style='background: linear-gradient(135deg, {risk_bg} 0%, {risk_color} 100%); color: white;'>
                        <div style='font-size: 14px; opacity: 0.95;'>Overall Risk</div>
                        <div style='font-size: 28px; font-weight: bold; margin-top: 5px;'>{risk_level}</div>
                        <div style='font-size: 12px; opacity: 0.85; margin-top: 5px;'>Score: {risk_score:.2f}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with cols[1]:
                    st.markdown(f"""
                    <div class='metric-card' style='background: linear-gradient(135deg, #3B82F6 0%, #1E90FF 100%); color: white;'>
                        <div style='font-size: 14px; opacity: 0.95;'>ML Confidence</div>
                        <div style='font-size: 28px; font-weight: bold; margin-top: 5px;'>{confidence:.1f}%</div>
                        <div style='font-size: 12px; opacity: 0.85; margin-top: 5px;'>{label}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with cols[2]:
                    rep_color = '#FF4B4B' if sender_score<0.3 else ('#FFA500' if sender_score<0.6 else '#4BB543')
                    rep_bg = '#FF6B6B' if sender_score<0.3 else ('#FFB84D' if sender_score<0.6 else '#5FD15F')
                    st.markdown(f"""
                    <div class='metric-card' style='background: linear-gradient(135deg, {rep_bg} 0%, {rep_color} 100%); color: white;'>
                        <div style='font-size: 14px; opacity: 0.95;'>Sender Rep.</div>
                        <div style='font-size: 28px; font-weight: bold; margin-top: 5px;'>{sender_score:.2f}</div>
                        <div style='font-size: 12px; opacity: 0.85; margin-top: 5px;'>URLs: {len(urls)}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Detailed analysis tabs
                st.markdown("---")
                tabs = st.tabs(["📊 Summary", "🤖 ML Analysis", "🔗 URL Analysis", "👥 Sender", "⚠️ Actions", "💡 Details"])
                
                with tabs[0]:
                    st.markdown("<h4 style='color:#1E90FF;'>Analysis Summary</h4>", unsafe_allow_html=True)
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Classification:** {label}")
                        st.write(f"**Risk Level:** {risk_level}")
                        st.write(f"**Overall Score:** {risk_score:.2f}")
                    with col2:
                        st.write(f"**ML Confidence:** {confidence:.2f}%")
                        st.write(f"**Sender Reputation:** {sender_score:.2f}")
                        st.write(f"**URLs Detected:** {len(urls)}")
                
                with tabs[1]:
                    st.markdown("<h4 style='color:#1E90FF;'>Machine Learning Analysis</h4>", unsafe_allow_html=True)
                    st.write(f"**Model Prediction:** {label}")
                    st.write(f"**Confidence Score:** {confidence:.2f}%")
                    st.progress(int(confidence/100), text=f"Confidence: {confidence:.2f}%")
                    
                    st.write("**Detected Risk Factors:**")
                    factors = []
                    if 'login' in email_content.lower() or 'verify' in email_content.lower():
                        factors.append('🚨 Suspicious keywords detected')
                    if 'urgent' in email_content.lower() or 'confirm' in email_content.lower():
                        factors.append('⏰ Urgent language detected')
                    if len(email_content) > 500:
                        factors.append('📏 Unusually long email')
                    if not factors:
                        factors.append('✓ No obvious red flags')
                    
                    for factor in factors:
                        st.write(f"- {factor}")
                
                with tabs[2]:
                    st.markdown("<h4 style='color:#1E90FF;'>URL Risk Analysis</h4>", unsafe_allow_html=True)
                    if urls:
                        for i, u in enumerate(urls, 1):
                            url_color = '#FF4B4B' if url_scores[i-1]>0.6 else ('#FFA500' if url_scores[i-1]>0.3 else '#4BB543')
                            url_label = '🔴 Malicious' if url_scores[i-1]>0.6 else ('🟠 Suspicious' if url_scores[i-1]>0.3 else '🟢 Safe')
                            st.markdown(f"<div class='risk-{'high' if url_scores[i-1]>0.6 else ('medium' if url_scores[i-1]>0.3 else 'low')}'>")
                            st.write(f"**URL {i}:** {u}")
                            st.write(f"{url_label} | Score: {url_scores[i-1]:.2f}")
                            st.markdown("</div>", unsafe_allow_html=True)
                    else:
                        st.info('✓ No URLs detected in email.')
                
                with tabs[3]:
                    st.markdown("<h4 style='color:#1E90FF;'>Sender Reputation</h4>", unsafe_allow_html=True)
                    rep_color = '#FF4B4B' if sender_score<0.3 else ('#FFA500' if sender_score<0.6 else '#4BB543')
                    rep_text = 'Not Trusted' if sender_score<0.3 else ('Mixed' if sender_score<0.6 else 'Trusted')
                    st.markdown(f"""
                    <div style='background-color: {rep_color}22; border-left: 4px solid {rep_color}; padding: 15px; border-radius: 6px;'>
                    <div style='font-size: 18px; color: {rep_color};'>Reputation: {rep_text}</div>
                    <div style='font-size: 24px; font-weight: bold; color: {rep_color}; margin: 10px 0;'>{sender_score:.2f}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with tabs[4]:
                    st.markdown("<h4 style='color:#1E90FF;'>Recommended Actions</h4>", unsafe_allow_html=True)
                    if risk_level == 'High Risk':
                        st.error('🚨 **PHISHING ALERT!** This email has been flagged as phishing.')
                        st.write("**Recommended actions:**")
                        st.write("- ❌ Do NOT click any links")
                        st.write("- ❌ Do NOT open attachments")
                        st.write("- 📧 Report to IT security")
                        st.write("- 🗑️ Delete the email")
                        update_sender_reputation(sender_email, True)
                    elif risk_level == 'Medium Risk':
                        st.warning('⚠️ **SUSPICIOUS EMAIL** - Please verify before interacting.')
                        st.write("**Recommended actions:**")
                        st.write("- ⚠️ Verify sender independently")
                        st.write("- 🔗 Don't click links directly - hover to check")
                        st.write("- 📞 Call sender if unexpected")
                        st.write("- 📧 Contact IT if unsure")
                        update_sender_reputation(sender_email, False)
                    else:
                        st.success('✅ **Email appears LEGITIMATE** - Low risk detected.')
                        st.write("**Status:** You can safely interact with this email.")
                        update_sender_reputation(sender_email, False)
                
                with tabs[5]:
                    st.markdown("<h4 style='color:#1E90FF;'>Detailed Analysis Report</h4>", unsafe_allow_html=True)
                    
                    st.write("**Why was this scored this way?**")
                    explain_points = []
                    if risk_level == 'High Risk':
                        explain_points.append('Multiple critical risk factors detected')
                    if sender_score < 0.3:
                        explain_points.append('Sender has low reputation')
                    if urls and any(s > 0.6 for s in url_scores):
                        explain_points.append('One or more malicious URLs found')
                    if 'login' in email_content.lower() or 'verify' in email_content.lower():
                        explain_points.append('Suspicious authentication keywords present')
                    if confidence > 80 and label == 'Phishing':
                        explain_points.append('ML model strongly indicates phishing')
                    
                    if explain_points:
                        for point in explain_points:
                            st.write(f"- {point}")
                    else:
                        st.write("- No major risk factors detected")

elif mode == "Email Content Only Analysis":
    st.markdown("---")
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("<h3 style='color:#FF4B4B;'>📧 Email Content Analysis</h3>", unsafe_allow_html=True)
        email_content = st.text_area('💬 Email Content', height=220, placeholder='Paste email text here...')
    
    with col2:
        st.markdown("<h3 style='color:#1E90FF;'>ℹ️ Info</h3>", unsafe_allow_html=True)
        st.info("""
        **This mode analyzes:**
        - 🤖 Content & language
        - 📝 Phishing patterns
        - ⚠️ Risk assessment
        """)
    
    analyze = st.button('🔍 Analyze Email', use_container_width=True, key='analyze_email_only')
    
    if analyze:
        if not email_content or len(email_content.strip()) < 10:
            st.error('❗ Please enter valid email content (at least 10 characters).')
        else:
            with st.spinner('🔄 Analyzing email...'):
                cleaned_text = preprocess(email_content)
                features = tfidf_vectorizer.transform([cleaned_text])
                ml_pred = model.predict(features)[0]
                ml_prob = model.predict_proba(features)[0]
                label = 'Phishing' if ml_pred == 1 or ml_pred == 'Phishing' else 'Legitimate'
                confidence = max(ml_prob) * 100
                risk_level = 'High Risk' if confidence > 80 and label == 'Phishing' else ('Medium Risk' if confidence > 50 and label == 'Phishing' else 'Low Risk')

                st.markdown("---")
                
                # Result cards
                cols = st.columns(2)
                with cols[0]:
                    risk_color = '#4BB543' if risk_level=='Low Risk' else ('#FFA500' if risk_level=='Medium Risk' else '#FF4B4B')
                    risk_bg = '#2ECC71' if risk_level=='Low Risk' else ('#FF8C00' if risk_level=='Medium Risk' else '#FF6B6B')
                    st.markdown(f"""
                    <div class='metric-card' style='background: linear-gradient(135deg, {risk_bg} 0%, {risk_color} 100%); color: white;'>
                        <div style='font-size: 14px; opacity: 0.95;'>Risk Level</div>
                        <div style='font-size: 28px; font-weight: bold; margin-top: 5px;'>{risk_level}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with cols[1]:
                    st.markdown(f"""
                    <div class='metric-card' style='background: linear-gradient(135deg, #3B82F6 0%, #1E90FF 100%); color: white;'>
                        <div style='font-size: 14px; opacity: 0.95;'>Confidence</div>
                        <div style='font-size: 28px; font-weight: bold; margin-top: 5px;'>{confidence:.1f}%</div>
                        <div style='font-size: 12px; opacity: 0.85; margin-top: 5px;'>{label}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.progress(int(confidence/100), text=f"Confidence: {confidence:.2f}%")
                
                # Tabs
                st.markdown("---")
                tabs = st.tabs(["📊 Summary", "🤖 ML Analysis", "⚠️ Actions", "💡 Details"])
                
                with tabs[0]:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Classification", label)
                        st.metric("Risk Level", risk_level)
                    with col2:
                        st.metric("Confidence", f"{confidence:.2f}%")
                        st.metric("Email Length", f"{len(email_content)} chars")
                
                with tabs[1]:
                    st.markdown("<h4 style='color:#1E90FF;'>ML Analysis Details</h4>", unsafe_allow_html=True)
                    st.write(f"**Model Output:** {label}")
                    st.write(f"**Confidence Score:** {confidence:.2f}%")
                    st.write("**Detected Patterns:**")
                    factors = []
                    if 'login' in email_content.lower() or 'verify' in email_content.lower():
                        factors.append('🚨 Suspicious keywords (login/verify)')
                    if 'urgent' in email_content.lower() or 'confirm' in email_content.lower() or 'action' in email_content.lower():
                        factors.append('⏰ Urgent language detected')
                    if 'click' in email_content.lower() or 'link' in email_content.lower():
                        factors.append('🔗 Call-to-action links mentioned')
                    if len(email_content) > 500:
                        factors.append('📏 Long email body')
                    if not factors:
                        factors.append('✓ No suspicious patterns')
                    for factor in factors:
                        st.write(f"- {factor}")
                
                with tabs[2]:
                    st.markdown("<h4 style='color:#1E90FF;'>Actions</h4>", unsafe_allow_html=True)
                    if risk_level == 'High Risk':
                        st.error('🚨 **PHISHING ALERT!**')
                        st.write("- Do NOT click links or open attachments")
                        st.write("- Report to your IT security team")
                    elif risk_level == 'Medium Risk':
                        st.warning('⚠️ **SUSPICIOUS** - Verify before interacting')
                        st.write("- Check sender independently")
                        st.write("- Hover over links to see actual URLs")
                    else:
                        st.success('✅ **SAFE** - Appears legitimate')
                
                with tabs[3]:
                    st.markdown("<h4 style='color:#1E90FF;'>Analysis Report</h4>", unsafe_allow_html=True)
                    if risk_level == 'High Risk':
                        st.write("**Why high risk?**")
                        st.write("- Multiple phishing indicators detected")
                        st.write("- Model confidence is very high")
                        st.write("- Email contains typical phishing patterns")
                    elif risk_level == 'Medium Risk':
                        st.write("**Why medium risk?**")
                        st.write("- Some suspicious elements found")
                        st.write("- Verify sender authenticity")
                        st.write("- Use caution with links")
                    else:
                        st.write("**Why low risk?**")
                        st.write("- Legitimate email patterns detected")
                        st.write("- No major phishing indicators")
                        st.write("- Safe to interact with")

elif mode == "URL Only Analysis":
    st.markdown("---")
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("<h3 style='color:#FF4B4B;'>🔗 URL Safety Check</h3>", unsafe_allow_html=True)
        url_input = st.text_input('🌐 Enter URL to analyze', placeholder='https://example.com')
    
    with col2:
        st.markdown("<h3 style='color:#1E90FF;'>ℹ️ Info</h3>", unsafe_allow_html=True)
        st.info("""
        **Checks for:**
        - 🚨 Malicious patterns
        - 🔐 HTTPS usage
        - 🏷️ Suspicious TLDs
        - ⚠️ URL structure
        """)
    
    analyze = st.button('🔍 Check URL Safety', use_container_width=True, key='analyze_url')
    
    if analyze:
        if not url_input or len(url_input.strip()) < 5:
            st.error('❗ Please enter a valid URL.')
        else:
            with st.spinner('🔄 Analyzing URL...'):
                score = url_risk_score(url_input)
                if score > 0.7:
                    label = 'Malicious'
                    color = '#FF4B4B'
                    emoji = '🔴'
                elif score > 0.4:
                    label = 'Suspicious'
                    color = '#FFA500'
                    emoji = '🟠'
                else:
                    label = 'Safe'
                    color = '#4BB543'
                    emoji = '🟢'
                
                st.markdown("---")
                
                # Result cards
                cols = st.columns(2)
                with cols[0]:
                    color_bg = '#FF6B6B' if color=='#FF4B4B' else ('#FFB84D' if color=='#FFA500' else '#5FD15F')
                    st.markdown(f"""
                    <div class='metric-card' style='background: linear-gradient(135deg, {color_bg} 0%, {color} 100%); color: white;'>
                        <div style='font-size: 14px; opacity: 0.95;'>Status</div>
                        <div style='font-size: 28px; font-weight: bold; margin-top: 5px;'>{emoji} {label}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with cols[1]:
                    st.markdown(f"""
                    <div class='metric-card' style='background: linear-gradient(135deg, #8B5CF6 0%, #6366F1 100%); color: white;'>
                        <div style='font-size: 14px; opacity: 0.95;'>Risk Score</div>
                        <div style='font-size: 28px; font-weight: bold; margin-top: 5px;'>{score:.2f}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.progress(int(score*100)/100, text=f"Risk Level: {score:.2%}")
                
                # Details
                st.markdown("---")
                tabs = st.tabs(["📊 Summary", "🔍 Details", "⚠️ Risk Factors", "💡 Recommendations"])
                
                with tabs[0]:
                    st.write(f"**URL:** {url_input}")
                    st.write(f"**Classification:** {label}")
                    st.write(f"**Risk Score:** {score:.2f}/1.0")
                    st.write(f"**Status:** {emoji} {label}")
                
                with tabs[1]:
                    st.markdown("<h4>URL Analysis</h4>", unsafe_allow_html=True)
                    parsed = urlparse(url_input)
                    st.write(f"**Protocol:** {parsed.scheme}")
                    st.write(f"**Domain:** {parsed.netloc}")
                    st.write(f"**Path:** {parsed.path if parsed.path else '(root)'}")
                    st.write(f"**Length:** {len(url_input)} characters")
                    st.write(f"**Scheme Security:** {'✓ HTTPS' if parsed.scheme == 'https' else '⚠️ HTTP'}")
                
                with tabs[2]:
                    st.markdown("<h4>Detected Risk Factors</h4>", unsafe_allow_html=True)
                    risk_factors = []
                    if len(url_input) > 60:
                        risk_factors.append(('📏 Long URL', 'URLs longer than 60 chars are suspicious'))
                    if 'login' in url_input.lower() or 'verify' in url_input.lower() or 'confirm' in url_input.lower():
                        risk_factors.append(('🚨 Suspicious keywords', 'Authentication-related keywords detected'))
                    if not url_input.startswith('https'):
                        risk_factors.append(('⚠️ No HTTPS', 'Unencrypted connection'))
                    if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url_input):
                        risk_factors.append(('🔗 IP Address', 'Direct IP instead of domain'))
                    if re.search(r'(\.ru|\.cn|\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top)', url_input):
                        risk_factors.append(('🏷️ Suspicious TLD', 'High-risk domain extension'))
                    if re.search(r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly)', url_input):
                        risk_factors.append(('🔗 URL Shortener', 'Shortened URL - destination unclear'))
                    
                    if risk_factors:
                        for factor, desc in risk_factors:
                            st.write(f"- {factor}: {desc}")
                    else:
                        st.write("✓ No major risk factors detected")
                
                with tabs[3]:
                    st.markdown("<h4>Recommendations</h4>", unsafe_allow_html=True)
                    if label == 'Malicious':
                        st.error('🚨 **DO NOT VISIT THIS URL**')
                        st.write("- Block this URL")
                        st.write("- Report to security team")
                        st.write("- Delete any emails containing this URL")
                    elif label == 'Suspicious':
                        st.warning('⚠️ **PROCEED WITH CAUTION**')
                        st.write("- Hover over URL to see actual destination")
                        st.write("- Verify the sender independently")
                        st.write("- Use browser security tools")
                    else:
                        st.success('✅ **URL APPEARS SAFE**')
                        st.write("- URL passed safety checks")
                        st.write("- Still exercise normal caution")
                        st.write("- Keep browser and security software updated")

# Professional footer with additional info
st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown("""
    <div style='text-align:center;'>
        <h4 style='color:#FF4B4B;'>🛡️ Security</h4>
        <p style='font-size:12px; color:#888;'>ML-powered detection</p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div style='text-align:center;'>
        <h4 style='color:#FF4B4B;'>📊 Analysis</h4>
        <p style='font-size:12px; color:#888;'>Multiple detection methods</p>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div style='text-align:center;'>
        <h4 style='color:#FF4B4B;'>🚀 Real-Time</h4>
        <p style='font-size:12px; color:#888;'>Instant results</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("""
<hr style='border:0.5px solid #eee;margin-top:20px;'>
<div style='text-align:center;font-size:12px;color:#999;font-family:Arial,sans-serif;padding:20px 0;'>
    <p style='margin:5px 0;'>&copy; 2026 Link Sights | Stay Safe Online | Powered by Machine Learning</p>
    <p style='margin:5px 0; font-size:11px;'>Always verify suspicious emails independently • Never click untrusted links • Report phishing to your IT team</p>
</div>
""", unsafe_allow_html=True)
