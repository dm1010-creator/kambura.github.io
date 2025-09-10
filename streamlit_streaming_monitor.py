import streamlit as st
import pandas as pd
import time
from datetime import datetime
from streaming_monitor import IPFrontingMonitor

# --- Streamlit UI Setup ---
st.set_page_config(page_title="Streaming Service ACL Monitor", page_icon="🔒", layout="wide")

st.title("🔒 Advanced Streaming Service Monitor")
st.write("""
Monitor streaming platforms for access/control list (ACL) evasion, IP fronting, and network diagnostics, 
optimized for restricted environments. Select your targets, configure proxies/fronting, and visualize results!
""")

with st.expander("ℹ️ About this App", expanded=False):
    st.markdown("""
    - **Targets:** Choose which streaming services to monitor
    - **Proxy/Fronting:** Rotate proxies, use domain fronting, and bypass ACLs
    - **Results:** View results in real-time, download as CSV/JSONL
    - **Novelty:** Uses ephemeral proxy pools, randomized delays, and domain fronting for advanced diagnostics
    """)

# --- Configurable Controls ---
monitor = IPFrontingMonitor()
target_names = [t['name'] for t in monitor.config['targets']]
default_targets = target_names[:4]

selected_targets = st.multiselect("🎯 Select streaming targets", target_names, default=default_targets)
concurrency = st.slider("⚡ Concurrency (threads)", min_value=1, max_value=10, value=monitor.config['concurrency'])
ping_timeout = st.slider("⏱️ Ping Timeout (seconds)", min_value=1, max_value=20, value=monitor.config['ping_timeout'])
tcp_timeout = st.slider("⏱️ TCP Timeout (seconds)", min_value=1, max_value=20, value=monitor.config['tcp_timeout'])
http_timeout = st.slider("⏱️ HTTP Timeout (seconds)", min_value=1, max_value=30, value=monitor.config['http_timeout'])

enable_ip_fronting = st.checkbox("Enable IP Fronting", value=monitor.config['enable_ip_fronting'])
rotate_proxies = st.checkbox("Enable Proxy Rotation", value=monitor.config['rotate_proxies'])
domain_fronting = st.checkbox("Enable Domain Fronting", value=monitor.config['domain_fronting'])
acl_evasion = st.checkbox("Enable ACL Evasion", value=monitor.config['acl_evasion'])

st.markdown("---")

# --- Run Monitoring ---
if st.button("🚀 Run Streaming Monitor"):
    st.info("Initializing monitor...")
    # Update config from UI
    monitor.config['concurrency'] = concurrency
    monitor.config['ping_timeout'] = ping_timeout
    monitor.config['tcp_timeout'] = tcp_timeout
    monitor.config['http_timeout'] = http_timeout
    monitor.config['enable_ip_fronting'] = enable_ip_fronting
    monitor.config['rotate_proxies'] = rotate_proxies
    monitor.config['domain_fronting'] = domain_fronting
    monitor.config['acl_evasion'] = acl_evasion
    monitor.config['targets'] = [t for t in monitor.config['targets'] if t['name'] in selected_targets]

    start_time = time.time()
    with st.spinner("Monitoring in progress..."):
        results = monitor.run_monitoring()
    execution_time = time.time() - start_time

    if results:
        df = pd.DataFrame(results)
        st.success(f"Monitoring complete! Total execution time: {execution_time:.2f} seconds")
        st.dataframe(df)

        # Summary
        total_tests = len(df)
        successful_tests = df['success'].sum()
        fronted_tests = df['fronted'].sum() if 'fronted' in df.columns else 0

        st.markdown(f"""
        **Summary**  
        - Total Tests: `{total_tests}`  
        - Successful: `{successful_tests}`  
        - Failed: `{total_tests - successful_tests}`  
        - Success Rate: `{(successful_tests/total_tests)*100:.1f}%`  
        - Fronted Requests: `{fronted_tests} ({(fronted_tests/total_tests)*100:.1f}%)`
        """)

        # Proxy Distribution
        if 'proxy_used' in df.columns:
            proxy_stats = df['proxy_used'].value_counts().reset_index()
            st.markdown("**Proxy Distribution:**")
            st.table(proxy_stats)

        # Visualizations
        st.markdown("**Latency Distribution:**")
        if 'latency_ms' in df.columns:
            st.bar_chart(df['latency_ms'].fillna(0), use_container_width=True)

        # Download
        st.markdown("**Download Results:**")
        st.download_button("Download CSV", df.to_csv(index=False), "results.csv", mime="text/csv")
        st.download_button("Download JSONL", df.to_json(orient="records", lines=True), "results.jsonl", mime="application/json")

    else:
        st.warning("No results to display. Please check your configuration and try again.")

st.markdown("---")
st.caption(f"© {datetime.now().year} Streaming Monitor | ACL Evasion & Fronting Diagnostics")